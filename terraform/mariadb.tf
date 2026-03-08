terraform {
  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "3.0.2-rc05"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

provider "vault" {
  address = "https://vault.downops.win"
}

data "vault_kv_secret_v2" "backend" {
  mount = "secret"
  name  = "wallettracker/backend"
}

provider "proxmox" {
  pm_api_url          = "https://${var.proxmox_ip}:${var.proxmox_port}/api2/json"
  pm_api_token_id     = data.vault_kv_secret_v2.backend.data["PROXMOX_API_TOKEN_ID"]
  pm_api_token_secret = data.vault_kv_secret_v2.backend.data["PROXMOX_API_TOKEN_SECRET"]
  pm_tls_insecure     = true
}

variable "hostname" {
  description = "MariaDB container hostname"
  type        = string
  default     = "mariadb.wallettracker"
}
variable "proxmox_ip" {
  description = "Proxmox ip address"
  type        = string
  default     = "192.168.0.20"
}
variable "proxmox_port" {
  description = "Proxmox port number"
  type        = string
  default     = "8006"
}
variable "api_container_ip" {
  description = "API container ip address"
  type        = string
  default     = "192.168.0.18"
}
variable "container_ip" {
  description = "MariaDB container ip address"
  type        = string
  default     = "192.168.0.19"
}
variable "wallettracker_mariadb_database" {
  description = "Database name to initialize"
  type        = string
  default     = "wallet_tracker"
}
variable "db_volume" {
  description = "Host directory to bind-mount as /var/lib/mysql"
  type        = string
  default     = "/mnt/mariadb_wallettracker"
}
variable "target_node" {
  description = "Proxmox node name where container runs"
  type        = string
  default     = "proxmoxserver"
}
variable "bridge_name" {
  description = "Network bridge to attach container NIC"
  type        = string
  default     = "vmbr0"
}
variable "storage_name" {
  description = "Rootfs storage for container"
  type        = string
  default     = "local-lvm"
}

resource "null_resource" "ensure_mariadb_volume" {
  connection {
    type     = "ssh"
    user     = "root"
    host     = var.proxmox_ip
    password = data.vault_kv_secret_v2.backend.data["PROXMOX_API_TOKEN"]
  }
  provisioner "remote-exec" {
    inline = [
      "if [ ! -d '${var.db_volume}' ]; then",
      "  echo 'Creating MariaDB data directory at ${var.db_volume}...'",
      "  mkdir -p '${var.db_volume}'",
      "  chmod 770 '${var.db_volume}'",
      "  chown 100100:100101 '${var.db_volume}'",
      "else",
      "  echo 'Directory ${var.db_volume} already exists.'",
      "fi"
    ]
  }
}

resource "proxmox_lxc" "mariadb" {
  depends_on   = [null_resource.ensure_mariadb_volume]
  target_node  = var.target_node
  hostname     = var.hostname
  ostemplate   = "local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz"
  password     = data.vault_kv_secret_v2.backend.data["DB_CONTAINER_PASSWORD"]
  cores        = 2
  memory       = 512
  swap         = 512
  rootfs {
    storage = "local-lvm"
    size    = "4G"
  }
  network {
    name   = "eth0"
    bridge = var.bridge_name
    gw     = "192.168.0.1"
    ip     = "${var.container_ip}/24"
  }
  mountpoint {
    key     = "1"
    slot    = "1"
    storage = var.db_volume
    volume  = var.db_volume
    mp      = "/var/lib/mysql"
    size    = "10G"
  }
  start = true
  lifecycle {
    create_before_destroy = true
  }
}

resource "null_resource" "setup_mariadb_in_container" {
  depends_on = [proxmox_lxc.mariadb]

  connection {
    type     = "ssh"
    host     = var.proxmox_ip
    user     = "root"
    password = data.vault_kv_secret_v2.backend.data["PROXMOX_API_TOKEN"]
  }

  provisioner "file" {
    source      = "${path.module}/init.sql.template"
    destination = "/tmp/script.sql"
  }

  provisioner "remote-exec" {
    inline = [
      <<-EOF
      pct exec ${proxmox_lxc.mariadb.vmid} -- apk update
      pct exec ${proxmox_lxc.mariadb.vmid} -- apk add gettext mariadb mariadb-client

      if [ ! -f "${var.db_volume}/ibdata1" ]; then
        echo "[INFO] Initializing new MariaDB instance in ${var.db_volume}..."

        pct exec ${proxmox_lxc.mariadb.vmid} -- rc-service mariadb stop || true
        pct exec ${proxmox_lxc.mariadb.vmid} -- chown -R mysql:mysql /var/lib/mysql
        pct exec ${proxmox_lxc.mariadb.vmid} -- chmod -R 770 /var/lib/mysql
        pct exec ${proxmox_lxc.mariadb.vmid} -- mkdir -p /run/mysqld
        pct exec ${proxmox_lxc.mariadb.vmid} -- chown mysql:mysql /run/mysqld

        pct exec ${proxmox_lxc.mariadb.vmid} -- mariadb-install-db --user=mysql --datadir=/var/lib/mysql
        pct exec ${proxmox_lxc.mariadb.vmid} -- rc-service mariadb start
        pct exec ${proxmox_lxc.mariadb.vmid} -- rc-update add mariadb

        pct exec ${proxmox_lxc.mariadb.vmid} -- sh -c "mariadb -e \\
          \\\"CREATE USER IF NOT EXISTS 'root'@'${var.api_container_ip}' IDENTIFIED BY '${data.vault_kv_secret_v2.backend.data["MARIADB_ROOT_PASSWORD"]}'; \\
          GRANT ALL PRIVILEGES ON *.* TO 'root'@'${var.api_container_ip}' WITH GRANT OPTION; \\
          FLUSH PRIVILEGES;\\\""

        pct exec ${proxmox_lxc.mariadb.vmid} -- sed -i 's/^skip-networking/#skip-networking/' /etc/my.cnf.d/mariadb-server.cnf
        pct exec ${proxmox_lxc.mariadb.vmid} -- sed -i 's/^#bind-address=.*/bind-address = ${var.container_ip}/' /etc/my.cnf.d/mariadb-server.cnf

        pct exec ${proxmox_lxc.mariadb.vmid} -- rc-service mariadb restart

        echo "[INFO] Importing initialization SQL..."

        pct push ${proxmox_lxc.mariadb.vmid} /tmp/script.sql /tmp/script.sql
        pct exec ${proxmox_lxc.mariadb.vmid} -- sh -c "MARIADB_DATABASE='${var.wallettracker_mariadb_database}' envsubst < /tmp/script.sql > /tmp/script_parsed.sql"
        pct exec ${proxmox_lxc.mariadb.vmid} -- sh -c "mariadb < /tmp/script_parsed.sql"

        echo "[INFO] Database initialization complete."
      else
        echo "[INFO] Existing MariaDB data found within ${var.db_volume}, skipping initialization."
        pct exec ${proxmox_lxc.mariadb.vmid} -- rc-service mariadb restart
      fi
      EOF
    ]
  }
}

output "mariadb_container" {
  value = proxmox_lxc.mariadb.hostname
}