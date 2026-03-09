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

data "vault_kv_secret_v2" "secrets" {
  mount = "secret"
  name  = "wallettracker/backend"
}

provider "proxmox" {
  pm_api_url      = "https://${var.proxmox_ip}:${var.proxmox_port}/api2/json"
  pm_user         = data.vault_kv_secret_v2.secrets.data["PROXMOX_USER"]
  pm_password     = data.vault_kv_secret_v2.secrets.data["PROXMOX_PASSWORD"]
  pm_tls_insecure = true
}

variable "hostname" {
  description = "API container hostname"
  type        = string
  default     = "api.wallettracker"
}
variable "proxmox_ip" {
  description = "Proxmox IP address"
  type        = string
  default     = "192.168.0.20"
}
variable "proxmox_port" {
  description = "Proxmox port number"
  type        = string
  default     = "8006"
}
variable "container_ip" {
  description = "API container IP address"
  type        = string
  default     = "192.168.0.18"
}
variable "db_container_ip" {
  description = "MariaDB container IP address"
  type        = string
  default     = "192.168.0.19"
}
variable "target_node" {
  description = "Proxmox node name"
  type        = string
  default     = "proxmoxserver"
}
variable "bridge_name" {
  description = "Network bridge"
  type        = string
  default     = "vmbr0"
}

resource "proxmox_lxc" "api" {
  target_node = var.target_node
  hostname    = var.hostname
  ostemplate  = "local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz"
  password    = data.vault_kv_secret_v2.secrets.data["API_CONTAINER_PASSWORD"]
  cores       = 2
  memory      = 512
  swap        = 512
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
  start = true
  lifecycle {
    create_before_destroy = true
  }
}

resource "null_resource" "setup_api_in_container" {
  depends_on = [proxmox_lxc.api]

  connection {
    type     = "ssh"
    host     = var.proxmox_ip
    user     = data.vault_kv_secret_v2.secrets.data["PROXMOX_USER"]
    password = data.vault_kv_secret_v2.secrets.data["PROXMOX_PASSWORD"]
  }

  provisioner "file" {
    content     = <<-INITEOF
      #!/sbin/openrc-run
      description="WalletTracker uWSGI"

      VENV_PATH="/srv/WalletTrackerAPI/app/.venv"
      directory="/srv/WalletTrackerAPI/app"
      pidfile="/run/wallettracker.pid"
      command="$${VENV_PATH}/bin/uwsgi"
      command_args="--ini $${directory}/uwsgi.ini"
      command_background="yes"

      export DATABASE_ROOT_PASSWORD="${data.vault_kv_secret_v2.secrets.data["MARIADB_ROOT_PASSWORD"]}"
      export WALLET_TRACKER_DB_USER="root"
      export WALLET_TRACKER_DB_HOST="${var.db_container_ip}"
      export DATABASE_NAME="wallet_tracker"
      export WALLET_TRACKER_SECRET="${data.vault_kv_secret_v2.secrets.data["WALLET_TRACKER_SECRET"]}"
      export ENABLE_REGISTER="false"

      start_pre() {
        checkpath --directory --owner root:root $${pidfile%/*}
      }
      INITEOF
    destination = "/tmp/wallettracker.init"
  }

  provisioner "remote-exec" {
    inline = [
      <<-EOF
      pct exec ${proxmox_lxc.api.vmid} -- apk update
      pct exec ${proxmox_lxc.api.vmid} -- apk add --no-cache git python3 py3-pip mariadb-dev gcc musl-dev python3-dev build-base linux-headers

      pct exec ${proxmox_lxc.api.vmid} -- git clone https://${data.vault_kv_secret_v2.secrets.data["GITHUB_TOKEN"]}@github.com/noelpatata/WalletTrackerAPI.git /srv/WalletTrackerAPI

      pct exec ${proxmox_lxc.api.vmid} -- python3 -m venv /srv/WalletTrackerAPI/app/.venv
      pct exec ${proxmox_lxc.api.vmid} -- /srv/WalletTrackerAPI/app/.venv/bin/pip install --no-cache-dir -r /srv/WalletTrackerAPI/app/requirements.txt

      pct exec ${proxmox_lxc.api.vmid} -- apk del gcc musl-dev build-base linux-headers

      pct exec ${proxmox_lxc.api.vmid} -- mkdir -p /var/logs
      pct exec ${proxmox_lxc.api.vmid} -- touch /var/logs/wallettracker.log
      pct exec ${proxmox_lxc.api.vmid} -- chmod 644 /var/logs/wallettracker.log

      pct push ${proxmox_lxc.api.vmid} /tmp/wallettracker.init /etc/init.d/wallettracker
      rm /tmp/wallettracker.init

      pct exec ${proxmox_lxc.api.vmid} -- chmod +x /etc/init.d/wallettracker
      pct exec ${proxmox_lxc.api.vmid} -- rc-update add wallettracker default
      pct exec ${proxmox_lxc.api.vmid} -- rc-service wallettracker start
      EOF
    ]
  }
}

output "api_container" {
  value = proxmox_lxc.api.hostname
}
