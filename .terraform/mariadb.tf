terraform {
  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "3.0.2-rc05"
    }
  }
}
provider "proxmox" {
  pm_api_url      = "https://${var.proxmox_ip}:${var.proxmox_port}/api2/json"
  pm_user         = var.proxmox_api_user
  pm_password     = var.proxmox_api_token
  pm_tls_insecure = true
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
variable "proxmox_api_user" {
  description = "Proxmox user in format user@realm!tokenid"
  type        = string
  default     = "root@pam"
}
variable "proxmox_api_token" {
  description = "API token secret for the above user"
  type        = string
  sensitive   = true
  default     = "noelmaricon123"
}
variable "vm_id" {
  description = "Container numeric ID (reuse for blue/green deployments)"
  type        = number
  default     = 101
}
variable "hostname" {
  description = "MariaDB container hostname"
  type        = string
  default     = "mysql.wallettracker"
}
variable "mysql_root_password" {
  description = "Root password for MariaDB"
  type        = string
  sensitive   = true
  default     = "PNe4Wq0oqvx87oGs6L7Fku9vf"
}
variable "wallettracker_mysql_database" {
  description = "Database name to initialize"
  type        = string
  default     = "wallet_tracker"
}
variable "db_volume" {
  description = "Host directory to bind-mount as /var/lib/mysql (e.g. /mnt/mysql_data)"
  type        = string
  default     = "/mnt/mysql"
}
variable "target_node" {
  description = "Proxmox node name where container runs"
  type        = string
  default     = "proxmoxserver"
}
variable "bridge_name" {
  description = "Network bridge to attach container NIC (e.g. vmbr0)"
  type        = string
  default     = "vmbr0"
}
variable "storage_name" {
  description = "Rootfs storage for container (e.g. local-lvm)"
  type        = string
  default     = "local-lvm"
}
variable "container_ip" {
  description = "ip address"
  type        = string
  default     = "192.168.0.19"
}
variable "container_password" {
  description = "root's password"
  type        = string
  default     = "noelmaricon123"
}
resource "null_resource" "ensure_mysql_volume" {
  connection {
    type     = "ssh"
    user     = "root"
    host     = var.proxmox_ip
    password = var.proxmox_api_token
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
  depends_on   = [null_resource.ensure_mysql_volume]
  target_node  = var.target_node
  hostname     = var.hostname
  ostemplate   = "local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz"
  password     = var.container_password
  cores        = 2
  memory       = 512
  swap         = 512
  rootfs {
    storage    = "local-lvm"
    size       = "4G"
  }
  network {
    name       = "eth0"
    bridge     = var.bridge_name
    ip         = "${var.container_ip}/24"
  }
  mountpoint {
    key        = "1"
    slot       = "1"
    storage    = var.db_volume
    volume     = var.db_volume
    mp         = "/var/lib/mysql"
    size       = "10G"
  }
  start = true
  lifecycle {
    create_before_destroy = true
  }
}

output "mariadb_container" {
  value        = proxmox_lxc.mariadb.hostname
}