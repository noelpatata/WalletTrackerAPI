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
  pm_api_url      = "https://${var.proxmox_ip}:${var.proxmox_port}/api2/json"
  pm_user         = "${data.vault_kv_secret_v2.backend.data["PROXMOX_USER"]}@pam"
  pm_password     = data.vault_kv_secret_v2.backend.data["PROXMOX_PASSWORD"]
  pm_tls_insecure = true
}
