variable "api_public_hostname" {
  description = "Public hostname for the API (e.g. api.downops.win)"
  type        = string
  default     = "api.downops.win"
}

resource "cloudflare_tunnel" "api" {
  account_id = data.vault_kv_secret_v2.backend.data["CLOUDFLARE_ACCOUNT_ID"]
  name       = "wallettracker-api"
  secret     = data.vault_kv_secret_v2.backend.data["CLOUDFLARE_TUNNEL_SECRET"]
}

resource "cloudflare_tunnel_config" "api" {
  account_id = data.vault_kv_secret_v2.backend.data["CLOUDFLARE_ACCOUNT_ID"]
  tunnel_id  = cloudflare_tunnel.api.id

  config {
    ingress_rule {
      hostname = var.api_public_hostname
      service  = "http://localhost:5000"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "api" {
  zone_id = data.vault_kv_secret_v2.backend.data["CLOUDFLARE_ZONE_ID"]
  name    = "api"
  content = "${cloudflare_tunnel.api.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

resource "null_resource" "setup_cloudflared" {
  depends_on = [null_resource.setup_api_in_container, cloudflare_tunnel.api]

  connection {
    type     = "ssh"
    host     = var.proxmox_ip
    user     = data.vault_kv_secret_v2.backend.data["PROXMOX_USER"]
    password = data.vault_kv_secret_v2.backend.data["PROXMOX_PASSWORD"]
  }

  provisioner "file" {
    content     = <<-INITEOF
      #!/sbin/openrc-run
      name="cloudflared"
      description="Cloudflare Tunnel"
      command="/usr/bin/cloudflared"
      command_args="tunnel run --token ${cloudflare_tunnel.api.tunnel_token}"
      command_background=true
      pidfile="/run/cloudflared.pid"
      output_log="/var/logs/cloudflared.log"
      error_log="/var/logs/cloudflared.log"

      depend() {
        need net
        after wallettracker
      }
      INITEOF
    destination = "/tmp/cloudflared.init"
  }

  provisioner "remote-exec" {
    inline = [
      <<-EOF
      pct exec ${proxmox_lxc.api.vmid} -- wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O /usr/bin/cloudflared
      pct exec ${proxmox_lxc.api.vmid} -- chmod +x /usr/bin/cloudflared

      pct push ${proxmox_lxc.api.vmid} /tmp/cloudflared.init /etc/init.d/cloudflared
      rm /tmp/cloudflared.init

      pct exec ${proxmox_lxc.api.vmid} -- chmod +x /etc/init.d/cloudflared
      pct exec ${proxmox_lxc.api.vmid} -- rc-update add cloudflared default
      pct exec ${proxmox_lxc.api.vmid} -- rc-service cloudflared start
      EOF
    ]
  }
}

output "api_public_url" {
  value = "https://${var.api_public_hostname}"
}
