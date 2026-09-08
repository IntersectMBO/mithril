locals {
  p2p_network_ports  = var.mithril_use_p2p_network ? concat([local.mithril_aggregator_relay_mithril_listen_port, local.mithril_aggregator_dmq_port], values(local.mithril_signers_relay_listen_port), values(local.mithril_signers_dmq_relay_port)) : []
  ipfs_network_ports = var.mithril_ipfs_enabled ? [local.mithril_ipfs_swarm_port] : []
}

resource "google_compute_firewall" "mithril-vm-firewall" {
  name    = "${local.environment_name}-firewall"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = concat(["22", "80", "443"], values(local.mithril_signers_relay_cardano_port), local.p2p_network_ports, local.ipfs_network_ports)
  }

  dynamic "allow" {
    for_each = local.ipfs_network_ports

    content {
      protocol = "udp"
      ports    = [allow.value]
    }
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.environment_name]
}
