output "google_project" {
  value = local.google_project_id
}

output "mithril_aggregator_endpoint" {
  value     = local.mithril_aggregator_endpoint_url
  sensitive = true
}

output "mithril_signers_endpoint_url" {
  value = local.mithril_signers_endpoint_url
}

output "prometheus_endpoint_url" {
  value     = local.prometheus_endpoint_url
  sensitive = true
}

output "loki_endpoint_url" {
  value     = local.loki_endpoint_url
  sensitive = true
}

output "storage_bucket" {
  value = google_storage_bucket.cloud_storage.name
}

output "external-ip" {
  value = google_compute_address.mithril-external-address.address
}

output "api_subdomain" {
  value = google_dns_managed_zone.mithril-api-zone.dns_name
}

output "name_servers" {
  value = google_dns_managed_zone.mithril-api-zone.name_servers
}

output "mithril_aggregator_relay_p2p_dial_to" {
  value = local.mithril_aggregator_relay_p2p_dial_to
}

output "mithril_signers_relay_p2p_dial_to" {
  value = local.mithril_signers_relay_p2p_dial_to
}

output "mithril_p2p_dmq_network_bootstrap_peer" {
  value = var.mithril_p2p_dmq_dense_topology ? join(",", concat(
    ["${google_compute_address.mithril-external-address.address}:${local.mithril_aggregator_dmq_port}"],
    [for key in keys(var.mithril_signers) : "${google_compute_address.mithril-external-address.address}:${local.mithril_signers_dmq_relay_port[key]}"]
  )) : "${google_compute_address.mithril-external-address.address}:${local.mithril_aggregator_dmq_port}"
}
