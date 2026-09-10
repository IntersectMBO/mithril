
resource "null_resource" "mithril_monitoring" {
  depends_on = [
    null_resource.mithril_network,
    null_resource.mithril_reverse_proxy,
    null_resource.mithril_aggregator,
    null_resource.mithril_signer
  ]

  triggers = {
    image_id                 = var.mithril_image_id,
    vm_instance              = google_compute_instance.vm_instance.id,
    prometheus_auth_username = var.prometheus_auth_username,
    prometheus_auth_password = var.prometheus_auth_password,
    loki_auth_username       = var.loki_auth_username,
    loki_auth_password       = var.loki_auth_password,
    mithril_ipfs_enabled     = var.mithril_ipfs_enabled
  }

  connection {
    type        = "ssh"
    user        = "curry"
    private_key = local.google_service_account_private_key
    host        = google_compute_address.mithril-external-address.address
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /home/curry/data/monitoring/prometheus",
      "mkdir -p /home/curry/data/monitoring/loki",
      <<-EOT
set -e
# Copy prometheus base configuration
cp /home/curry/docker/prometheus/prometheus-base.yml /home/curry/docker/prometheus/prometheus.yml
# Setup prometheus targets configuration for the IPFS node
if [ "${var.mithril_ipfs_enabled}" = "true" ] ; then
cat >> /home/curry/docker/prometheus/prometheus.yml << EOF

  - job_name: "ipfs-node"
    metrics_path: /debug/metrics/prometheus
    static_configs:
      - targets: ["ipfs-node:5001"]
EOF
fi
# Setup prometheus remote write
if [ -n "${var.prometheus_ingest_host}" ] ; then 
cat >> /home/curry/docker/prometheus/prometheus.yml << EOF

remote_write:
- url: https://${var.prometheus_ingest_host}/api/prom/push
  basic_auth:
    username: ${var.prometheus_ingest_username}
    password: ${var.prometheus_ingest_password}
EOF
fi
# Setup prometheus targets configuration for Cardano nodes
CARDANO_NODES=$(docker ps --format='{{.Names}}:12798,' | grep "cardano-node" | sort | tr -d '\n\t\r ' | sed 's/.$//')
cat /home/curry/docker/prometheus/cardano.json | jq --arg CARDANO_NODES "$CARDANO_NODES" '. += [{
    "labels": {
        "job": "cardano-nodes"
    },
    "targets": $CARDANO_NODES
}]' | jq '. | map(try(.targets |= split(",")) // .)' > /home/curry/docker/prometheus/cardano.json.new
rm -f /home/curry/docker/prometheus/cardano.json
mv /home/curry/docker/prometheus/cardano.json.new docker/prometheus/cardano.json
# Setup prometheus targets configuration for Mithril signer nodes
MITHRIL_SIGNER_NODES=$(docker ps --format='{{.Names}}:9090,' | grep "mithril-signer" | grep -v "www" | grep -v "relay" | sort | tr -d '\n\t\r ' | sed 's/.$//')
cat /home/curry/docker/prometheus/mithril-signer.json | jq --arg MITHRIL_SIGNER_NODES "$MITHRIL_SIGNER_NODES" '. += [{
    "labels": {
        "job": "mithril-signer"
    },
    "targets": $MITHRIL_SIGNER_NODES
}]' | jq '. | map(try(.targets |= split(",")) // .)' > /home/curry/docker/prometheus/mithril-signer.json.new
rm -f /home/curry/docker/prometheus/mithril-signer.json
mv /home/curry/docker/prometheus/mithril-signer.json.new docker/prometheus/mithril-signer.json
# Setup prometheus targets configuration for Mithril aggregator nodes
MITHRIL_AGGREGATOR_NODES=$(docker ps --format='{{.Names}}:9090,' | grep "mithril-aggregator" | sort | tr -d '\n\t\r ' | sed 's/.$//')
cat /home/curry/docker/prometheus/mithril-aggregator.json | jq --arg MITHRIL_AGGREGATOR_NODES "$MITHRIL_AGGREGATOR_NODES" '. += [{
    "labels": {
        "job": "mithril-aggregator"
    },
    "targets": $MITHRIL_AGGREGATOR_NODES
}]' | jq '. | map(try(.targets |= split(",")) // .)' > /home/curry/docker/prometheus/mithril-aggregator.json.new
rm -f /home/curry/docker/prometheus/mithril-aggregator.json
mv /home/curry/docker/prometheus/mithril-aggregator.json.new docker/prometheus/mithril-aggregator.json
EOT
      ,
      <<-EOT
set -e
# Copy promtail base configuration
cp /home/curry/docker/promtail/promtail-config-base.yml /home/curry/docker/promtail/promtail-config.yml
# Setup promtail remote client
if [ -n "${var.loki_ingest_host}" ] ; then 
cat >> /home/curry/docker/promtail/promtail-config.yml << EOF

  - url: https://${var.loki_ingest_username}:${var.loki_ingest_password}@${var.loki_ingest_host}/loki/api/v1/push
EOF
fi
EOT
      ,
      <<-EOT
set -e
# Setup disk usage exporter configuration
cp /home/curry/docker/prometheus/disk_usage_exporter/disk_usage_exporter-base.yml /home/curry/docker/prometheus/disk_usage_exporter/disk_usage_exporter.yml
# Setup disk usage exporter targets for Mithril signers
MITHRIL_SIGNER_NODES=$(docker ps --format='{{.Names}},' | grep "mithril-signer" | grep -v "www" | grep -v "relay" | sort | tr -d '\n\t\r ' | sed 's/.$//' | tr ',' ' ')
for MITHRIL_SIGNER_NODE in $MITHRIL_SIGNER_NODES; do
    echo "  /data/$MITHRIL_SIGNER_NODE/mithril: 1" >> /home/curry/docker/prometheus/disk_usage_exporter/disk_usage_exporter.yml 
done
# Setup disk usage exporter target for the IPFS node datastore
if [ "${var.mithril_ipfs_enabled}" = "true" ] ; then
    echo "  /data/ipfs: 1" >> /home/curry/docker/prometheus/disk_usage_exporter/disk_usage_exporter.yml
fi
EOT
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "export NETWORK=${var.cardano_network}",
      "export LOGGING_DRIVER='${var.mithril_container_logging_driver}'",
      "export LOGGING_MAX_SIZE='${var.mithril_container_logging_max_size}'",
      "export LOGGING_MAX_FILE='${var.mithril_container_logging_max_file}'",
      "export PROMETHEUS_HOST=${local.prometheus_host}",
      "export PROMETHEUS_AUTH_USER_PASSWORD=$(htpasswd -nb ${var.prometheus_auth_username} ${var.prometheus_auth_password})",
      "export LOKI_HOST=${local.loki_host}",
      "export LOKI_AUTH_USER_PASSWORD=$(htpasswd -nb ${var.loki_auth_username} ${var.loki_auth_password})",
      "export CURRENT_UID=$(id -u)",
      "docker compose -f /home/curry/docker/docker-compose-monitoring.yaml --profile all up -d",
    ]
  }
}
