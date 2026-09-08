locals {
  mithril_ipfs_swarm_port  = 4001
  mithril_ipfs_rpc_api_url = "http://ipfs-node:5001/"
}

resource "null_resource" "mithril_ipfs" {
  count = var.mithril_ipfs_enabled ? 1 : 0

  depends_on = [
    null_resource.mithril_bootstrap,
    null_resource.mithril_mount_data_disk,
    null_resource.mithril_network
  ]

  triggers = {
    vm_instance         = google_compute_instance.vm_instance.id,
    ipfs_image_id       = var.ipfs_image_id,
    ipfs_image_registry = var.ipfs_image_registry,
    ipfs_storage_max    = var.mithril_ipfs_storage_max,
  }

  connection {
    type        = "ssh"
    user        = "curry"
    private_key = local.google_service_account_private_key
    host        = google_compute_address.mithril-external-address.address
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /home/curry/data/${var.cardano_network}/ipfs",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "export NETWORK=${var.cardano_network}",
      "export IPFS_IMAGE_ID=${var.ipfs_image_id}",
      "export IPFS_IMAGE_REGISTRY=${var.ipfs_image_registry}",
      "export IPFS_SWARM_PORT=${local.mithril_ipfs_swarm_port}",
      "export IPFS_PUBLIC_ADDRESS=${google_compute_address.mithril-external-address.address}",
      "export IPFS_STORAGE_MAX='${var.mithril_ipfs_storage_max}'",
      "export LOGGING_DRIVER='${var.mithril_container_logging_driver}'",
      "export LOGGING_MAX_SIZE='${var.mithril_container_logging_max_size}'",
      "export LOGGING_MAX_FILE='${var.mithril_container_logging_max_file}'",
      "export CURRENT_UID=$(id -u)",
      "docker compose -f /home/curry/docker/docker-compose-ipfs.yaml --profile all up -d",
    ]
  }
}
