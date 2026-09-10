resource "null_resource" "mithril_bootstrap" {

  connection {
    type        = "ssh"
    user        = "curry"
    private_key = local.google_service_account_private_key
    host        = google_compute_address.mithril-external-address.address
  }

  triggers = {
    vm_instance                      = google_compute_instance.vm_instance.id,
    image_id                         = var.mithril_image_id,
    cardano_image_id                 = var.cardano_image_id,
    cardano_image_registry           = var.cardano_image_registry,
    dmq_image_id                     = var.dmq_image_id,
    dmq_image_registry               = var.dmq_image_registry,
    ipfs_image_id                    = var.ipfs_image_id,
    ipfs_image_registry              = var.ipfs_image_registry,
    mithril_ipfs_enabled             = var.mithril_ipfs_enabled,
    mithril_aggregator_auth_username = var.mithril_aggregator_auth_username,
    mithril_aggregator_auth_password = var.mithril_aggregator_auth_password,
  }

  provisioner "file" {
    source      = "assets/infra.version"
    destination = "/home/curry/infra.version"
  }

  provisioner "file" {
    source      = "assets/docker"
    destination = "/home/curry"
  }

  provisioner "file" {
    source      = "assets/tools"
    destination = "/home/curry"
  }

  provisioner "remote-exec" {
    inline = [
      <<-EOT
# Wait for VM startup script to complete
while ! test -f "/startup-ready.txt"; do
  sleep 2
  echo "Waiting for startup script to complete..."
done
echo "Startup script complete!"
EOT
      ,
      "find /home/curry/tools -name '*.sh' -type f | xargs chmod u+x"
    ]
  }
}
