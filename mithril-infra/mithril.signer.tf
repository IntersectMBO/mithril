locals {
  mithril_signers_index                       = [for key, signer in var.mithril_signers : key]
  mithril_signers_www_port                    = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 8080 }
  mithril_signers_relay_listen_port           = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 6060 }
  mithril_signers_relay_server_port           = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 7070 }
  mithril_signers_relay_cardano_port          = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 9090 }
  mithril_signers_block_producer_cardano_port = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 10000 }
  mithril_signers_dmq_relay_port              = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 11000 }
  mithril_signers_dmq_block_producer_port     = { for key, signer in var.mithril_signers : key => index(local.mithril_signers_index, key) + 1 + 12000 }
}

resource "null_resource" "mithril_signer" {
  for_each = var.mithril_signers

  depends_on = [
    null_resource.mithril_aggregator
  ]

  triggers = {
    vm_instance                    = google_compute_instance.vm_instance.id,
    cardano_image_id               = var.cardano_image_id,
    cardano_image_registry         = var.cardano_image_registry,
    dmq_image_id                   = var.dmq_image_id,
    dmq_image_registry             = var.dmq_image_registry,
    image_id                       = var.mithril_image_id,
    mithril_p2p_dmq_dense_topology = var.mithril_p2p_dmq_dense_topology,
    signer_bundle                  = each.value.bundle,
  }

  connection {
    type        = "ssh"
    user        = "curry"
    private_key = local.google_service_account_private_key
    host        = google_compute_address.mithril-external-address.address
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /home/curry/data/${var.cardano_network}",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/config",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/db",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/db/passive",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/db/block-producer",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/db/relay",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/ipc",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/pool",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/www",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/mithril/stores",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/mithril/snapshots",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/relay/config",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/relay/ipc",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/block-producer/config",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/block-producer/ipc",
      "echo -n ${local.mithril_signers_relay_cardano_port[each.key]} > /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/pool/port",
      <<-EOT
set -e
# Setup cardano node configuration
CARDANO_NODE_EXACT_VERSION="${var.cardano_image_id}"
CARDANO_NODE_MINOR_VERSION=$(echo $CARDANO_NODE_EXACT_VERSION | cut -d. -f1,2)
CARDANO_NODE_VERSIONS="$CARDANO_NODE_EXACT_VERSION $CARDANO_NODE_MINOR_VERSION"
SIGNER_TYPES="full relay block-producer"
for SIGNER_TYPE in $SIGNER_TYPES; do
  # Copy the cardano node configuration files to the signer and setup topology files (exact version, and fallback to minor version of the Cardano node)
  FOUND_CONFIGURATION=false
  for CARDANO_NODE_VERSION in $CARDANO_NODE_VERSIONS; do
    if [ -d "/home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}" ]; then 
      # Copy the configuration files to the signer
      SIGNER_TYPE_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/config/$SIGNER_TYPE
      rm -rf $SIGNER_TYPE_CONFIG_DIRECTORY/config
      mkdir -p $SIGNER_TYPE_CONFIG_DIRECTORY
      cp -R /home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network} $SIGNER_TYPE_CONFIG_DIRECTORY
      echo $CARDANO_NODE_VERSION > $SIGNER_TYPE_CONFIG_DIRECTORY/config.version

      # Copy config.json files to the signer
      cat $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json | jq ".hasPrometheus[0] |= \"cardano-node-$SIGNER_TYPE-signer-${each.key}\"" > $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json.new
      rm -f $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json
      mv $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json.new $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json

      # Create the config-bp.json file if not exists
      # From version `10.6`, it is no more needed to have a separate config-bp.json file
      # The support for the config-bp.json file is kept for backward compatibility with older Cardano node versions and will be removed once the minimum supported version is `10.6`
      if [ ! -f "$SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json" ]; then
        cp $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json
      fi

      # Copy config-bp.json to the signer
      cat $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json | jq ".hasPrometheus[0] |= \"cardano-node-$SIGNER_TYPE-signer-${each.key}\"" > $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json.new
      rm -f $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json
      mv $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json.new $SIGNER_TYPE_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config-bp.json

      # Setup cardano node block producer topology
      cat /home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}/cardano-node/topology.json | jq 'del(.peerSnapshotFile)' | jq 'del(.bootstrapPeers)' | jq '.localRoots[0].accessPoints[0] |= . + { "address": "${google_compute_address.mithril-external-address.address}", "port": ${local.mithril_signers_relay_cardano_port[each.key]}}' > /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/pool/topology-block-producer.json

      # Setup cardano node relay topology
      cat /home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}/cardano-node/topology.json > /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/pool/topology-relay.json
      
      # Copy peer snapshot file (if exists)
      if [ -f "/home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}/cardano-node/peer-snapshot.json" ]; then
        cp /home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}/cardano-node/peer-snapshot.json /home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/cardano/pool/peer-snapshot.json
      fi

      FOUND_CONFIGURATION=true
      break
    fi
  done
  # Check if a configuration was found
  if [ "$FOUND_CONFIGURATION" = "false" ]; then
    echo "No cardano node configuration found for version $CARDANO_NODE_EXACT_VERSION of type $SIGNER_TYPE"
    exit 1
  fi
done

EOT
      ,
      <<-EOT
set -e
if [ "${var.mithril_use_p2p_network}" = "true" ] && [ "${var.mithril_p2p_use_dmq_protocol}" = "true" ]; then
  if [ "${var.mithril_p2p_use_real_dmq_node}" = "true" ]; then
    # Setup DMQ node configuration
    SIGNER__TYPES="relay block-producer"
    for SIGNER__TYPE in $SIGNER__TYPES; do
      # Copy the DMQ node configuration files to the signer
      SIGNER__TYPE_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/$SIGNER__TYPE/config
      rm -rf $SIGNER__TYPE_CONFIG_DIRECTORY
      mkdir -p $SIGNER__TYPE_CONFIG_DIRECTORY
      cp -R /home/curry/docker/dmq/config/* $SIGNER__TYPE_CONFIG_DIRECTORY/

      # Setup config.json with network magic and type-specific settings
      if [ "$SIGNER__TYPE" = "block-producer" ]; then
        # Block-producer: disable PeerSharing
        cat $SIGNER__TYPE_CONFIG_DIRECTORY/config.json | jq '. + {"NetworkMagic": ${var.dmq_network_magic_map[var.cardano_network]}, "CardanoNetworkMagic": ${var.cardano_network_magic_map[var.cardano_network]}, "CardanoNodeSocket": "/ipc-cardano/node.socket", "ShelleyGenesisFile": "/config-cardano/cardano-node/shelley-genesis.json", "PeerSharing": false}' > $SIGNER__TYPE_CONFIG_DIRECTORY/config.json.new
      else
        # Relay: keep default PeerSharing
        cat $SIGNER__TYPE_CONFIG_DIRECTORY/config.json | jq '. + {"NetworkMagic": ${var.dmq_network_magic_map[var.cardano_network]}, "CardanoNetworkMagic": ${var.cardano_network_magic_map[var.cardano_network]}, "CardanoNodeSocket": "/ipc-cardano/node.socket", "ShelleyGenesisFile": "/config-cardano/cardano-node/shelley-genesis.json"}' > $SIGNER__TYPE_CONFIG_DIRECTORY/config.json.new
      fi
      rm -f $SIGNER__TYPE_CONFIG_DIRECTORY/config.json
      mv $SIGNER__TYPE_CONFIG_DIRECTORY/config.json.new $SIGNER__TYPE_CONFIG_DIRECTORY/config.json
    done

    # Setup DMQ block-producer topology (connects ONLY to local relay via external IP)
    DMQ_BP_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/block-producer/config
    cat /home/curry/docker/dmq/config/topology.json | jq '.localRoots[0].accessPoints = [{"address": "${google_compute_address.mithril-external-address.address}", "port": ${local.mithril_signers_dmq_relay_port[each.key]}}]' | jq '.localRoots[0].advertise = false' | jq '.localRoots[0].trustable = true' | jq '.localRoots[0].valency = 1' > $DMQ_BP_CONFIG_DIRECTORY/topology.json

    # Setup DMQ relay topology (connects to aggregator + other signer relays + bootstrap peers)
    DMQ_RELAY_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-signer-${each.key}/dmq/relay/config
    cat /home/curry/docker/dmq/config/topology.json | jq '.localRoots[0].advertise = true' | jq '.localRoots[0].accessPoints += [{"address": "${google_compute_address.mithril-external-address.address}", "port": ${local.mithril_aggregator_dmq_port}}]' > $DMQ_RELAY_CONFIG_DIRECTORY/topology.json

    # Add signer relay peers to DMQ relay topology (only in dense topology mode)
    if [ "${var.mithril_p2p_dmq_dense_topology}" = "true" ]; then
      SIGNER_PEER_PORTS="${join(" ", values(local.mithril_signers_dmq_relay_port))}"
      for SIGNER_PEER_PORT in $SIGNER_PEER_PORTS; do
        if [ "$SIGNER_PEER_PORT" != "${local.mithril_signers_dmq_relay_port[each.key]}" ]; then
          cat $DMQ_RELAY_CONFIG_DIRECTORY/topology.json | jq '.localRoots[0].accessPoints += [{"address": "${google_compute_address.mithril-external-address.address}", "port": '"$SIGNER_PEER_PORT"'}]' > $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new
          rm -f $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
          mv $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
        fi
      done
    fi

    # Add bootstrap peers to DMQ relay topology
    if [ "${var.mithril_p2p_network_bootstrap_peer}" != "" ]; then
      BOOTSTRAP_PEERS=$(echo "${var.mithril_p2p_network_bootstrap_peer}" | tr "," " ")
      for BOOTSTRAP_PEER in $BOOTSTRAP_PEERS; do
        BOOTSTRAP_PEER_ADDRESS=$(echo $BOOTSTRAP_PEER | cut -d: -f1)
        BOOTSTRAP_PEER_PORT=$(echo $BOOTSTRAP_PEER | cut -d: -f2)
        cat $DMQ_RELAY_CONFIG_DIRECTORY/topology.json | jq '.localRoots[0].accessPoints += [{"address": "'"$BOOTSTRAP_PEER_ADDRESS"'", "port": '"$BOOTSTRAP_PEER_PORT"'}]' > $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new
        rm -f $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
        mv $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
      done
    fi

    # Update DMQ relay topology valency
    cat $DMQ_RELAY_CONFIG_DIRECTORY/topology.json | jq '.localRoots[0].valency = (.localRoots[0].accessPoints | length)' > $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new
    rm -f $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
    mv $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new $DMQ_RELAY_CONFIG_DIRECTORY/topology.json

    # Enable DMQ relay ledger peers (CIP-155 SRV records)
    if [ "${var.mithril_p2p_dmq_use_ledger_peers}" = "true" ]; then
      cat $DMQ_RELAY_CONFIG_DIRECTORY/topology.json | jq '. + {"useLedgerAfterSlot": 0}' > $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new
      rm -f $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
      mv $DMQ_RELAY_CONFIG_DIRECTORY/topology.json.new $DMQ_RELAY_CONFIG_DIRECTORY/topology.json
    fi

    # Update DMQ block-producer topology valency
    cat $DMQ_BP_CONFIG_DIRECTORY/topology.json | jq '.localRoots[0].valency = (.localRoots[0].accessPoints | length)' > $DMQ_BP_CONFIG_DIRECTORY/topology.json.new
    rm -f $DMQ_BP_CONFIG_DIRECTORY/topology.json
    mv $DMQ_BP_CONFIG_DIRECTORY/topology.json.new $DMQ_BP_CONFIG_DIRECTORY/topology.json
  fi
fi
EOT
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "export SIGNER_ID=${each.key}",
      "export PARTY_ID=${each.value.pool_id}",
      "export NETWORK=${var.cardano_network}",
      "export NETWORK_MAGIC=${var.cardano_network_magic_map[var.cardano_network]}",
      "export CARDANO_IMAGE_ID=${var.cardano_image_id}",
      "export CARDANO_IMAGE_REGISTRY=${var.cardano_image_registry}",
      "export MITHRIL_IMAGE_ID=${var.mithril_image_id}",
      "export DMQ_IMAGE_ID='${var.dmq_image_id}'",
      "export DMQ_IMAGE_REGISTRY=${var.dmq_image_registry}",
      "export SIGNER_HOST=${local.mithril_signers_host[each.key]}",
      "export SIGNER_WWW_PORT=${local.mithril_signers_www_port[each.key]}",
      "export SIGNER_CARDANO_RELAY_ADDR=0.0.0.0",
      "export SIGNER_CARDANO_RELAY_PORT=${local.mithril_signers_relay_cardano_port[each.key]}",
      "export SIGNER_CARDANO_BLOCK_PRODUCER_ADDR=0.0.0.0",
      "export SIGNER_CARDANO_BLOCK_PRODUCER_PORT=${local.mithril_signers_block_producer_cardano_port[each.key]}",
      "export SIGNER_DMQ_RELAY_ADDR='0.0.0.0'",
      "export SIGNER_DMQ_RELAY_PORT=${local.mithril_signers_dmq_relay_port[each.key]}",
      "export SIGNER_DMQ_BLOCK_PRODUCER_ADDR='0.0.0.0'",
      "export SIGNER_DMQ_BLOCK_PRODUCER_PORT=${local.mithril_signers_dmq_block_producer_port[each.key]}",
      "export ERA_READER_ADAPTER_TYPE='${var.mithril_era_reader_adapter_type}'",
      <<-EOT
ERA_READER_ADAPTER_PARAMS=$(jq -nc --arg address "$(wget -q -O - '${var.mithril_era_reader_address_url}')" --arg verification_key "$(wget -q -O - '${var.mithril_era_reader_verification_key_url}')" '{"address": $address, "verification_key": $verification_key}')
export ERA_READER_ADAPTER_PARAMS="$ERA_READER_ADAPTER_PARAMS"
EOT
      ,
      <<-EOT
PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG=$(jq -nc --arg type '${var.mithril_protocol_configuration_reader_adapter_type}' --arg address "$(wget -q -O - '${var.mithril_protocol_configuration_reader_address_url}')" --arg verification_key "$(wget -q -O - '${var.mithril_protocol_configuration_reader_verification_key_url}')" '{"type": $type, "address": $address, "verification_key": $verification_key}')
export PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG="$PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG"
EOT
      ,
      "export AGGREGATOR_RELAY_LISTEN_PORT='${local.mithril_aggregator_relay_mithril_listen_port}'",
      "export SIGNER_RELAY_LISTEN_PORT='${local.mithril_signers_relay_listen_port[each.key]}'",
      "export SIGNER_RELAY_SERVER_PORT='${local.mithril_signers_relay_server_port[each.key]}'",
      "export SIGNER_RELAY_SIGNER_REGISTRATION_MODE='${var.mithril_p2p_signer_relay_signer_registration_mode}'",
      "export SIGNER_RELAY_SIGNATURE_REGISTRATION_MODE='${var.mithril_p2p_signer_relay_signature_registration_mode}'",
      "export SIGNER_RELAY_REGISTRATION_REPEATER_DELAY='${var.mithril_p2p_signer_registration_repeat_delay}'",
      <<-EOT
if [ "${local.mithril_aggregator_is_follower}" = "true" ]; then
  export AGGREGATOR_ENDPOINT='${var.mithril_aggregator_leader_aggregator_endpoint}'
else
  export AGGREGATOR_ENDPOINT='http://${local.mithril_aggregator_credentials}mithril-aggregator:8080/aggregator'
fi
EOT
      ,
      "export P2P_BOOTSTRAP_PEER='${var.mithril_p2p_network_bootstrap_peer}'",
      "export ENABLE_METRICS_SERVER=true",
      "export METRICS_SERVER_IP=0.0.0.0",
      "export METRICS_SERVER_PORT=9090",
      "export LOGGING_DRIVER='${var.mithril_container_logging_driver}'",
      "export LOGGING_MAX_SIZE='${var.mithril_container_logging_max_size}'",
      "export LOGGING_MAX_FILE='${var.mithril_container_logging_max_file}'",
      "export CURRENT_UID=$(id -u)",
      "export DOCKER_GID=$(getent group docker | cut -d: -f3)",
      <<-EOT
# Compute the docker compose files merge sequence for the signer
DOCKER_DIRECTORY=/home/curry/docker
DOCKER_COMPOSE_FILES="-f $DOCKER_DIRECTORY/docker-compose-signer-base.yaml"
# Support for verified signer with squid relay
if [ "${each.value.type}" = "verified" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-verified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bp-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-squid-relay-override.yaml"
fi
if [ "${each.value.type}" = "verified-norelay" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-verified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bp-override.yaml"
fi
# Support for unverified signer with passive Cardano node
if [ "${each.value.type}" = "unverified-cardano-passive" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-unverified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-passive-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-squid-relay-override.yaml"
fi
if [ "${each.value.type}" = "unverified-cardano-passive-norelay" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-unverified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-passive-override.yaml"
fi
# Support for unverified signer with shared Cardano node
if [ "${each.value.type}" = "unverified-cardano-shared" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-unverified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-shared-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-squid-relay-override.yaml"
fi
if [ "${each.value.type}" = "unverified-cardano-shared-norelay" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-unverified-override.yaml"
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-shared-override.yaml"
fi
# Support for Cardano/Mithril bundle image (layers on top of any compatible type)
if [ "${each.value.bundle}" = "true" ]; then
  if [ "${each.value.type}" = "verified" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-bp-override.yaml"
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-bp-squid-relay-override.yaml"
  elif [ "${each.value.type}" = "verified-norelay" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-bp-override.yaml"
  elif [ "${each.value.type}" = "unverified-cardano-passive" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-passive-override.yaml"
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-passive-squid-relay-override.yaml"
  elif [ "${each.value.type}" = "unverified-cardano-passive-norelay" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-passive-override.yaml"
  else
    echo "WARNING: bundle=true is not supported for signer type '${each.value.type}', falling back to non-bundled version"
  fi
fi
# Support for signer P2P network
if [ "${var.mithril_use_p2p_network}" = "true" ]; then
  if [ "${var.mithril_p2p_use_real_dmq_node}" = "true" ]; then
    # Bootstrap peers configuration is done through topology files for the real DMQ node
    echo "Bootstrap peers configuration is done through topology files for the real DMQ node"
  else
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-p2p-base-no-dmq-override.yaml"

    if [ "${var.mithril_p2p_network_bootstrap_peer}" != "" ]; then
      DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-p2p-bootstrap-no-dmq-override.yaml"
    fi
  fi
fi
# Support for DMQ protocol
if [ "${var.mithril_use_p2p_network}" = "true" ] && [ "${var.mithril_p2p_use_dmq_protocol}" = "true" ]; then
  if [ "${var.mithril_p2p_use_real_dmq_node}" = "true" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-p2p-dmq-real-node-override.yaml"
    # Bundle: add DMQ env vars and deps to the cardano container instead of mithril-signer
    if [ "${each.value.bundle}" = "true" ]; then
      if [ "${each.value.type}" = "verified" ] || [ "${each.value.type}" = "verified-norelay" ]; then
        DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-bp-p2p-dmq-real-node-override.yaml"
      elif [ "${each.value.type}" = "unverified-cardano-passive" ] || [ "${each.value.type}" = "unverified-cardano-passive-norelay" ]; then
        DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-passive-p2p-dmq-real-node-override.yaml"
      fi
    fi
  else
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-p2p-dmq-fake-node-override.yaml"
    # Bundle: add DMQ env vars to the cardano container instead of mithril-signer
    if [ "${each.value.bundle}" = "true" ]; then
      if [ "${each.value.type}" = "verified" ] || [ "${each.value.type}" = "verified-norelay" ]; then
        DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-bp-p2p-dmq-fake-node-override.yaml"
      elif [ "${each.value.type}" = "unverified-cardano-passive" ] || [ "${each.value.type}" = "unverified-cardano-passive-norelay" ]; then
        DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-signer-cardano-bundle-passive-p2p-dmq-fake-node-override.yaml"
      fi
    fi
  fi
fi
EOT
      ,
      "docker compose -p $SIGNER_ID $DOCKER_COMPOSE_FILES --profile all up -d",
    ]
  }
}
