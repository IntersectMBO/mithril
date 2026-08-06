locals {
  mithril_aggregator_relay_mithril_listen_port            = 6060
  mithril_aggregator_dmq_port                             = 6161
  mithril_aggregator_ancillary_signer_gcp_kms_credentials = base64decode(var.mithril_aggregator_ancillary_signer_gcp_kms_credentials)
}

resource "null_resource" "mithril_aggregator" {
  depends_on = [
    null_resource.mithril_reverse_proxy
  ]

  triggers = {
    vm_instance                                                                      = google_compute_instance.vm_instance.id,
    cardano_image_id                                                                 = var.cardano_image_id,
    cardano_image_registry                                                           = var.cardano_image_registry,
    image_id                                                                         = var.mithril_image_id,
    dmq_image_id                                                                     = var.dmq_image_id,
    dmq_image_registry                                                               = var.dmq_image_registry,
    mithril_aggregator_auth_username                                                 = var.mithril_aggregator_auth_username,
    mithril_aggregator_auth_password                                                 = var.mithril_aggregator_auth_password,
    mithril_aggregator_aggregate_signature_type                                      = var.mithril_aggregator_aggregate_signature_type,
    mithril_aggregator_signed_entity_types                                           = var.mithril_aggregator_signed_entity_types,
    mithril_aggregator_snapshot_compression_algorithm                                = var.mithril_aggregator_snapshot_compression_algorithm,
    mithril_aggregator_zstandard_parameters_level                                    = var.mithril_aggregator_zstandard_parameters_level,
    mithril_aggregator_zstandard_parameters_workers                                  = var.mithril_aggregator_zstandard_parameters_workers,
    mithril_aggregator_cardano_blocks_transactions_prover_cache_pool_size            = var.mithril_aggregator_cardano_blocks_transactions_prover_cache_pool_size,
    mithril_aggregator_cardano_blocks_transactions_database_connection_pool_size     = var.mithril_aggregator_cardano_blocks_transactions_database_connection_pool_size,
    mithril_aggregator_cardano_blocks_transactions_signing_config_security_parameter = var.mithril_aggregator_cardano_blocks_transactions_signing_config_security_parameter,
    mithril_aggregator_cardano_blocks_transactions_signing_config_step               = var.mithril_aggregator_cardano_blocks_transactions_signing_config_step,
    mithril_aggregator_cardano_transactions_prover_cache_pool_size                   = var.mithril_aggregator_cardano_transactions_prover_cache_pool_size,
    mithril_aggregator_cardano_transactions_database_connection_pool_size            = var.mithril_aggregator_cardano_transactions_database_connection_pool_size,
    mithril_aggregator_cardano_transactions_signing_config_security_parameter        = var.mithril_aggregator_cardano_transactions_signing_config_security_parameter,
    mithril_aggregator_cardano_transactions_signing_config_step                      = var.mithril_aggregator_cardano_transactions_signing_config_step,
    mithril_aggregator_blockfrost_parameters                                         = var.mithril_aggregator_blockfrost_parameters,
    mithril_p2p_dmq_dense_topology                                                   = var.mithril_p2p_dmq_dense_topology,
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
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-aggregator/cardano/config",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-aggregator/cardano/db",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-aggregator/cardano/ipc",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-aggregator/mithril/stores",
      "mkdir -p /home/curry/data/${var.cardano_network}/mithril-aggregator/mithril/snapshots",
      <<-EOT
set -e
# Setup cardano node configuration
# Copy the cardano node configuration files to the aggregator (exact version, and fallback to minor version)
CARDANO_NODE_EXACT_VERSION="${var.cardano_image_id}"
CARDANO_NODE_MINOR_VERSION=$(echo $CARDANO_NODE_EXACT_VERSION | cut -d. -f1,2)
CARDANO_NODE_VERSIONS="$CARDANO_NODE_EXACT_VERSION $CARDANO_NODE_MINOR_VERSION"
FOUND_CONFIGURATION=false
for CARDANO_NODE_VERSION in $CARDANO_NODE_VERSIONS; do
  if [ -d "/home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network}" ]; then 
    AGGREGATOR_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-aggregator/cardano/config
    rm -rf $AGGREGATOR_CONFIG_DIRECTORY
    mkdir -p $AGGREGATOR_CONFIG_DIRECTORY
    cp -R /home/curry/docker/cardano/config/$CARDANO_NODE_VERSION/${var.cardano_network} $AGGREGATOR_CONFIG_DIRECTORY
    echo $CARDANO_NODE_VERSION > $AGGREGATOR_CONFIG_DIRECTORY/config.version
    cat $AGGREGATOR_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json | jq ".hasPrometheus[0] |= \"cardano-node-aggregator\"" > $AGGREGATOR_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json.new
    rm -f $AGGREGATOR_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json
    mv $AGGREGATOR_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json.new $AGGREGATOR_CONFIG_DIRECTORY/${var.cardano_network}/cardano-node/config.json
    FOUND_CONFIGURATION=true
    break
  fi
done
# Check if a configuration was found
if [ "$FOUND_CONFIGURATION" = "false" ]; then
  echo "No cardano node configuration found for version $CARDANO_NODE_EXACT_VERSION"
  exit 1
fi
EOT
      ,
      <<-EOT
set -e
if [ "${var.mithril_use_p2p_network}" = "true" ] && [ "${var.mithril_p2p_use_dmq_protocol}" = "true" ]; then
  if [ "${var.mithril_p2p_use_real_dmq_node}" = "true" ]; then
    # Setup dmq node configuration
    AGGREGATOR_CONFIG_DIRECTORY=/home/curry/data/${var.cardano_network}/mithril-aggregator/dmq
    rm -rf $AGGREGATOR_CONFIG_DIRECTORY/config
    mkdir -p $AGGREGATOR_CONFIG_DIRECTORY
    cp -R /home/curry/docker/dmq/config/ $AGGREGATOR_CONFIG_DIRECTORY

    # Setup dmq node ipc folder (to avoid permission issues)
    mkdir -p $AGGREGATOR_CONFIG_DIRECTORY/ipc

    # Setup dmq node config
    cat $AGGREGATOR_CONFIG_DIRECTORY/config/config.json | jq '. + {"NetworkMagic": ${var.dmq_network_magic_map[var.cardano_network]}, "CardanoNetworkMagic": ${var.cardano_network_magic_map[var.cardano_network]}, "CardanoNodeSocket": "/ipc-cardano/node.socket", "ShelleyGenesisFile": "/config-cardano/cardano-node/shelley-genesis.json"}' > $AGGREGATOR_CONFIG_DIRECTORY/config/config.json.new
    rm -f $AGGREGATOR_CONFIG_DIRECTORY/config/config.json
    mv $AGGREGATOR_CONFIG_DIRECTORY/config/config.json.new $AGGREGATOR_CONFIG_DIRECTORY/config/config.json

    # Setup dmq node topology for signer relay peers (only in dense topology mode)
    if [ "${var.mithril_p2p_dmq_dense_topology}" = "true" ]; then
      SIGNER_PEER_PORTS="${join(" ", values(local.mithril_signers_dmq_relay_port))}"
      for SIGNER_PEER_PORT in $SIGNER_PEER_PORTS; do
        cat $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json | jq '.localRoots[0].advertise = true' | jq '.localRoots[0].accessPoints += [{ "address": "${google_compute_address.mithril-external-address.address}", "port": '"$SIGNER_PEER_PORT"'}]' > $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new
        rm -f $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
        mv $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
      done
    fi

    # Setup dmq node topology for bootstrap peer
    if [ "${var.mithril_p2p_network_bootstrap_peer}" != "" ]; then
      BOOTSTRAP_PEERS=$(echo "${var.mithril_p2p_network_bootstrap_peer}" | tr "," " ")
      for BOOTSTRAP_PEER in $BOOTSTRAP_PEERS; do
        BOOTSTRAP_PEER_ADDRESS=$(echo $BOOTSTRAP_PEER | cut -d: -f1)
        BOOTSTRAP_PEER_PORT=$(echo $BOOTSTRAP_PEER | cut -d: -f2)
        cat $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json | jq '.localRoots[0].advertise = true' | jq '.localRoots[0].accessPoints += [{ "address": "'"$BOOTSTRAP_PEER_ADDRESS"'", "port": '"$BOOTSTRAP_PEER_PORT"'}]' > $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new
        rm -f $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
        mv $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
      done
    fi

    # Update dmq node topology advertise and valency
    cat $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json | jq '.localRoots[0].advertise = true' | jq '.localRoots[0].valency = (.localRoots[0].accessPoints | length)' > $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new
    rm -f $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
    mv $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json

    # Enable dmq node ledger peers (CIP-155 SRV records)
    if [ "${var.mithril_p2p_dmq_use_ledger_peers}" = "true" ]; then
      cat $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json | jq '. + {"useLedgerAfterSlot": 0}' > $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new
      rm -f $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
      mv $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json.new $AGGREGATOR_CONFIG_DIRECTORY/config/topology.json
    fi
  fi
fi
EOT
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "set -e",
      "export NETWORK=${var.cardano_network}",
      "export NETWORK_MAGIC=${var.cardano_network_magic_map[var.cardano_network]}",
      "export CARDANO_IMAGE_ID=${var.cardano_image_id}",
      "export CARDANO_IMAGE_REGISTRY=${var.cardano_image_registry}",
      "export MITHRIL_IMAGE_ID=${var.mithril_image_id}",
      "export DMQ_IMAGE_ID='${var.dmq_image_id}'",
      "export DMQ_IMAGE_REGISTRY=${var.dmq_image_registry}",
      "export AGGREGATOR_HOST=${local.mithril_aggregator_host}",
      "export GOOGLE_APPLICATION_CREDENTIALS_JSON='${local.google_cloud_storage_credentials_json}'",
      "export SIGNED_ENTITY_TYPES='${var.mithril_aggregator_signed_entity_types}'",
      "export AGGREGATE_SIGNATURE_TYPE='${var.mithril_aggregator_aggregate_signature_type}'",
      "export SNAPSHOT_BUCKET_NAME='${google_storage_bucket.cloud_storage.name}'",
      "export SNAPSHOT_USE_CDN_DOMAIN='${var.mithril_aggregator_snapshot_use_cdn_domain}'",
      "export SNAPSHOT_COMPRESSION_ALGORITHM=${var.mithril_aggregator_snapshot_compression_algorithm}",
      "export ZSTANDARD_PARAMETERS__LEVEL=${var.mithril_aggregator_zstandard_parameters_level}",
      "export ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS=${var.mithril_aggregator_zstandard_parameters_workers}",
      "export GENESIS_VERIFICATION_KEY=\"$(wget -q -O - '${var.mithril_genesis_verification_key_url}')\"",
      "export GENESIS_SECRET_KEY='${var.mithril_genesis_secret_key}'",
      "export PROTOCOL_PARAMETERS__K='${var.mithril_protocol_parameters.k}'",
      "export PROTOCOL_PARAMETERS__M='${var.mithril_protocol_parameters.m}'",
      "export PROTOCOL_PARAMETERS__PHI_F='${var.mithril_protocol_parameters.phi_f}'",
      "export CHAIN_OBSERVER_TYPE='${var.mithril_aggregator_chain_observer_type}'",
      "export ERA_READER_ADAPTER_TYPE='${var.mithril_era_reader_adapter_type}'",
      <<-EOT
ERA_READER_ADAPTER_PARAMS=$(jq -nc --arg address "$(wget -q -O - '${var.mithril_era_reader_address_url}')" --arg verification_key "$(wget -q -O - '${var.mithril_era_reader_verification_key_url}')" '{"address": $address, "verification_key": $verification_key}')
export ERA_READER_ADAPTER_PARAMS="$ERA_READER_ADAPTER_PARAMS"
EOT
      ,
      "export ERA_READER_SECRET_KEY='${var.mithril_era_reader_secret_key}'",
      "export PROTOCOL_CONFIGURATION_READER_ADAPTER_TYPE='${var.mithril_protocol_configuration_reader_adapter_type}'",
      <<-EOT
PROTOCOL_CONFIGURATION_READER_ADAPTER_PARAMS=$(jq -nc --arg address "$(wget -q -O - '${var.mithril_protocol_configuration_reader_address_url}')" --arg verification_key "$(wget -q -O - '${var.mithril_protocol_configuration_reader_verification_key_url}')" '{"address": $address, "verification_key": $verification_key}')
export PROTOCOL_CONFIGURATION_READER_ADAPTER_PARAMS="$PROTOCOL_CONFIGURATION_READER_ADAPTER_PARAMS"
EOT
      ,
      "export PROTOCOL_CONFIGURATION_READER_SECRET_KEY='${var.mithril_protocol_configuration_reader_secret_key}'",
      <<-EOT
export ANCILLARY_FILES_SIGNER_TYPE=${var.mithril_aggregator_ancillary_signer_type}
if [ "$ANCILLARY_FILES_SIGNER_TYPE" = "secret-key" ]; then
  export ANCILLARY_FILES_SIGNER_CONFIG=$(jq -nc --arg secret_key '${var.mithril_aggregator_ancillary_signer_secret_key}' '{"type": "secret-key", "secret_key": $secret_key}')
fi
if [ "$ANCILLARY_FILES_SIGNER_TYPE" = "gcp-kms" ]; then
  export ANCILLARY_FILES_SIGNER_CONFIG=$(jq -nc --arg resource_name '${var.mithril_aggregator_ancillary_signer_gcp_kms_resource_name}' '{"type": "gcp-kms", "resource_name": $resource_name, "credentials_json_env_var": "GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON"}')
  export GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON='${local.mithril_aggregator_ancillary_signer_gcp_kms_credentials}'
fi
EOT
      ,
      "export BLOCKFROST_PARAMETERS='${var.mithril_aggregator_blockfrost_parameters}'",
      "export ALLOW_UNPARSABLE_BLOCK=${var.mithril_aggregator_allow_unparsable_block}",
      "export CARDANO_BLOCKS_TRANSACTIONS_PROVER_CACHE_POOL_SIZE=${var.mithril_aggregator_cardano_blocks_transactions_prover_cache_pool_size}",
      "export CARDANO_BLOCKS_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE=${var.mithril_aggregator_cardano_blocks_transactions_database_connection_pool_size}",
      "export CARDANO_BLOCKS_TRANSACTIONS_SIGNING_CONFIG__SECURITY_PARAMETER=${var.mithril_aggregator_cardano_blocks_transactions_signing_config_security_parameter}",
      "export CARDANO_BLOCKS_TRANSACTIONS_SIGNING_CONFIG__STEP=${var.mithril_aggregator_cardano_blocks_transactions_signing_config_step}",
      "export CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE=${var.mithril_aggregator_cardano_transactions_prover_cache_pool_size}",
      "export CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE=${var.mithril_aggregator_cardano_transactions_database_connection_pool_size}",
      "export CARDANO_TRANSACTIONS_SIGNING_CONFIG__SECURITY_PARAMETER=${var.mithril_aggregator_cardano_transactions_signing_config_security_parameter}",
      "export CARDANO_TRANSACTIONS_SIGNING_CONFIG__STEP=${var.mithril_aggregator_cardano_transactions_signing_config_step}",
      "export CUSTOM_ORIGIN_TAG_WHITE_LIST='${var.mithril_aggregator_custom_origin_tag_white_list}'",
      "export PUBLIC_SERVER_URL=${local.mithril_aggregator_endpoint_url}",
      <<-EOT
if [ "${var.mithril_aggregator_auth_username}" != "" && "${var.mithril_aggregator_auth_password}" != "" ]; then
  AUTH_USER_PASSWORD=$(htpasswd -nb ${var.mithril_aggregator_auth_username} ${var.mithril_aggregator_auth_password})
else
  AUTH_USER_PASSWORD=""
fi
export AUTH_USER_PASSWORD=$AUTH_USER_PASSWORD
EOT
      ,
      "export LEADER_AGGREGATOR_ENDPOINT='${var.mithril_aggregator_leader_aggregator_endpoint}'",
      "export AGGREGATOR_RELAY_LISTEN_PORT='${local.mithril_aggregator_relay_mithril_listen_port}'",
      "export AGGREGATOR_DMQ_ADDR='0.0.0.0'",
      "export AGGREGATOR_DMQ_PORT='${local.mithril_aggregator_dmq_port}'",
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
# Compute the docker compose files merge sequence for the aggregator
DOCKER_DIRECTORY=/home/curry/docker
DOCKER_COMPOSE_FILES="-f $DOCKER_DIRECTORY/docker-compose-aggregator-base.yaml"
# Support for aggregator authentication
if [ "${local.mithril_aggregator_use_authentication}" = "true" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-auth-override.yaml"
fi
# Support for aggregator P2P network (without real DMQ node)
if [ "${var.mithril_use_p2p_network}" = "true" ] && [ "${var.mithril_p2p_use_real_dmq_node}" = "false" ]; then
  
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-p2p-base-override.yaml"

  if [ "${var.mithril_p2p_network_bootstrap_peer}" != "" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-p2p-bootstrap-override.yaml"
  fi
fi
# Support for aggregator follower
if [ "${local.mithril_aggregator_is_follower}" = "true" ]; then
  DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-follower-override.yaml"
fi
# Support for DMQ protocol
if [ "${var.mithril_use_p2p_network}" = "true" ] && [ "${var.mithril_p2p_use_dmq_protocol}" = "true" ]; then
  if [ "${var.mithril_p2p_use_real_dmq_node}" = "true" ]; then
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-p2p-dmq-real-node-override.yaml"
  else
    DOCKER_COMPOSE_FILES="$DOCKER_COMPOSE_FILES -f $DOCKER_DIRECTORY/docker-compose-aggregator-p2p-dmq-fake-node-override.yaml"
  fi
fi
EOT
      ,
      "docker compose $DOCKER_COMPOSE_FILES --profile all up -d",
    ]
  }
}
