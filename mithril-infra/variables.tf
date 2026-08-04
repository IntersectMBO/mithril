variable "environment_prefix" {
  type        = string
  description = "The environment prefix to deploy: testing, pre-release or release"
}

variable "environment_suffix" {
  type        = string
  description = "The environment suffix to deploy"
  default     = ""
}

variable "cardano_network" {
  type        = string
  description = "The Cardano network name to attach: preview, preprod or mainnet"
}

variable "cardano_network_magic_map" {
  type        = map(number)
  description = "The Cardano network magic number mapping from Cardano network name"
  default = {
    "mainnet" = 764824073,
    "preprod" = 1,
    "preview" = 2,
  }
}

variable "dmq_network_magic_map" {
  type        = map(number)
  description = "The DMQ network magic number mapping from Cardano network name"
  default = {
    "mainnet" = 2912307721,
    "preprod" = 2147483649,
    "preview" = 2147483650,
  }
}

locals {
  environment_name_short = format("%s%s", "${var.environment_prefix}-${var.cardano_network}", var.environment_suffix != "" ? "-${var.environment_suffix}" : "")
  environment_name       = "mithril-${local.environment_name_short}"
}

variable "google_region" {
  type        = string
  description = "The region on GCP"
  default     = "europe-west1"
}

variable "google_zone" {
  type        = string
  description = "The zone on GCP"
  default     = "europe-west1-b"
}

variable "google_machine_type" {
  type        = string
  description = "The machine type on which to run the VM on GCP"
  default     = "e2-medium"
}

variable "google_compute_instance_boot_disk_size" {
  type        = number
  description = "Size of the boot disk in GB"
  default     = 200
}

variable "google_compute_instance_boot_disk_type" {
  type        = string
  description = "Type of disk"
  default     = "pd-standard"
}

variable "google_compute_instance_boot_disk_image" {
  type        = string
  description = "Image of the boot disk"
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "google_compute_instance_boot_disk_snapshot" {
  type        = string
  description = "Snapshot used to restore the boot disk"
  default     = ""
}

variable "google_compute_instance_boot_disk_snapshot_max_retention_days" {
  type        = number
  description = "Number of days after a boot disk snapshot is dropped"
  default     = 30
}

variable "google_compute_instance_boot_disk_snapshot_pace_days" {
  type        = number
  description = "Pace of the boot disk snapshot in days"
  default     = 1
}

variable "google_compute_instance_boot_disk_snapshot_start_time" {
  type        = string
  description = "Start time of the boot disk snapshot"
  default     = "04:00"
}

variable "google_compute_instance_data_disk_size" {
  type        = number
  description = "Size of the data disk in GB"
  default     = 250
}

variable "google_compute_instance_data_disk_type" {
  type        = string
  description = "Type of disk"
  default     = "pd-standard"
}

variable "google_compute_instance_data_disk_snapshot" {
  type        = string
  description = "Snapshot used to restore the data disk"
  default     = ""
}

variable "google_compute_instance_data_disk_snapshot_max_retention_days" {
  type        = number
  description = "Number of days after a data disk snapshot is dropped"
  default     = 30
}

variable "google_compute_instance_data_disk_snapshot_pace_days" {
  type        = number
  description = "Pace of the data disk snapshot in days"
  default     = 1
}

variable "google_compute_instance_data_disk_snapshot_start_time" {
  type        = string
  description = "Start time of the data disk snapshot"
  default     = "03:00"
}


variable "google_compute_instance_ssh_keys_environment" {
  type        = string
  description = "VM SSH keys environment (`testing` or `production`)"
}

variable "google_service_credentials_json_file" {
  type        = string
  description = "The credentials of the GCP service account"
}

variable "google_storage_bucket_force_destroy" {
  type        = bool
  description = "Force destroy all items of the bucket when destroying the associated terraform resource"
  default     = false
}

variable "google_storage_bucket_max_age" {
  type        = number
  description = "Number of days after which an object in the storage bucket expires"
  default     = 28
}

variable "google_storage_bucket_prefix_with_lifecyle_rule" {
  type        = list(any)
  description = "The prefix of the object in the storage bucket to apply the lifecycle rule"
  default     = ["cardano-immutable-files-full", "cardano-database/ancillary", "cardano-database/digests"]
}

locals {
  google_service_credentials_json_file_decoded = jsondecode(file(var.google_service_credentials_json_file))
  google_service_account_private_key           = local.google_service_credentials_json_file_decoded.private_key
  google_project_id                            = local.google_service_credentials_json_file_decoded.project_id
}

variable "cardano_image_id" {
  type        = string
  description = "The Cardano image tag of service to deploy"
  default     = "10.7.1"
}

variable "cardano_image_registry" {
  type        = string
  description = "The Cardano image repository of service to deploy"
  default     = "ghcr.io/intersectmbo/cardano-node"
}

variable "mithril_api_domain" {
  type        = string
  description = "The Mithril api (sub)domain name of service to deploy"
}

variable "mithril_image_id" {
  type        = string
  description = "The Mithril image tag of service to deploy"
}

variable "mithril_container_logging_driver" {
  type        = string
  description = "The logging driver used by Mithril containers"
  default     = "json-file"
}

variable "mithril_container_logging_max_size" {
  type        = string
  description = "The maximum size of the log file before it is rotated"
  default     = "1g"
}

variable "mithril_container_logging_max_file" {
  type        = string
  description = "The maximum number of log files to keep"
  default     = "2"
}

variable "mithril_use_p2p_network" {
  type        = bool
  description = "Use the P2P network layer (experimental)"
  default     = false
}

variable "mithril_p2p_use_dmq_protocol" {
  type        = bool
  description = "Use the Decentralized Message Queue protocol (DMQ) (experimental)"
  default     = false
}

variable "mithril_p2p_use_real_dmq_node" {
  type        = bool
  description = "Use the real Decentralized Message Queue (DMQ) node (experimental)"
  default     = false
}

variable "mithril_p2p_dmq_dense_topology" {
  type        = bool
  description = "Use a dense (fully-connected mesh) topology for DMQ nodes. When false, a sparse topology is used where nodes connect only to the bootstrap peer (local aggregator for signers). (experimental, for test only)"
  default     = false
}

variable "mithril_p2p_dmq_use_ledger_peers" {
  type        = bool
  description = "Use ledger peers declared with SRV records (CIP-155) for DMQ nodes. When true, the public facing DMQ nodes (aggregator and signer relays) discover peers from the Cardano ledger. Disabled by default to isolate Mithril networks sharing the same Cardano network. (experimental)"
  default     = false
}

variable "dmq_image_id" {
  type        = string
  description = "The DMQ image tag of service to deploy"
  default     = "0.7.0.0"
}

variable "dmq_image_registry" {
  type        = string
  description = "The DMQ image repository of service to deploy"
  default     = "ghcr.io/intersectmbo/dmq-node"
}

variable "mithril_p2p_network_bootstrap_peer" {
  type        = string
  description = "The dial to address of a bootstrap peer of the P2P network layer. Useful when setting-up a follower aggregator and signers in a different VM. (experimental)"
  default     = ""
}

variable "mithril_p2p_signer_relay_signer_registration_mode" {
  type        = string
  description = "The signer registration mode used by the mithril signer relay. Can be either `p2p` or `passthrough` (defaults to `passthrough`) (experimental, for test only)"
  default     = "passthrough"
}

variable "mithril_p2p_signer_relay_signature_registration_mode" {
  type        = string
  description = "The signature registration mode used by the mithril signer relay. Can be either `p2p` or `passthrough` (defaults to `p2p`) (experimental, for test only)"
  default     = "p2p"
}

variable "mithril_p2p_signer_registration_repeat_delay" {
  type        = number
  description = "The repeat delay in milliseconds for the signer registration when operating in P2P mode (defaults to 1 hour)"
  default     = 3600 * 1000
}

variable "mithril_aggregator_signed_entity_types" {
  type        = string
  description = "The custom signed list of entity types used by the mithril aggregator (discriminants names in an ordered comma separated list)."
  default     = ""
}

variable "mithril_aggregator_aggregate_signature_type" {
  type        = string
  description = "The aggregate signature type used by the mithril aggregator to create certificates."
  default     = "Concatenation"
}

variable "mithril_aggregator_chain_observer_type" {
  type        = string
  description = "The chain observer type used by the mithril aggregator."
  default     = "pallas"
}

variable "mithril_aggregator_snapshot_compression_algorithm" {
  type        = string
  description = "The compression algorithm of the snapshot archive"
  default     = "zstandard"
}

variable "mithril_aggregator_zstandard_parameters_level" {
  type        = string
  description = "Zstandard compression level parameter"
  default     = "9"
}

variable "mithril_aggregator_zstandard_parameters_workers" {
  type        = string
  description = "Zstandard number of workers parameter"
  default     = "4"
}

variable "mithril_aggregator_snapshot_use_cdn_domain" {
  type        = bool
  description = "Use CDN domain for constructing snapshot url"
  default     = false
}

variable "mithril_aggregator_cardano_blocks_transactions_prover_cache_pool_size" {
  type        = number
  description = "Cardano blocks transactions prover cache pool size"
  default     = 10
}

variable "mithril_aggregator_cardano_blocks_transactions_database_connection_pool_size" {
  type        = number
  description = "Cardano blocks transactions database connection pool size"
  default     = 10
}

variable "mithril_aggregator_cardano_blocks_transactions_signing_config_security_parameter" {
  type        = number
  description = "Number of blocks to discard from the tip of the chain when importing Cardano blocks and transactions"
  default     = 100
}

variable "mithril_aggregator_cardano_blocks_transactions_signing_config_step" {
  type        = number
  description = "Number of blocks between signature of the Cardano blocks and transactions"
  default     = 30
}


variable "mithril_aggregator_cardano_transactions_prover_cache_pool_size" {
  type        = number
  description = "Cardano transactions prover cache pool size"
  default     = 10
}

variable "mithril_aggregator_cardano_transactions_database_connection_pool_size" {
  type        = number
  description = "Cardano transactions database connection pool size"
  default     = 10
}

variable "mithril_aggregator_cardano_transactions_signing_config_security_parameter" {
  type        = number
  description = "Number of blocks to discard from the tip of the chain when importing Cardano transactions"
  default     = 100
}

variable "mithril_aggregator_cardano_transactions_signing_config_step" {
  type        = number
  description = "Number of blocks between signature of the Cardano transactions"
  default     = 30
}

variable "mithril_aggregator_cdn_cname" {
  type        = string
  description = "The CNAME field used for the mithril aggregator CDN"
  default     = "c.storage.googleapis.com."
}

variable "mithril_aggregator_auth_username" {
  type        = string
  description = "The username for authentication on the mithril aggregator"
  default     = ""
}

variable "mithril_aggregator_auth_password" {
  type        = string
  description = "The password for authentication on the mithril aggregator"
  default     = ""
}

variable "mithril_aggregator_blockfrost_parameters" {
  type        = string
  description = "Optional parameters to connect to the Blockfrost API. Used to fetch the ticker and name of the registered stake pools."
  default     = ""
}

variable "mithril_aggregator_allow_unparsable_block" {
  type        = bool
  description = "If set no error is returned in case of unparsable block and an error log is written instead. Will be ignored on (pre)production networks."
  default     = false
}

variable "mithril_aggregator_leader_aggregator_endpoint" {
  type        = string
  description = "The endpoint of the leader aggregator to use when running in follower mode (optional)"
  default     = ""
}

variable "mithril_aggregator_ancillary_signer_type" {
  type        = string
  description = "The type of signer used to sign ancillary files"

  validation {
    condition     = contains(["secret-key", "gcp-kms"], var.mithril_aggregator_ancillary_signer_type)
    error_message = "Valid values for 'mithril_aggregator_ancillary_signer_type' are 'secret-key' or 'gcp-kms'."
  }
}

variable "mithril_aggregator_ancillary_signer_secret_key" {
  type        = string
  description = "The secret key used to sign ancillary files (used with mithril_aggregator_ancillary_signer_type='secret-key')"
  default     = ""
}

variable "mithril_aggregator_ancillary_signer_gcp_kms_resource_name" {
  type        = string
  description = "The GCP KMS resource name used to sign ancillary files (used with mithril_aggregator_ancillary_signer_type='gcp-kms')"
  default     = ""
}

variable "mithril_aggregator_ancillary_signer_gcp_kms_credentials" {
  type        = string
  description = "The JSON credentials to access GCP KMS base64 encoded (used with mithril_aggregator_ancillary_signer_type='gcp-kms')"
  default     = ""
}

variable "mithril_aggregator_custom_origin_tag_white_list" {
  type        = string
  description = "The custom origin tags white list used by the mithril aggregator (comma separated list of tags)"
  default     = ""
}

variable "prometheus_auth_username" {
  type        = string
  description = "The username for authentication on local prometheus endpoint"
  default     = ""
}

variable "prometheus_auth_password" {
  type        = string
  description = "The password for authentication on local prometheus endpoint"
  default     = ""
}

variable "prometheus_ingest_host" {
  type        = string
  description = "The host to ingest on remote prometheus endpoint"
  default     = ""
}

variable "prometheus_ingest_username" {
  type        = string
  description = "The username to ingest on remote prometheus endpoint"
  default     = ""
}

variable "prometheus_ingest_password" {
  type        = string
  description = "The password to ingest on remote prometheus endpoint"
  default     = ""
}

variable "loki_auth_username" {
  type        = string
  description = "The username for authentication on local loki endpoint"
  default     = ""
}

variable "loki_auth_password" {
  type        = string
  description = "The password for authentication on local loki endpoint"
  default     = ""
}

variable "loki_ingest_host" {
  type        = string
  description = "The host to ingest on remote loki endpoint"
  default     = ""
}

variable "loki_ingest_username" {
  type        = string
  description = "The username to ingest on remote loki endpoint"
  default     = ""
}

variable "loki_ingest_password" {
  type        = string
  description = "The password to ingest on remote loki endpoint"
  default     = ""
}

locals {
  mithril_aggregator_use_authentication = var.mithril_aggregator_auth_username == "" ? false : true
  mithril_aggregator_is_follower        = var.mithril_aggregator_leader_aggregator_endpoint == "" ? false : true
  mithril_aggregator_credentials        = var.mithril_aggregator_auth_username == "" ? "" : format("%s:%s@", var.mithril_aggregator_auth_username, var.mithril_aggregator_auth_password)
  prometheus_credentials                = var.prometheus_auth_username == "" ? "" : format("%s:%s@", var.prometheus_auth_username, var.prometheus_auth_password)
  loki_credentials                      = var.loki_auth_username == "" ? "" : format("%s:%s@", var.loki_auth_username, var.loki_auth_password)
}

variable "mithril_genesis_verification_key_url" {
  type        = string
  description = "The url of the Mithril genesis verification key used by to verify a genesis certificate"
}
variable "mithril_genesis_secret_key" {
  type        = string
  description = "The Mithril genesis secret key used by the aggregator to bootstrap a genesis certificate (test only)"
}

variable "mithril_protocol_parameters" {
  type = object({
    k     = number,
    m     = number,
    phi_f = number
  })
  description = "The Mithril protocol parameters used to aggregate multi signatures"
  default = {
    k     = 5
    m     = 100
    phi_f = 0.65
  }
}

variable "mithril_era_reader_adapter_type" {
  type        = string
  description = "The Mithril era reader adapter used to read the era markers"
  default     = "cardano-chain"
}

variable "mithril_era_reader_address_url" {
  type        = string
  description = "The url of the Mithril era reader address used to query the on chain Utxo containing the era markers payload"
  default     = ""
}

variable "mithril_era_reader_verification_key_url" {
  type        = string
  description = "The url of the Mithril era reader verification key used by to verify an era markers payload"
  default     = ""
}
variable "mithril_era_reader_secret_key" {
  type        = string
  description = "The Mithril genesis secret key used by the aggregator to generate an era marker payload TxDatum file (test only)"
  default     = ""
}

variable "mithril_signers" {
  type = map(object({
    type    = string
    pool_id = string
    bundle  = optional(bool, false)
  }))
  description = "The Mithril signers configuration to deploy"
  default = {
    "1" = {
      type    = "unverified-cardano-passive",
      pool_id = "pool15qde6mnkc0jgycm69ua0grwxmmu0tke54h5uhml0j8ndw3kcu9x",
    }
  }
}

