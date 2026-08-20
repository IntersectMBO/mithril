use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use mithril_common::StdResult;
use mithril_common::entities::PartyId;
use slog_scope::info;
use tokio::process::Child;
use tokio::sync::RwLock;

use crate::devnet::PoolNode;
use crate::utils::{MithrilCommand, NodeVersion};
use crate::{
    DEVNET_DMQ_MAGIC_ID, DEVNET_MAGIC_ID, DmqNodeFlavor, ERA_MARKERS_VERIFICATION_KEY,
    PROTOCOL_CONFIGURATION_MARKERS_VERIFICATION_KEY,
};

#[derive(Debug)]
pub struct SignerConfig<'a> {
    pub signer_number: usize,
    pub aggregator_endpoint: String,
    pub pool_node: &'a PoolNode,
    pub cardano_cli_path: &'a Path,
    pub work_dir: &'a Path,
    pub store_dir: &'a Path,
    pub bin_dir: &'a Path,
    pub mithril_run_interval: u32,
    pub mithril_era: &'a str,
    pub mithril_era_reader_adapter: &'a str,
    pub mithril_era_marker_address: &'a str,
    pub protocol_configuration_reader_adapter: &'a str,
    pub protocol_configuration_marker_address: &'a str,
    pub enable_certification: bool,
    pub skip_signature_delayer: bool,
    pub use_dmq: bool,
    pub dmq_node_flavor: &'a Option<DmqNodeFlavor>,
}

#[derive(Debug)]
pub struct Signer {
    name: String,
    party_id: PartyId,
    command: Arc<RwLock<MithrilCommand>>,
    process: RwLock<Option<Child>>,
    version: NodeVersion,
}

impl Signer {
    pub const BIN_NAME: &'static str = "mithril-signer";

    pub fn new(signer_config: &SignerConfig) -> StdResult<Self> {
        let version = NodeVersion::fetch(Self::BIN_NAME, signer_config.bin_dir)?;

        let party_id = signer_config.pool_node.party_id()?;
        let magic_id = DEVNET_MAGIC_ID.to_string();
        let dmq_magic_id = DEVNET_DMQ_MAGIC_ID.to_string();
        let era_reader_adapter_params =
            if signer_config.mithril_era_reader_adapter == "cardano-chain" {
                format!(
                    r#"{{"address": "{}", "verification_key": "{}"}}"#,
                    signer_config.mithril_era_marker_address, ERA_MARKERS_VERIFICATION_KEY
                )
            } else {
                format!(
                    r#"{{"markers": [{{"name": "{}", "epoch": 0}}]}}"#,
                    signer_config.mithril_era
                )
            };
        let protocol_configuration_reader_adapter_config =
            if signer_config.protocol_configuration_reader_adapter == "cardano-chain" {
                format!(
                    r#"{{"type": "cardano-chain", "address": "{}", "verification_key": "{}"}}"#,
                    signer_config.protocol_configuration_marker_address,
                    PROTOCOL_CONFIGURATION_MARKERS_VERIFICATION_KEY
                )
            } else {
                r#"{{"type": "fake"}}"#.to_string()
            };
        let mithril_run_interval = format!("{}", signer_config.mithril_run_interval);
        let skip_signature_delayer = if signer_config.skip_signature_delayer {
            "true"
        } else {
            "false"
        };
        let mut env = HashMap::from([
            ("NETWORK", "devnet"),
            ("NETWORK_MAGIC", &magic_id),
            ("DMQ_NETWORK_MAGIC", &dmq_magic_id),
            ("RUN_INTERVAL", &mithril_run_interval),
            ("AGGREGATOR_ENDPOINT", &signer_config.aggregator_endpoint),
            (
                "DB_DIRECTORY",
                signer_config.pool_node.db_path.to_str().unwrap(),
            ),
            (
                "DATA_STORES_DIRECTORY",
                signer_config.store_dir.to_str().unwrap(),
            ),
            ("STORE_RETENTION_LIMIT", "10"),
            (
                "CARDANO_NODE_SOCKET_PATH",
                signer_config.pool_node.socket_path.to_str().unwrap(),
            ),
            (
                "CARDANO_CLI_PATH",
                signer_config.cardano_cli_path.to_str().unwrap(),
            ),
            (
                "ERA_READER_ADAPTER_TYPE",
                signer_config.mithril_era_reader_adapter,
            ),
            ("ERA_READER_ADAPTER_PARAMS", &era_reader_adapter_params),
            (
                "PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG",
                &protocol_configuration_reader_adapter_config,
            ),
            ("TRANSACTIONS_IMPORT_BLOCK_CHUNK_SIZE", "150"),
            (
                "CARDANO_TRANSACTIONS_BLOCK_STREAMER_THROTTLING_INTERVAL",
                "30",
            ),
            ("PRELOADING_REFRESH_INTERVAL_IN_SECONDS", "10"),
            ("SIGNATURE_PUBLISHER_RETRY_DELAY_MS", "1"),
            ("SIGNATURE_PUBLISHER_DELAYER_DELAY_MS", "1"),
            ("SIGNATURE_PUBLISHER_SKIP_DELAYER", skip_signature_delayer),
            ("PARTY_ID", &party_id),
        ]);
        if signer_config.enable_certification {
            env.insert(
                "KES_SECRET_KEY_PATH",
                signer_config.pool_node.kes_secret_key_path.to_str().unwrap(),
            );
            env.insert(
                "OPERATIONAL_CERTIFICATE_PATH",
                signer_config.pool_node.operational_certificate_path.to_str().unwrap(),
            );
        } else {
            env.insert("PARTY_ID", &party_id);
        }
        let dmq_node_socket_path = if signer_config.use_dmq {
            match signer_config.dmq_node_flavor {
                Some(DmqNodeFlavor::Haskell) => {
                    signer_config.pool_node.dmq_socket_path.to_str().unwrap().to_string()
                }
                Some(DmqNodeFlavor::Fake) => signer_config
                    .work_dir
                    .join(format!("dmq-signer-{}.socket", signer_config.signer_number))
                    .to_str()
                    .unwrap()
                    .to_string(),
                _ => {
                    return Err(anyhow!(format!(
                        "Unsupported DMQ node flavor: {:?}",
                        signer_config.dmq_node_flavor
                    )));
                }
            }
        } else {
            "".to_string()
        };
        if signer_config.use_dmq {
            env.insert("DMQ_NODE_SOCKET_PATH", dmq_node_socket_path.as_str());
        }
        let args = vec!["-vvv"];

        let mut command = MithrilCommand::new(
            "mithril-signer",
            signer_config.work_dir,
            signer_config.bin_dir,
            env,
            &args,
        )?;
        let name = format!("mithril-signer-{}-{party_id}", signer_config.signer_number);
        command.set_log_name(&name);

        Ok(Self {
            name,
            party_id,
            command: Arc::new(RwLock::new(command)),
            process: RwLock::new(None),
            version,
        })
    }

    /// Get the version of the mithril-signer binary.
    pub fn version(&self) -> &NodeVersion {
        &self.version
    }

    pub async fn start(&self) -> StdResult<()> {
        let mut command = self.command.write().await;
        let mut process = self.process.write().await;
        *process = Some(command.start(&[])?);
        Ok(())
    }

    pub async fn stop(&self) -> StdResult<()> {
        let mut process_option = self.process.write().await;
        if let Some(process) = process_option.as_mut() {
            info!("Stopping {}", &self.name);
            process.kill().await.with_context(|| "Could not kill signer")?;
            *process_option = None;
        }
        Ok(())
    }
    pub async fn tail_logs(&self, number_of_line: u64) -> StdResult<()> {
        self.command
            .read()
            .await
            .tail_logs(
                Some(format!("mithril-signer-{}", self.party_id).as_str()),
                number_of_line,
            )
            .await
    }
}
