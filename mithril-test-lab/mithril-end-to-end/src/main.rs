use anyhow::{Context, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand};
use slog::{Drain, Level, Logger};
use slog_scope::{error, info};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{ExitCode, Termination},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::Mutex,
    task::JoinSet,
};

use mithril_common::{
    StdResult,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
    },
    messages::SignedEntityTypeDiscriminantsMessage,
};
use mithril_doc::GenerateDocCommands;
use mithril_end_to_end::toolkit::{ScenarioToolkit, ScenarioToolkitContext};
use mithril_end_to_end::{
    AggregateSignatureType, Aggregator, Client, CompatibilityChecker, CompatibilityCheckerError,
    Devnet, DevnetBootstrapArgs, DmqNodeFlavor, MithrilInfrastructure, MithrilInfrastructureConfig,
    NodeVersion, RelaySigner, RetryableDevnetError, Signer,
};
use mithril_end_to_end::{
    ProtocolConfiguration,
    scenario::{FullScenario, MinimalScenario, RunOnlyScenario},
};

/// Default signed entity types used by scenarios that support multiple entities, such as Full and RunOnly.
const DEFAULT_SIGNED_ENTITY_TYPES: &str =
    "CardanoTransactions,CardanoBlocksTransactions,CardanoStakeDistribution,CardanoDatabase";

/// Tests args
#[derive(Parser, Debug, Clone)]
pub struct Cli {
    /// Test scenario to run
    #[command(subcommand)]
    scenario: Option<ScenarioArgs>,

    /// A directory where all logs, generated devnet artifacts, snapshots and store folder
    /// will be located.
    ///
    /// Optional: if not set it will default to `{system_temp_folder}/mithril-end-to-end`
    /// Exception for MacOS: default is `./mithril-end-to-end` as the length of the temporary directory's path
    /// is too long. It causes the maximum path size of the node.sock file to be exceeded.
    #[clap(long)]
    work_directory: Option<PathBuf>,

    /// Directory to the mithril binaries
    ///
    /// It must contains the binaries of the aggregator, signer and client.
    ///
    /// Defaults to current folder
    #[clap(long, default_value = ".")]
    bin_directory: PathBuf,

    #[command(flatten)]
    cardano_devnet: CardanoDevnetArgs,

    #[command(flatten)]
    mithril: MithrilArgs,

    #[command(flatten)]
    network_topology: NetworkTopologyArgs,

    /// Verbosity level
    #[clap(
        short,
        long,
        action = clap::ArgAction::Count,
        help = "Verbosity level, add more v to increase"
    )]
    verbose: u8,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
enum ScenarioArgs {
    /// Run the full scenario (bootstrap, run, shutdown) [default]
    Full {
        /// Will check the ledger snapshot conversion step using utxo-hd snapshot-converter
        #[clap(long)]
        check_client_cli_snapshot_converter: bool,

        /// Signed entity types parameters (discriminants names in an ordered comma separated list).
        #[clap(
            long,
            value_delimiter = ',',
            default_value = DEFAULT_SIGNED_ENTITY_TYPES
        )]
        signed_entity_types: Vec<String>,
    },
    Minimal {
        /// Additional signed entity type to enable.
        #[clap(long, default_value_t = SignedEntityTypeDiscriminants::CardanoDatabase)]
        signed_entity_type: SignedEntityTypeDiscriminants,
    },
    /// Bootstrap a Cardano devnet, Mithril Aggregators and Signers, and run continuously
    RunOnly {
        /// Signed entity types parameters (discriminants names in an ordered comma separated list).
        #[clap(
            long,
            value_delimiter = ',',
            default_value = DEFAULT_SIGNED_ENTITY_TYPES
        )]
        signed_entity_types: Vec<String>,
    },
    // Note: not a scenario, but clap doesn't support more than one subcommand per command
    #[clap(alias("doc"), hide(true))]
    GenerateDoc(GenerateDocCommands),
}

impl Default for ScenarioArgs {
    fn default() -> Self {
        Self::Full {
            check_client_cli_snapshot_converter: false,
            signed_entity_types: DEFAULT_SIGNED_ENTITY_TYPES.split(',').map(String::from).collect(),
        }
    }
}

impl ScenarioArgs {
    fn signed_entity_types(&self) -> Vec<String> {
        match self {
            ScenarioArgs::Full {
                signed_entity_types,
                ..
            } => signed_entity_types.clone(),
            ScenarioArgs::Minimal { signed_entity_type } => vec![signed_entity_type.to_string()],
            ScenarioArgs::RunOnly {
                signed_entity_types,
                ..
            } => signed_entity_types.clone(),
            ScenarioArgs::GenerateDoc(..) => vec![],
        }
    }
}

#[derive(Args, Debug, Clone)]
struct NetworkTopologyArgs {
    /// Number of aggregators
    #[clap(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..))]
    number_of_aggregators: u8,

    /// Number of signers
    #[clap(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..))]
    number_of_signers: u8,

    /// Use Mithril relays
    #[clap(long)]
    use_relays: bool,

    /// Signer registration relay mode (used only when 'use_relays' is set, can be 'passthrough' or 'p2p')
    #[clap(long, default_value = "passthrough")]
    relay_signer_registration_mode: String,

    /// Signature registration relay mode (used only when 'use_relays' is set, can be 'passthrough' or 'p2p')
    #[clap(long, default_value = "p2p")]
    relay_signature_registration_mode: String,

    /// Enable P2P passive relays in P2P mode (used only when 'use_relays' is set)
    #[clap(long, default_value = "false")]
    use_p2p_passive_relays: bool,

    /// Use DMQ protocol (used to broadcast signatures)
    #[clap(long)]
    use_dmq: bool,

    /// DMQ node flavor (used only when 'use_dmq' is set, can be 'haskell' or 'fake')
    ///
    /// 'haskell': will use the DMQ network created within the 'cardano-devnet'
    /// 'fake': will use a fake DMQ network within created with the Mithril relay
    #[arg(long, value_enum, default_value = "haskell")]
    dmq_node_flavor: Option<DmqNodeFlavor>,

    /// Haskell DMQ node version
    #[clap(long)]
    dmq_node_version: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct MithrilArgs {
    /// Mithril run interval for nodes (in ms)
    #[clap(long, default_value_t = 125)]
    mithril_run_interval: u32,

    /// Mithril era to run
    #[clap(long, default_value = "pythagoras")]
    mithril_era: String,

    /// Mithril next era to run
    #[clap(long)]
    mithril_next_era: Option<String>,

    /// Mithril re-genesis on era switch (used only when 'mithril_next_era' is set)
    #[clap(long, default_value_t = false)]
    mithril_era_regenesis_on_switch: bool,

    /// Mithril era reader adapter
    #[clap(long, default_value = "cardano-chain")]
    mithril_era_reader_adapter: String,

    /// Protocol configuration reader adapter
    #[clap(long, default_value = "cardano-chain")]
    protocol_configuration_reader_adapter: String,

    /// Signers read on-chain protocol configurations
    #[clap(long, default_value_t = false)]
    signers_read_on_chain_protocol_configurations: bool,

    /// Aggregate signature type used to create the certificates
    #[clap(long, value_enum, default_value = "Concatenation")]
    aggregate_signature_type: AggregateSignatureType,

    /// Skip the signature delayer in mithril-signer
    #[clap(long)]
    skip_signature_delayer: bool,
}

#[derive(Args, Debug, Clone)]
struct CardanoDevnetArgs {
    /// Directory containing scripts to bootstrap a devnet
    #[clap(long, default_value = "./devnet")]
    devnet_scripts_directory: PathBuf,

    /// Length of a Cardano slot in the devnet (in s)
    #[clap(long, default_value_t = 0.10)]
    cardano_slot_length: f64,

    /// Length of a Cardano epoch in the devnet (multiple of the slot length)
    #[clap(long, default_value_t = 30.0)]
    cardano_epoch_length: f64,

    /// Cardano node version, must be a valid semver version
    #[clap(long, default_value = "11.0.1")]
    cardano_node_version: semver::Version,

    /// Epoch at which hard fork to the latest Cardano era will be made (starts with the latest era by default)
    #[clap(long, default_value_t = 0)]
    cardano_hard_fork_latest_era_at_epoch: u16,

    /// Skip cardano binaries download
    /// (will use the ones in the `bin` folder of the `Args::devnet_scripts_directory`, which defaults to `./devnet/bin`)
    #[clap(long)]
    skip_cardano_bin_download: bool,

    /// URL to download cardano binaries from (if not set, it will default to the official cardano releases)
    #[clap(long)]
    cardano_binary_url: Option<String>,
}

impl Cli {
    fn log_level(&self) -> Level {
        match self.verbose {
            0 => Level::Error,
            1 => Level::Warning,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }

    fn validate(&self) -> StdResult<()> {
        if !self.network_topology.use_relays && self.network_topology.number_of_aggregators >= 2 {
            return Err(anyhow!(
                "The 'use_relays' parameter must be activated to run more than one aggregator"
            ));
        }

        Ok(())
    }
}

fn main() -> AppResult {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { main_exec().await })
        .into()
}

async fn main_exec() -> StdResult<()> {
    let args = Cli::parse();

    if let Some(ScenarioArgs::GenerateDoc(cmd)) = &args.scenario {
        return cmd.execute(&mut Cli::command()).map_err(|message| anyhow!(message));
    }

    let work_dir = {
        let dir = match &args.work_directory {
            Some(path) => path.to_owned(),
            None => {
                if cfg!(target_os = "macos") {
                    PathBuf::from("./mithril_end_to_end")
                } else {
                    std::env::temp_dir().join("mithril_end_to_end")
                }
            }
        };
        create_workdir_if_not_exist_clean_otherwise(&dir);
        std::path::absolute(&dir).with_context(|| {
            format!(
                "Failed to resolve absolute work directory path: {}",
                dir.display()
            )
        })?
    };

    let _guard = slog_scope::set_global_logger(build_logger(
        &args,
        &work_dir.join("mithril-end-to-end.log"),
    ));

    info!("Starting Mithril End-to-End test suite"; "args" => #?args);

    let artifacts_dir = {
        let path = work_dir.join("artifacts");
        fs::create_dir(&path).with_context(|| "Artifacts dir creation failure")?;
        path
    };
    let store_dir = {
        let path = work_dir.join("stores");
        fs::create_dir(&path).with_context(|| "Stores dir creation failure")?;
        path
    };

    let mut app = App::new();
    let mut app_stopper = AppStopper::new(&app);
    let mut join_set = JoinSet::new();
    with_graceful_shutdown(&mut join_set);

    join_set.spawn(async move { app.run(args, work_dir, store_dir, artifacts_dir).await });

    let res = match join_set.join_next().await {
        Some(Ok(tasks_result)) => tasks_result,
        Some(Err(join_set_error)) => Err(anyhow!(join_set_error)).with_context(|| "JoinSet error"),
        None => Ok(()),
    };

    app_stopper.stop().await;
    join_set.shutdown().await;

    res
}

#[derive(Debug)]
enum AppResult {
    Success(),
    UnretryableError(anyhow::Error),
    RetryableError(anyhow::Error),
    Cancelled(anyhow::Error),
    IncompatibleNode(anyhow::Error),
}

impl AppResult {
    fn exit_code(&self) -> ExitCode {
        match self {
            AppResult::Success() => ExitCode::SUCCESS,
            AppResult::UnretryableError(..) | AppResult::Cancelled(..) => ExitCode::FAILURE,
            AppResult::RetryableError(..) => ExitCode::from(2),
            AppResult::IncompatibleNode(..) => ExitCode::from(3),
        }
    }
}

impl fmt::Display for AppResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppResult::Success() => write!(f, "Success"),
            AppResult::UnretryableError(error) => write!(f, "Error(Unretryable): {error:?}"),
            AppResult::RetryableError(error) => write!(f, "Error(Retryable): {error:?}"),
            AppResult::Cancelled(error) => write!(f, "Cancelled: {error:?}"),
            AppResult::IncompatibleNode(error) => write!(f, "{error:?}"),
        }
    }
}

impl Termination for AppResult {
    fn report(self) -> ExitCode {
        let exit_code = self.exit_code();
        println!(" ");
        println!("{:-^100}", "");
        println!("Mithril End to End test outcome:");
        println!("{:-^100}", "");
        println!("{self}");

        exit_code
    }
}

impl From<StdResult<()>> for AppResult {
    fn from(result: StdResult<()>) -> Self {
        match result {
            Ok(()) => AppResult::Success(),
            Err(error) => {
                if error.is::<RetryableDevnetError>() {
                    AppResult::RetryableError(error)
                } else if error.is::<SignalError>() {
                    AppResult::Cancelled(error)
                } else if error.is::<CompatibilityCheckerError>() {
                    AppResult::IncompatibleNode(error)
                } else {
                    AppResult::UnretryableError(error)
                }
            }
        }
    }
}

struct App {
    devnet: Arc<Mutex<Option<Devnet>>>,
    infrastructure: Arc<Mutex<Option<Arc<MithrilInfrastructure>>>>,
}

impl App {
    fn new() -> Self {
        Self {
            devnet: Arc::new(Mutex::new(None)),
            infrastructure: Arc::new(Mutex::new(None)),
        }
    }

    async fn tail_logs(&self) {
        if let Some(infrastructure) = self.infrastructure.lock().await.as_ref() {
            let _ = infrastructure.tail_logs(40).await.inspect_err(|e| {
                error!("Failed to tail logs: {}", e);
            });
        }
    }

    async fn last_error_in_logs(&self) {
        if let Some(infrastructure) = self.infrastructure.lock().await.as_ref() {
            let _ = infrastructure.last_error_in_logs(1).await.inspect_err(|e| {
                error!("Failed to grep error in logs: {}", e);
            });
        }
    }

    pub async fn run(
        &mut self,
        args: Cli,
        work_dir: PathBuf,
        store_dir: PathBuf,
        artifacts_dir: PathBuf,
    ) -> StdResult<()> {
        let server_port = 8080;
        args.validate()?;
        let scenario = args.scenario.unwrap_or_default();
        let use_relays = args.network_topology.use_relays;
        let relay_signer_registration_mode = args.network_topology.relay_signer_registration_mode;
        let relay_signature_registration_mode =
            args.network_topology.relay_signature_registration_mode;
        let use_dmq = args.network_topology.use_dmq;

        let use_p2p_passive_relays = args.network_topology.use_p2p_passive_relays;

        CompatibilityChecker::default().check(BTreeMap::from([
            (
                Aggregator::BIN_NAME,
                NodeVersion::fetch_semver(Aggregator::BIN_NAME, &args.bin_directory)?,
            ),
            (
                Signer::BIN_NAME,
                NodeVersion::fetch_semver(Signer::BIN_NAME, &args.bin_directory)?,
            ),
            (
                Client::BIN_NAME,
                NodeVersion::fetch_semver(Client::BIN_NAME, &args.bin_directory)?,
            ),
            (
                RelaySigner::BIN_NAME,
                NodeVersion::fetch_semver(RelaySigner::BIN_NAME, &args.bin_directory)?,
            ),
            (
                "cardano-node",
                args.cardano_devnet.cardano_node_version.to_owned(),
            ),
        ]))?;

        let toolkit = ScenarioToolkit::new(ScenarioToolkitContext::new_from_cardano_epoch(
            args.cardano_devnet.cardano_slot_length,
            args.cardano_devnet.cardano_epoch_length,
        ));

        let devnet = Devnet::bootstrap(&DevnetBootstrapArgs {
            devnet_scripts_dir: args.cardano_devnet.devnet_scripts_directory,
            artifacts_target_dir: work_dir.join("devnet"),
            number_of_pool_nodes: args.network_topology.number_of_signers,
            number_of_full_nodes: args.network_topology.number_of_aggregators,
            cardano_slot_length: args.cardano_devnet.cardano_slot_length,
            cardano_epoch_length: args.cardano_devnet.cardano_epoch_length,
            cardano_node_version: args.cardano_devnet.cardano_node_version.to_owned(),
            dmq_node_version: args.network_topology.dmq_node_version.clone(),
            cardano_hard_fork_latest_era_at_epoch: args
                .cardano_devnet
                .cardano_hard_fork_latest_era_at_epoch,
            skip_cardano_bin_download: args.cardano_devnet.skip_cardano_bin_download,
            cardano_binary_url: args.cardano_devnet.cardano_binary_url.clone(),
        })
        .await?;
        *self.devnet.lock().await = Some(devnet.clone());

        let startup_protocol_configuration =
            Self::build_startup_protocol_configuration(&args.mithril.aggregate_signature_type);

        let infrastructure = Arc::new(
            MithrilInfrastructure::start(
                toolkit.clone(),
                &MithrilInfrastructureConfig {
                    number_of_aggregators: args.network_topology.number_of_aggregators,
                    number_of_signers: args.network_topology.number_of_signers,
                    server_port,
                    devnet: devnet.clone(),
                    work_dir,
                    store_dir,
                    artifacts_dir,
                    bin_dir: args.bin_directory,
                    cardano_node_version: args.cardano_devnet.cardano_node_version,
                    mithril_run_interval: args.mithril.mithril_run_interval,
                    mithril_era: args.mithril.mithril_era,
                    mithril_era_reader_adapter: args.mithril.mithril_era_reader_adapter,
                    protocol_configuration_reader_adapter: args
                        .mithril
                        .protocol_configuration_reader_adapter,
                    startup_protocol_configuration,
                    signed_entity_types: scenario.signed_entity_types(),
                    aggregate_signature_type: args.mithril.aggregate_signature_type,
                    use_dmq,
                    dmq_node_flavor: args.network_topology.dmq_node_flavor,
                    use_relays,
                    relay_signer_registration_mode,
                    relay_signature_registration_mode,
                    skip_signature_delayer: args.mithril.skip_signature_delayer,
                    use_p2p_passive_relays,
                    use_era_specific_work_dir: args.mithril.mithril_next_era.is_some(),
                    signers_read_on_chain_protocol_configurations: args
                        .mithril
                        .signers_read_on_chain_protocol_configurations,
                },
            )
            .await?,
        );
        *self.infrastructure.lock().await = Some(infrastructure.clone());

        let (runner, run_forever): (StdResult<()>, bool) = match scenario {
            ScenarioArgs::Full {
                check_client_cli_snapshot_converter,
                signed_entity_types,
            } => {
                let runner = FullScenario::new(
                    toolkit,
                    infrastructure,
                    signed_entity_types,
                    check_client_cli_snapshot_converter,
                    args.mithril.mithril_next_era,
                    args.mithril.mithril_era_regenesis_on_switch,
                )
                .run()
                .await;
                (runner, false)
            }
            ScenarioArgs::Minimal { signed_entity_type } => (
                MinimalScenario::new(toolkit, infrastructure, signed_entity_type)
                    .run()
                    .await,
                false,
            ),
            ScenarioArgs::RunOnly { .. } => (
                RunOnlyScenario::new(toolkit, infrastructure).run().await,
                true,
            ),
            ScenarioArgs::GenerateDoc(_) => {
                unreachable!("ScenarioArgs::GenerateDoc should not be used here")
            }
        };

        match runner.with_context(|| "Mithril End to End test failed") {
            Ok(()) if run_forever => loop {
                info!(
                    "Mithril end to end is running and will remain active until manually stopped..."
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            },
            Ok(()) => Ok(()),
            Err(error) => {
                self.tail_logs().await;
                self.last_error_in_logs().await;
                Err(error)
            }
        }
    }

    fn build_startup_protocol_configuration(
        aggregate_signature_type: &AggregateSignatureType,
    ) -> ProtocolConfiguration {
        let protocol_parameters = match aggregate_signature_type {
            AggregateSignatureType::Concatenation => ProtocolParameters {
                k: 274,
                m: 420,
                phi_f: 0.77,
            },
            AggregateSignatureType::Snark | AggregateSignatureType::IvcSnark => {
                ProtocolParameters {
                    k: 5,
                    m: 9,
                    phi_f: 0.95,
                }
            }
        };
        ProtocolConfiguration {
            epoch: Epoch(0),
            protocol_parameters,
            cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(1),
                step: BlockNumber(15),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(1),
                    step: BlockNumber(15),
                },
            ),
            enabled_signed_entity_types: SignedEntityTypeDiscriminantsMessage::all_known(),
        }
    }
}

struct AppStopper {
    devnet: Arc<Mutex<Option<Devnet>>>,
    infrastructure: Arc<Mutex<Option<Arc<MithrilInfrastructure>>>>,
}

impl AppStopper {
    pub fn new(app: &App) -> Self {
        Self {
            devnet: app.devnet.clone(),
            infrastructure: app.infrastructure.clone(),
        }
    }

    pub async fn stop(&mut self) {
        if let Some(infrastructure) = self.infrastructure.lock().await.as_mut() {
            let _ = infrastructure.stop_nodes().await.inspect_err(|e| {
                error!("Failed to stop nodes: {}", e);
            });
        }
        if let Some(devnet) = self.devnet.lock().await.as_ref() {
            let _ = devnet.stop().await.inspect_err(|e| {
                error!("Failed to stop devnet: {}", e);
            });
        }
    }
}

fn build_logger(args: &Cli, log_file: &Path) -> Logger {
    let terminal_drain = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog::LevelFilter::new(drain, args.log_level()).fuse();
        slog_async::Async::new(drain).build().fuse()
    };

    let file_drain = {
        let file = File::create(log_file).expect("failed to open log file at {log_file}");
        let decorator = slog_term::PlainSyncDecorator::new(file);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog::LevelFilter::new(drain, args.log_level()).fuse();
        slog_async::Async::new(drain).build().fuse()
    };

    let slog_duplicate = slog::Duplicate::new(terminal_drain, file_drain).fuse();

    Logger::root(slog_duplicate, slog::o!())
}

fn create_workdir_if_not_exist_clean_otherwise(work_dir: &Path) {
    if work_dir.exists() {
        fs::remove_dir_all(work_dir).expect("Previous work dir removal failed");
    }
    fs::create_dir(work_dir).expect("Work dir creation failure");
}

#[derive(Error, Debug, PartialEq, Eq)]
#[error("Signal received: `{0}`")]
pub struct SignalError(pub String);

fn with_graceful_shutdown(join_set: &mut JoinSet<StdResult<()>>) {
    join_set.spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM signal");
        sigterm.recv().await;

        Err(anyhow!(SignalError("SIGTERM".to_string())))
    });

    join_set.spawn(async move {
        let mut sigterm = signal(SignalKind::interrupt()).expect("Failed to create SIGINT signal");
        sigterm.recv().await;

        Err(anyhow!(SignalError("SIGINT".to_string())))
    });

    join_set.spawn(async move {
        let mut sigterm = signal(SignalKind::quit()).expect("Failed to create SIGQUIT signal");
        sigterm.recv().await;

        Err(anyhow!(SignalError("SIGQUIT".to_string())))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scenario_is_full_with_expected_signed_entity_types() {
        assert_eq!(
            ScenarioArgs::default(),
            ScenarioArgs::Full {
                check_client_cli_snapshot_converter: false,
                signed_entity_types: DEFAULT_SIGNED_ENTITY_TYPES
                    .split(',')
                    .map(String::from)
                    .collect(),
            }
        )
    }

    #[test]
    fn app_result_exit_code() {
        let expected_exit_code = ExitCode::SUCCESS;
        let exit_code = AppResult::Success().exit_code();
        assert_eq!(expected_exit_code, exit_code);

        let expected_exit_code = ExitCode::FAILURE;
        let exit_code = AppResult::UnretryableError(anyhow::anyhow!("an error")).exit_code();
        assert_eq!(expected_exit_code, exit_code);

        let expected_exit_code = ExitCode::from(2);
        let exit_code = AppResult::RetryableError(anyhow::anyhow!("an error")).exit_code();
        assert_eq!(expected_exit_code, exit_code);

        let expected_exit_code = ExitCode::FAILURE;
        let exit_code = AppResult::Cancelled(anyhow::anyhow!("an error")).exit_code();
        assert_eq!(expected_exit_code, exit_code);
    }

    #[test]
    fn app_result_conversion() {
        assert!(matches!(AppResult::from(Ok(())), AppResult::Success()));

        assert!(matches!(
            AppResult::from(Err(anyhow!(RetryableDevnetError("an error".to_string())))),
            AppResult::RetryableError(_)
        ));

        assert!(matches!(
            AppResult::from(Err(anyhow!("an error"))),
            AppResult::UnretryableError(_)
        ));

        assert!(matches!(
            AppResult::from(Err(anyhow!(SignalError("an error".to_string())))),
            AppResult::Cancelled(_)
        ));
    }

    #[test]
    fn args_fails_validation() {
        let args = Cli::parse_from(["", "--number-of-aggregators", "2"]);
        args.validate().expect_err(
            "validate should fail with more than one aggregator if p2p network is not used",
        );

        let args = Cli::parse_from(["", "--use-relays", "--number-of-aggregators", "2"]);
        args.validate()
            .expect("validate should succeed with more than one aggregator if p2p network is used");
    }
}
