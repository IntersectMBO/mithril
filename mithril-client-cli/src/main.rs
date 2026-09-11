#![doc = include_str!("../README.md")]

use anyhow::{Context, anyhow};
use clap::{CommandFactory, Parser, Subcommand};
use config::{Map, Source, Value};
use mithril_cli_helper::{register_config_value, register_config_value_option};
use slog::{Drain, Fuse, Level, Logger, debug};
use slog_term::Decorator;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::{fs::File, path::PathBuf};

use mithril_client::MithrilResult;
use mithril_doc::{Documenter, GenerateDocCommands, StructDoc};

use mithril_client_cli::commands::{
    DeprecatedCommand, Deprecation, cardano_block::CardanoBlockCommands,
    cardano_db::CardanoDbCommands, cardano_stake_distribution::CardanoStakeDistributionCommands,
    cardano_transaction::CardanoTransactionCommands,
    mithril_stake_distribution::MithrilStakeDistributionCommands, tools::ToolsCommands,
};
use mithril_client_cli::{ClapError, CommandContext, ConfigParameters};

enum LogOutputType {
    StdErr,
    File(String),
}

impl LogOutputType {
    fn get_writer(&self) -> MithrilResult<Box<dyn Write + Send>> {
        let writer: Box<dyn Write + Send> = match self {
            LogOutputType::StdErr => Box::new(std::io::stderr()),
            LogOutputType::File(filepath) => Box::new(
                File::create(filepath)
                    .with_context(|| format!("Can not create output log file: {filepath}"))?,
            ),
        };

        Ok(writer)
    }
}

#[derive(Documenter, Parser, Debug, Clone)]
#[clap(name = "mithril-client")]
#[clap(
about = "This program shows, downloads and verifies certified blockchain artifacts.",
long_about = None
)]
#[command(version)]
pub struct Args {
    /// Available commands
    #[clap(subcommand)]
    command: ArtifactCommands,

    /// Run Mode.
    #[clap(long, env = "RUN_MODE", default_value = "dev", global = true)]
    run_mode: String,

    /// Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace).
    #[clap(short, long, action = clap::ArgAction::Count, global = true)]
    #[example = "Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace`"]
    verbose: u8,

    /// Directory where configuration file is located.
    #[clap(long, default_value = "./config", global = true)]
    pub config_directory: PathBuf,

    /// Override configuration Aggregator endpoint URL.
    ///
    /// Either the full URL of the aggregator endpoint (e.g., "https://aggregator.release-preprod.api.mithril.network/aggregator")
    /// or a string formatted as "auto:<mithril_network>" to use automatic discovery (e.g., "auto:release-preprod") (unstable).
    #[clap(long, env = "AGGREGATOR_ENDPOINT", global = true)]
    #[example = "`https://aggregator.pre-release-preview.api.mithril.network/aggregator`"]
    aggregator_endpoint: Option<String>,

    /// Enable JSON output for command results
    #[clap(long, global = true)]
    json: bool,

    /// Enable JSON output for logs displayed according to verbosity level
    #[clap(long, global = true)]
    log_format_json: bool,

    /// Redirect the logs to a file
    #[clap(long, alias("o"), global = true)]
    #[example = "`./mithril-client.log`"]
    log_output: Option<String>,

    /// Enable unstable commands
    #[clap(long, global = true)]
    unstable: bool,

    /// Request origin tag
    #[clap(long, global = true)]
    origin_tag: Option<String>,

    /// Read the circuit verification key registry from a local signed registry file instead of
    /// resolving it through the published networks configuration (unstable, for local deployments)
    #[cfg(feature = "future_snark")]
    #[clap(long, env = "CIRCUIT_VERIFICATION_KEY_REGISTRY_PATH", global = true)]
    #[example = "`./circuit-verification-key-registry.json`"]
    circuit_verification_key_registry_path: Option<String>,

    /// Override the Mithril era
    #[clap(long, global = true)]
    #[example = "`pythagoras`"]
    era: Option<String>,
}

impl Args {
    pub async fn execute(&self, root_logger: Logger) -> MithrilResult<()> {
        self.print_and_log_version(&root_logger);
        debug!(root_logger, "Run Mode: {}", self.run_mode);

        let config_parameters = self.config_parameters(&root_logger)?;
        let context = CommandContext::new(config_parameters, self.unstable, self.json, root_logger);

        self.command.execute(context).await
    }

    fn print_and_log_version(&self, root_logger: &Logger) {
        let client_cli_version = env!("CARGO_PKG_VERSION");
        let version_message = format!("Mithril Client CLI version: {client_cli_version}");
        if self.json {
            let json_message = serde_json::json!({
                "mithril_client_cli_version": client_cli_version});
            eprintln!("{json_message}");
        } else {
            eprintln!("{version_message}");
        }
        debug!(root_logger, "{version_message}");
    }

    fn log_level(&self) -> Level {
        match self.verbose {
            0 => Level::Error,
            1 => Level::Warning,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }

    fn get_log_output_type(&self) -> LogOutputType {
        if let Some(output_filepath) = &self.log_output {
            LogOutputType::File(output_filepath.to_string())
        } else {
            LogOutputType::StdErr
        }
    }

    fn wrap_drain<D: Decorator + Send + 'static>(&self, decorator: D) -> Fuse<slog_async::Async> {
        let drain = slog_term::CompactFormat::new(decorator).build().fuse();
        let drain = slog::LevelFilter::new(drain, self.log_level()).fuse();

        slog_async::Async::new(drain).build().fuse()
    }

    fn build_logger(&self) -> MithrilResult<Logger> {
        let log_output_type = self.get_log_output_type();
        let writer = log_output_type.get_writer()?;

        let drain = if self.log_format_json {
            let drain = slog_bunyan::with_name("mithril-client", writer)
                .set_pretty(false)
                .build()
                .fuse();
            let drain = slog::LevelFilter::new(drain, self.log_level()).fuse();

            slog_async::Async::new(drain).build().fuse()
        } else {
            match log_output_type {
                LogOutputType::StdErr => self.wrap_drain(slog_term::TermDecorator::new().build()),
                LogOutputType::File(_) => self.wrap_drain(slog_term::PlainDecorator::new(writer)),
            }
        };

        Ok(Logger::root(Arc::new(drain), slog::o!()))
    }

    fn parse_with_decorator(
        decorator: &dyn Fn(Result<Self, ClapError>) -> Result<Self, ClapError>,
    ) -> Self {
        let result = decorator(Self::try_parse());
        match result {
            Ok(s) => s,
            Err(e) => e.exit(),
        }
    }

    fn handle_deprecated_decorator(
        args_result: Result<Self, ClapError>,
        deprecated_commands: Vec<DeprecatedCommand>,
    ) -> Result<Self, ClapError> {
        let styles = Args::command().get_styles().clone();
        Deprecation::handle_deprecated_commands(args_result, styles, deprecated_commands)
    }

    fn config_parameters(&self, root_logger: &Logger) -> MithrilResult<ConfigParameters> {
        let filename = format!("{}/{}.json", self.config_directory.display(), self.run_mode);
        debug!(root_logger, "Reading configuration file '{filename}'.");
        let config = config::Config::builder()
            .add_source(config::File::with_name(&filename).required(false))
            .add_source(self.clone())
            .set_default("download_dir", "")?
            .build()?;
        let config_hash_map = config.try_deserialize::<HashMap<String, String>>()?;

        Ok(ConfigParameters::new(config_hash_map))
    }
}

impl Source for Args {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, config::ConfigError> {
        let mut map = Map::new();
        let namespace = "clap arguments".to_string();

        let myself = self.clone();
        register_config_value_option!(map, &namespace, myself.aggregator_endpoint);
        register_config_value_option!(map, &namespace, myself.origin_tag);
        register_config_value_option!(map, &namespace, myself.era);
        #[cfg(feature = "future_snark")]
        register_config_value_option!(
            map,
            &namespace,
            myself.circuit_verification_key_registry_path
        );

        Ok(map)
    }
}

#[derive(Subcommand, Debug, Clone)]
enum ArtifactCommands {
    #[clap(subcommand, alias("cdb"))]
    CardanoDb(CardanoDbCommands),

    #[clap(subcommand, alias("msd"))]
    MithrilStakeDistribution(MithrilStakeDistributionCommands),

    #[clap(subcommand, alias("ctx"))]
    CardanoTransaction(CardanoTransactionCommands),

    #[clap(subcommand, alias("cb"))]
    CardanoBlock(CardanoBlockCommands),

    #[clap(subcommand, alias("csd"))]
    CardanoStakeDistribution(CardanoStakeDistributionCommands),

    #[clap(alias("doc"), hide(true))]
    GenerateDoc(GenerateDocCommands),

    #[clap(subcommand)]
    Tools(ToolsCommands),
}

impl ArtifactCommands {
    pub async fn execute(&self, context: CommandContext) -> MithrilResult<()> {
        match self {
            Self::CardanoDb(cmd) => cmd.execute(context).await,
            Self::MithrilStakeDistribution(cmd) => cmd.execute(context).await,
            Self::CardanoTransaction(cmd) => cmd.execute(context).await,
            Self::CardanoBlock(cmd) => cmd.execute(context).await,
            Self::CardanoStakeDistribution(cmd) => cmd.execute(context).await,
            Self::GenerateDoc(cmd) => {
                cmd.execute(&mut Args::command()).map_err(|message| anyhow!(message))
            }
            Self::Tools(cmd) => cmd.execute(context).await,
        }
    }
}

#[tokio::main]
async fn main() -> MithrilResult<()> {
    // Load args
    let args = Args::parse_with_decorator(&|result: Result<Args, ClapError>| {
        Args::handle_deprecated_decorator(
            result,
            vec![
                DeprecatedCommand::new("snapshot", "cardano-db"),
                DeprecatedCommand::new("cardano-db-v2", "cardano-db")
                    .with_alias("cdbv2")
                    .with_additional_message("with option `--backend v2`"),
            ],
        )
    });
    let logger = args.build_logger()?;

    args.execute(logger).await
}
