#![doc = include_str!("../README.md")]

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{Map, Value};
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use tracing::debug;
use tracing::level_filters::LevelFilter;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use mithril_doc::{Documenter, StructDoc};

use mithril_setup::CommandContext;
use mithril_setup::signer::SignerCommand;

enum LogOutputType {
    StdErr,
    File(String),
}

impl LogOutputType {
    fn get_writer(&self) -> anyhow::Result<Box<dyn Write + Send>> {
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
#[clap(name = "mithril-setup")]
#[clap(
about = "This program helps setting up Mithril environments.",
long_about = None
)]
#[command(version)]
pub struct Args {
    /// Available commands
    #[clap(subcommand)]
    command: SetupCommands,

    /// Run Mode.
    #[clap(long, env = "RUN_MODE", default_value = "dev", global = true)]
    run_mode: String,

    /// Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace).
    #[clap(short, long, action = clap::ArgAction::Count, global = true)]
    #[example = "Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace`"]
    verbose: u8,

    /// Enable JSON output for command results
    #[clap(long, global = true)]
    json: bool,

    /// Enable JSON output for logs displayed according to verbosity level
    #[clap(long, global = true)]
    log_format_json: bool,

    /// Redirect the logs to a file
    #[clap(long, alias("o"), global = true)]
    #[example = "`./mithril-setup.log`"]
    log_output: Option<String>,

    /// Enable unstable commands
    #[clap(long, global = true)]
    unstable: bool,
}

impl Args {
    pub async fn execute(&self) -> anyhow::Result<()> {
        self.print_and_log_version();
        debug!(run_mode = %self.run_mode, "Run mode");

        let context = CommandContext::new(self.unstable, self.json);
        self.command.execute(context).await
    }

    fn print_and_log_version(&self) {
        let version = env!("CARGO_PKG_VERSION");
        let version_message = format!("Mithril Setup version: {version}");
        if self.json {
            let json_message = serde_json::json!({
                "mithril_setup_version": version});
            eprintln!("{json_message}");
        } else {
            eprintln!("{version_message}");
        }
        debug!("{version_message}");
    }

    fn log_level(&self) -> LevelFilter {
        match self.verbose {
            0 => LevelFilter::ERROR,
            1 => LevelFilter::WARN,
            2 => LevelFilter::INFO,
            3 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    }

    fn get_log_output_type(&self) -> LogOutputType {
        if let Some(output_filepath) = &self.log_output {
            LogOutputType::File(output_filepath.to_string())
        } else {
            LogOutputType::StdErr
        }
    }

    /// Install the global subscriber writing the logs to stderr or to the log output file
    fn init_logging(&self) -> anyhow::Result<()> {
        let log_output_type = self.get_log_output_type();
        let writer = Mutex::new(log_output_type.get_writer()?);
        // Colors are only meant for a terminal
        let with_ansi = matches!(log_output_type, LogOutputType::StdErr);

        let result = if self.log_format_json {
            tracing_subscriber::registry()
                .with(self.log_level())
                .with(JsonStorageLayer)
                .with(BunyanFormattingLayer::new(
                    "mithril-setup".to_string(),
                    writer,
                ))
                .try_init()
                .map_err(|error| anyhow::anyhow!(error))
        } else {
            tracing_subscriber::fmt()
                .with_max_level(self.log_level())
                .with_target(false)
                .with_ansi(with_ansi)
                .with_writer(writer)
                .compact()
                .try_init()
                .map_err(|error| anyhow::anyhow!(error))
        };

        result.context("Could not initialize the logs")
    }
}

#[derive(Subcommand, Debug, Clone)]
enum SetupCommands {
    #[clap(arg_required_else_help = false)]
    Signer(SignerCommand),
}

impl SetupCommands {
    pub async fn execute(&self, context: CommandContext) -> anyhow::Result<()> {
        match self {
            Self::Signer(cmd) => cmd.execute(context).await,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load args
    let args = Args::parse();
    args.init_logging()?;

    args.execute().await
}

#[cfg(test)]
mod tests {
    use super::{Args, SetupCommands};
    use clap::Parser;

    #[test]
    fn signer_command_is_registered() {
        let args =
            Args::try_parse_from(["mithril-setup", "signer"]).expect("signer command should parse");

        assert!(matches!(args.command, SetupCommands::Signer(_)));
    }
}
