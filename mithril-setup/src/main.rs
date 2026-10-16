#![doc = include_str!("../README.md")]

use anyhow::{Context, Ok};
use clap::{Parser, Subcommand};
use config::{Map, Value};
use slog::{Drain, Fuse, Level, Logger, debug};
use slog_term::Decorator;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

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
    pub async fn execute(&self, root_logger: Logger) -> anyhow::Result<()> {
        self.print_and_log_version(&root_logger);
        debug!(root_logger, "Run Mode: {}", self.run_mode);

        let context = CommandContext::new(self.unstable, self.json, root_logger);
        self.command.execute(context).await
    }

    fn print_and_log_version(&self, root_logger: &Logger) {
        let version = env!("CARGO_PKG_VERSION");
        let version_message = format!("Mithril Setup version: {version}");
        if self.json {
            let json_message = serde_json::json!({
                "mithril_setup_version": version});
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

    fn build_logger(&self) -> anyhow::Result<Logger> {
        let log_output_type = self.get_log_output_type();
        let writer = log_output_type.get_writer()?;

        let drain = if self.log_format_json {
            let drain = slog_bunyan::with_name("mithril-setup", writer)
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
    let logger = args.build_logger()?;

    args.execute(logger).await
}
