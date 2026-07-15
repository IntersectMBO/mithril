mod config_association;
mod database_command;
mod era_command;
mod genesis_command;
mod protocol_configuration_command;
mod serve_command;
mod tools_command;

use anyhow::anyhow;
use clap::{CommandFactory, Parser, Subcommand};
use config::{ConfigBuilder, Map, Source, Value, builder::DefaultState};
use mithril_cli_helper::{register_config_value, register_config_value_option};
use mithril_common::StdResult;
use mithril_doc::{Documenter, GenerateDocCommands, StructDoc};
use slog::{Level, Logger, debug};
use std::{collections::HashMap, path::PathBuf};

pub use protocol_configuration_command::*;

use crate::{DefaultConfiguration, extract_all};

/// Main command selector
#[derive(Debug, Clone, Subcommand)]
pub enum MainCommand {
    Genesis(genesis_command::GenesisCommand),
    Era(era_command::EraCommand),
    Serve(serve_command::ServeCommand),
    Tools(tools_command::ToolsCommand),
    Database(database_command::DatabaseCommand),
    ProtocolConfiguration(protocol_configuration_command::ProtocolConfigurationCommand),
    #[clap(alias("doc"), hide(true))]
    GenerateDoc(GenerateDocCommands),
}
/// Identifies the type of command
pub enum CommandType {
    /// Command that runs a server
    Server,

    /// Command that outputs some result after execution
    CommandLine,
}

impl MainCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match self {
            Self::Genesis(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Era(cmd) => cmd.execute(root_logger).await,
            Self::Serve(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Tools(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Database(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::ProtocolConfiguration(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::GenerateDoc(cmd) => {
                let commands_configs =
                    Self::extract_config(Self::format_crate_name_to_config_key());

                cmd.execute_with_configurations(&mut MainOpts::command(), commands_configs)
                    .map_err(|message| anyhow!(message))
            }
        }
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            MainCommand,
            Database = { database_command::DatabaseCommand },
            Era = { era_command::EraCommand },
            Genesis = { genesis_command::GenesisCommand },
            Serve = { serve_command::ServeCommand },
            Tools = { tools_command::ToolsCommand },
            ProtocolConfiguration =
                { protocol_configuration_command::ProtocolConfigurationCommand },
            GenerateDoc = {},
        )
    }

    fn format_crate_name_to_config_key() -> String {
        env!("CARGO_PKG_NAME").replace("-", "")
    }

    pub fn command_type(&self) -> CommandType {
        match self {
            MainCommand::Serve(_) => CommandType::Server,
            MainCommand::Genesis(_) => CommandType::CommandLine,
            MainCommand::Era(_) => CommandType::CommandLine,
            MainCommand::Tools(_) => CommandType::CommandLine,
            MainCommand::Database(_) => CommandType::CommandLine,
            MainCommand::ProtocolConfiguration(_) => CommandType::CommandLine,
            MainCommand::GenerateDoc(_) => CommandType::CommandLine,
        }
    }
}

/// Mithril aggregator node
#[derive(Documenter, Parser, Debug, Clone)]
#[command(version)]
pub struct MainOpts {
    /// application main command
    #[clap(subcommand)]
    pub command: MainCommand,

    /// Run Mode
    #[clap(short, long, default_value = "dev")]
    pub run_mode: String,

    /// Verbosity level
    #[clap(short, long, action = clap::ArgAction::Count)]
    #[example = "Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace`"]
    pub verbose: u8,

    /// Directory of the Cardano node files
    #[clap(long)]
    pub db_directory: Option<PathBuf>,

    /// Directory where configuration file is located
    #[clap(long, default_value = "./config")]
    pub config_directory: PathBuf,
}

impl Source for MainOpts {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, config::ConfigError> {
        let mut result = Map::new();
        let namespace = "clap arguments".to_string();

        register_config_value_option!(result, &namespace, self.db_directory, |v: PathBuf| format!(
            "{}",
            v.to_string_lossy()
        ));

        Ok(result)
    }
}

impl MainOpts {
    /// execute command
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        let config_file_path = self.config_directory.join(format!("{}.json", self.run_mode));
        let config_builder = config::Config::builder()
            .add_source(DefaultConfiguration::default())
            .add_source(
                config::File::with_name(&config_file_path.to_string_lossy()).required(false),
            )
            .add_source(config::Environment::default().separator("__"))
            .add_source(self.clone());
        debug!(root_logger, "Started"; "run_mode" => &self.run_mode, "node_version" => env!("CARGO_PKG_VERSION"));

        self.command.execute(root_logger, config_builder).await
    }

    /// get log level from parameters
    pub fn log_level(&self) -> Level {
        match self.verbose {
            0 => Level::Error,
            1 => Level::Warning,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_crate_name_as_config_key() {
        let crate_name = MainCommand::format_crate_name_to_config_key();

        assert_eq!(crate_name, "mithrilaggregator");
    }
}
