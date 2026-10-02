use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::Deserialize;
use slog::{Logger, debug};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use mithril_common::StdResult;
use mithril_doc::{Documenter, StructDoc};
use mithril_persistence::sqlite::{SqliteCleaner, SqliteCleaningTask};

use crate::{
    ConfigurationSource, ExecutionEnvironment,
    database::repository::{CertificateRepository, SignedEntityStore},
    dependency_injection::DependenciesBuilder,
    extract_all,
    tools::CertificatesHashMigrator,
};

#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ToolsCommandConfiguration {
    /// Directory to store aggregator databases
    #[example = "`./mithril-aggregator/stores`"]
    pub data_stores_directory: PathBuf,
}

impl ConfigurationSource for ToolsCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn data_stores_directory(&self) -> PathBuf {
        self.data_stores_directory.clone()
    }
}

/// List of tools to upkeep the aggregator
#[derive(Parser, Debug, Clone)]
pub struct ToolsCommand {
    /// commands
    #[clap(subcommand)]
    pub subcommand: ToolsSubCommand,
}

impl ToolsCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        self.subcommand.execute(root_logger, config_builder).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            ToolsSubCommand,
            RecomputeCertificatesHash = { RecomputeCertificatesHashCommand },
            GenerateKeypair = { GenerateKeypairCommand },
        )
    }
}

/// Tools subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum ToolsSubCommand {
    /// Load all certificates in the database to recompute their hash and update all related
    /// entities.
    ///
    /// Since it will modify the aggregator sqlite database it's strongly recommended to backup it
    /// before running this command.
    RecomputeCertificatesHash(RecomputeCertificatesHashCommand),

    /// Generate a new keypair
    GenerateKeypair(GenerateKeypairCommand),
}

/// List of commands to generate a new keypair
#[derive(Parser, Debug, Clone)]
pub struct GenerateKeypairCommand {
    /// Keypair type
    #[clap(subcommand)]
    pub subcommand: GenerateKeypairSubCommand,
}

/// Keypair type subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum GenerateKeypairSubCommand {
    /// Generate an Ed25519 keypair
    Ed25519(Ed25519SubCommand),
}

impl GenerateKeypairCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match &self.subcommand {
            GenerateKeypairSubCommand::Ed25519(cmd) => {
                cmd.execute(root_logger, config_builder).await
            }
        }
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            GenerateKeypairSubCommand,
            Ed25519 = { Ed25519SubCommand },
        )
    }
}

impl ToolsSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match self {
            Self::RecomputeCertificatesHash(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::GenerateKeypair(cmd) => cmd.execute(root_logger, config_builder).await,
        }
    }
}

/// Recompute certificates hash command.
#[derive(Parser, Debug, Clone)]
pub struct RecomputeCertificatesHashCommand {}

impl RecomputeCertificatesHashCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let config: ToolsCommandConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "RECOMPUTE CERTIFICATES HASH command"; "config" => format!("{config:?}"));
        println!("Recomputing all certificate hash",);
        let mut dependencies_builder =
            DependenciesBuilder::new(root_logger.clone(), Arc::new(config.clone()));

        let dependencies_container = dependencies_builder
            .create_tools_command_container()
            .await
            .with_context(|| "Failed to create the tools command dependencies container")?;

        let migrator = CertificatesHashMigrator::new(
            CertificateRepository::new(dependencies_container.db_connection.clone()),
            Arc::new(SignedEntityStore::new(
                dependencies_container.db_connection.clone(),
            )),
            root_logger,
        );

        migrator
            .migrate()
            .await
            .with_context(|| "recompute-certificates-hash: database migration error")?;

        SqliteCleaner::new(&dependencies_container.db_connection)
            .with_tasks(&[SqliteCleaningTask::Vacuum])
            .run()
            .with_context(|| "recompute-certificates-hash: database vacuum error")?;

        Ok(())
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(command_path, ToolsCommandConfiguration::extract())])
    }
}

/// Ed25519 keypair generation command.
#[derive(clap::Args, Debug, Clone)]
pub struct Ed25519SubCommand {
    /// Target path for the generated keypair
    #[clap(long)]
    target_path: PathBuf,
}

impl Ed25519SubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        debug!(root_logger, "GENERATE KEYPAIR ED25519 command");
        println!(
            "tools generate keypair ed25519 to {}",
            self.target_path.display()
        );
        Ok(())
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(command_path, ToolsCommandConfiguration::extract())])
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mithril_common::temp_dir;

    use crate::test::TestLogger;

    use super::*;

    #[tokio::test]
    async fn create_container_does_not_panic() {
        let config = ToolsCommandConfiguration {
            data_stores_directory: temp_dir!().join("stores"),
        };
        let mut dependencies_builder =
            DependenciesBuilder::new(TestLogger::stdout(), Arc::new(config));

        dependencies_builder
            .create_tools_command_container()
            .await
            .expect("Expected container creation to succeed without panicking");
    }

    mod generate_keypair_subcommand {
        use super::*;

        #[test]
        fn generate_keypair_subcommand_parses_target_path() {
            let cmd = ToolsCommand::try_parse_from([
                "tools",
                "generate-keypair",
                "ed25519",
                "--target-path",
                "/tmp/keys",
            ])
            .expect("CLI parse should succeed");
            assert!(matches!(
                cmd.subcommand,
                ToolsSubCommand::GenerateKeypair(GenerateKeypairCommand {
                    subcommand: GenerateKeypairSubCommand::Ed25519(_)
                })
            ));
        }
    }
}
