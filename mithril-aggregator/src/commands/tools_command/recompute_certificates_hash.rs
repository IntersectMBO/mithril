use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::Deserialize;
use slog::{Logger, debug};

use mithril_common::StdResult;
use mithril_doc::{Documenter, StructDoc};
use mithril_persistence::sqlite::{SqliteCleaner, SqliteCleaningTask};

use crate::{
    ConfigurationSource, ExecutionEnvironment,
    database::repository::{CertificateRepository, SignedEntityStore},
    dependency_injection::DependenciesBuilder,
    tools::CertificatesHashMigrator,
};

#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct RecomputeCertificatesHashCommandConfiguration {
    /// Directory to store aggregator databases
    #[example = "`./mithril-aggregator/stores`"]
    pub data_stores_directory: PathBuf,
}

impl ConfigurationSource for RecomputeCertificatesHashCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn data_stores_directory(&self) -> PathBuf {
        self.data_stores_directory.clone()
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
        let config: RecomputeCertificatesHashCommandConfiguration = config_builder
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
        HashMap::from([(
            command_path,
            RecomputeCertificatesHashCommandConfiguration::extract(),
        )])
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
        let config = RecomputeCertificatesHashCommandConfiguration {
            data_stores_directory: temp_dir!().join("stores"),
        };
        let mut dependencies_builder =
            DependenciesBuilder::new(TestLogger::stdout(), Arc::new(config));

        dependencies_builder
            .create_tools_command_container()
            .await
            .expect("Expected container creation to succeed without panicking");
    }
}
