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
    ConfigurationSource, ExecutionEnvironment, SnapshotUploaderType,
    database::repository::{CertificateRepository, SignedEntityStore},
    dependency_injection::{CARDANO_DB_ARTIFACTS_DIR, DependenciesBuilder, IMMUTABLE_ARCHIVES_DIR},
    extract_all,
    tools::{
        CertificatesHashMigrator, ImmutablesArchivesCacheCleaner, ImmutablesArchivesSummary,
        KeypairTools,
    },
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

#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ClearImmutablesArchivesCacheCommandConfiguration {
    /// Directory to store snapshot
    #[example = "`./mithril-aggregator/snapshots`"]
    pub snapshot_directory: PathBuf,

    /// Type of snapshot uploader to use
    #[example = "`gcp` or `local`"]
    pub snapshot_uploader_type: SnapshotUploaderType,
}

impl ConfigurationSource for ClearImmutablesArchivesCacheCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn snapshot_uploader_type(&self) -> SnapshotUploaderType {
        self.snapshot_uploader_type
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
            ClearImmutablesArchivesCache = { ClearImmutablesArchivesCacheCommand },
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

    /// Clear the cache directory of the immutable files compressed archives.
    ///
    /// Must not be run while the aggregator is running.
    ClearImmutablesArchivesCache(ClearImmutablesArchivesCacheCommand),
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
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        match &self.subcommand {
            GenerateKeypairSubCommand::Ed25519(cmd) => cmd.execute(root_logger).await,
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
            Self::GenerateKeypair(cmd) => cmd.execute(root_logger).await,
            Self::ClearImmutablesArchivesCache(cmd) => {
                cmd.execute(root_logger, config_builder).await
            }
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
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "GENERATE KEYPAIR ED25519 command");
        println!(
            "tools generate keypair ed25519 to {}",
            self.target_path.display()
        );
        KeypairTools::create_and_save_ed25519_keypair(&self.target_path)
            .with_context(|| "tools: keypair generation error")?;

        Ok(())
    }

    pub fn extract_config(_command_path: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Clear immutable files compressed archives cache command.
#[derive(Parser, Debug, Clone)]
pub struct ClearImmutablesArchivesCacheCommand {
    /// Delete the archives, without it nothing is deleted
    #[clap(long)]
    delete: bool,
}

impl ClearImmutablesArchivesCacheCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let config: ClearImmutablesArchivesCacheCommandConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "CLEAR IMMUTABLES ARCHIVES CACHE command"; "config" => format!("{config:?}"));
        let cache_dir = config
            .snapshot_directory
            .join(CARDANO_DB_ARTIFACTS_DIR)
            .join(IMMUTABLE_ARCHIVES_DIR);

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir)
            .with_context(|| "clear-immutables-archives-cache: archives detection error")?;
        println!(
            "Immutables archives cache directory: {}",
            cache_dir.display()
        );
        println!("{}", ImmutablesArchivesSummary::from_archives(&archives));

        if archives.is_empty() {
            println!("Nothing to delete: no immutables archives in the cache directory");
            return Ok(());
        }

        if config.allow_http_serve_directory() {
            eprintln!(
                "WARNING: with the 'local' snapshot uploader, this directory is served as is: \
                deleting its archives will break the download of the existing Cardano database snapshots"
            );
        }

        if !self.delete {
            println!("Dry run: nothing was deleted, use '--delete' to delete the archives");
            return Ok(());
        }

        ImmutablesArchivesCacheCleaner::delete_archives(&archives)
            .with_context(|| "clear-immutables-archives-cache: archives deletion error")?;
        println!("Immutables archives deleted");

        Ok(())
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(
            command_path,
            ClearImmutablesArchivesCacheCommandConfiguration::extract(),
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
        use mithril_common::temp_dir_create;

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

        #[tokio::test]
        async fn generate_ed25519_keypair_subcommand_writes_key_files() {
            let target = temp_dir_create!();
            let cmd = Ed25519SubCommand {
                target_path: target.clone(),
            };

            cmd.execute(TestLogger::stdout())
                .await
                .expect("generate-keypair ed25519 should succeed");
            assert!(target.join("ed25519_keypair.sk").exists());
            assert!(target.join("ed25519_keypair.vk").exists());
        }
    }

    mod clear_immutables_archives_cache_subcommand {
        use std::fs::{File, create_dir_all};
        use std::path::Path;

        use mithril_common::temp_dir_create;

        use crate::dependency_injection::{CARDANO_DB_ARTIFACTS_DIR, IMMUTABLE_ARCHIVES_DIR};

        use super::*;

        fn config_builder_with_snapshot_directory(
            snapshot_directory: &Path,
        ) -> ConfigBuilder<DefaultState> {
            config_builder(snapshot_directory, "gcp")
        }

        fn config_builder(
            snapshot_directory: &Path,
            snapshot_uploader_type: &str,
        ) -> ConfigBuilder<DefaultState> {
            config::Config::builder()
                .set_override(
                    "snapshot_directory",
                    snapshot_directory.to_string_lossy().to_string(),
                )
                .unwrap()
                .set_override("snapshot_uploader_type", snapshot_uploader_type)
                .unwrap()
        }

        fn create_cache_dir_with_files(snapshot_directory: &Path, file_names: &[&str]) -> PathBuf {
            let cache_dir = snapshot_directory
                .join(CARDANO_DB_ARTIFACTS_DIR)
                .join(IMMUTABLE_ARCHIVES_DIR);
            create_dir_all(&cache_dir).unwrap();
            for file_name in file_names {
                File::create(cache_dir.join(file_name)).unwrap();
            }

            cache_dir
        }

        #[test]
        fn clear_immutables_archives_cache_subcommand_parses() {
            let cmd = ToolsCommand::try_parse_from(["tools", "clear-immutables-archives-cache"])
                .expect("CLI parse should succeed");

            assert!(matches!(
                cmd.subcommand,
                ToolsSubCommand::ClearImmutablesArchivesCache(
                    ClearImmutablesArchivesCacheCommand { delete: false }
                )
            ));
        }

        #[test]
        fn clear_immutables_archives_cache_subcommand_parses_delete_flag() {
            let cmd = ToolsCommand::try_parse_from([
                "tools",
                "clear-immutables-archives-cache",
                "--delete",
            ])
            .expect("CLI parse should succeed");

            assert!(matches!(
                cmd.subcommand,
                ToolsSubCommand::ClearImmutablesArchivesCache(
                    ClearImmutablesArchivesCacheCommand { delete: true }
                )
            ));
        }

        #[tokio::test]
        async fn dry_run_does_not_delete_archives() {
            let snapshot_directory = temp_dir_create!();
            let cache_dir = snapshot_directory
                .join(CARDANO_DB_ARTIFACTS_DIR)
                .join(IMMUTABLE_ARCHIVES_DIR);
            create_dir_all(&cache_dir).unwrap();
            File::create(cache_dir.join("00000.tar.zst")).unwrap();

            ClearImmutablesArchivesCacheCommand { delete: false }
                .execute(
                    TestLogger::stdout(),
                    config_builder_with_snapshot_directory(&snapshot_directory),
                )
                .await
                .expect("clear-immutables-archives-cache should succeed");

            assert!(cache_dir.join("00000.tar.zst").exists());
        }

        #[tokio::test]
        async fn dry_run_succeeds_if_cache_directory_does_not_exist() {
            let snapshot_directory = temp_dir_create!();

            ClearImmutablesArchivesCacheCommand { delete: false }
                .execute(
                    TestLogger::stdout(),
                    config_builder_with_snapshot_directory(&snapshot_directory),
                )
                .await
                .expect("clear-immutables-archives-cache should succeed");

            assert!(!snapshot_directory.join(CARDANO_DB_ARTIFACTS_DIR).exists());
        }

        #[tokio::test]
        async fn with_delete_flag_deletes_archives_and_keeps_other_files() {
            let snapshot_directory = temp_dir_create!();
            let cache_dir = create_cache_dir_with_files(
                &snapshot_directory,
                &["00000.tar.zst", "00003.tar.zst", "foo.txt"],
            );

            ClearImmutablesArchivesCacheCommand { delete: true }
                .execute(
                    TestLogger::stdout(),
                    config_builder_with_snapshot_directory(&snapshot_directory),
                )
                .await
                .expect("clear-immutables-archives-cache should succeed");

            assert!(!cache_dir.join("00000.tar.zst").exists());
            assert!(!cache_dir.join("00003.tar.zst").exists());
            assert!(cache_dir.join("foo.txt").exists());
        }

        #[tokio::test]
        async fn with_delete_flag_and_local_uploader_still_deletes_archives() {
            let snapshot_directory = temp_dir_create!();
            let cache_dir = create_cache_dir_with_files(&snapshot_directory, &["00000.tar.zst"]);

            ClearImmutablesArchivesCacheCommand { delete: true }
                .execute(
                    TestLogger::stdout(),
                    config_builder(&snapshot_directory, "local"),
                )
                .await
                .expect("clear-immutables-archives-cache should succeed");

            assert!(!cache_dir.join("00000.tar.zst").exists());
        }
    }
}
