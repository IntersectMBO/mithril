use std::{collections::HashMap, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::Deserialize;
use slog::{Logger, debug};

use mithril_common::StdResult;
use mithril_doc::{Documenter, StructDoc};

use crate::{
    ConfigurationSource, ExecutionEnvironment,
    dependency_injection::{CARDANO_DB_ARTIFACTS_DIR, IMMUTABLE_ARCHIVES_DIR},
    tools::{ImmutablesArchivesCacheCleaner, ImmutablesArchivesSummary},
};

#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ClearImmutablesArchivesCacheCommandConfiguration {
    /// Directory where the snapshot archives are stored
    #[example = "`./mithril-aggregator/snapshots`"]
    pub snapshot_directory: PathBuf,
}

impl ConfigurationSource for ClearImmutablesArchivesCacheCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
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
            "Immutable archives cache directory: {}",
            cache_dir.display()
        );
        println!("{}", ImmutablesArchivesSummary::from_archives(&archives));

        eprintln!("WARNING: The mithril aggregator must be stopped before running this command");
        eprintln!();
        eprintln!(
            "WARNING: With the 'local' snapshot uploader, this directory is served as is: \
                deleting its archives will break the download of the existing Cardano database snapshots"
        );

        if archives.is_empty() {
            println!("Nothing to delete: no immutable archives in the cache directory");
            return Ok(());
        }

        if !self.delete {
            println!("Dry run: nothing was deleted, use '--delete' to delete the archives");
            return Ok(());
        }

        ImmutablesArchivesCacheCleaner::delete_archives(&archives)
            .with_context(|| "clear-immutables-archives-cache: archives deletion error")?;
        println!("Immutable archives deleted");

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
    use std::fs::{File, create_dir_all};
    use std::path::Path;

    use mithril_common::{temp_dir_create, test::assert_dir_eq};

    use crate::test::TestLogger;

    use super::super::{ToolsCommand, ToolsSubCommand};
    use super::*;

    fn config_builder_with_snapshot_directory(
        snapshot_directory: &Path,
    ) -> ConfigBuilder<DefaultState> {
        config_builder(snapshot_directory)
    }

    fn config_builder(snapshot_directory: &Path) -> ConfigBuilder<DefaultState> {
        config::Config::builder()
            .set_override(
                "snapshot_directory",
                snapshot_directory.to_string_lossy().to_string(),
            )
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
            ToolsSubCommand::ClearImmutablesArchivesCache(ClearImmutablesArchivesCacheCommand {
                delete: false
            })
        ));
    }

    #[test]
    fn clear_immutables_archives_cache_subcommand_parses_delete_flag() {
        let cmd =
            ToolsCommand::try_parse_from(["tools", "clear-immutables-archives-cache", "--delete"])
                .expect("CLI parse should succeed");

        assert!(matches!(
            cmd.subcommand,
            ToolsSubCommand::ClearImmutablesArchivesCache(ClearImmutablesArchivesCacheCommand {
                delete: true
            })
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

        assert_dir_eq!(&cache_dir, "* 00000.tar.zst");
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

        assert_dir_eq!(&snapshot_directory, "");
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

        assert_dir_eq!(&cache_dir, "* foo.txt");
    }
}
