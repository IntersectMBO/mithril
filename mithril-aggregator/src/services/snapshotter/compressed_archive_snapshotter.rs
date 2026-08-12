use anyhow::{Context, anyhow};
use async_trait::async_trait;
use semver::Version;
use slog::{Logger, debug, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mithril_cardano_node_internal_database::entities::{
    AncillaryFilesManifest, LedgerStateSnapshot,
};
use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, LEDGER_DIR, immutable_trio_names};
use mithril_common::StdResult;
use mithril_common::entities::{CompressionAlgorithm, ImmutableFileNumber};
use mithril_common::logging::LoggerExtensions;
use mithril_file_archiver::{
    ArchiveParameters, FileArchive, FileArchiver,
    appender::{AppenderData, AppenderEntries, TarAppender},
    tools::file_size,
};

use crate::dependency_injection::DependenciesBuilderError;

use super::{Snapshotter, ancillary_signer::AncillarySigner};

const CARDANO_NODE_VERSION_WITH_UTXO_HD_SUPPORT: Version = Version::new(10, 4, 1);

/// Compressed Archive Snapshotter create a compressed file.
pub struct CompressedArchiveSnapshotter {
    /// Cardano node version to adapt the snapshot content if needed
    cardano_node_version: Version,

    /// DB directory to snapshot
    db_directory: PathBuf,

    /// Directory to store ongoing snapshot
    ongoing_snapshot_directory: PathBuf,

    /// Compression algorithm to use
    compression_algorithm: CompressionAlgorithm,

    file_archiver: Arc<FileArchiver>,

    ancillary_signer: Arc<dyn AncillarySigner>,

    logger: Logger,
}

#[async_trait]
impl Snapshotter for CompressedArchiveSnapshotter {
    async fn snapshot_ancillary(
        &self,
        immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        debug!(
            self.logger,
            "Snapshotting ancillary archive: '{archive_name_without_extension}'"
        );

        let temp_snapshot_directory =
            self.temp_ancillary_snapshot_directory(archive_name_without_extension);
        fs::create_dir(&temp_snapshot_directory).with_context(|| {
            format!(
                "Can not create temporary snapshot ancillary directory: '{}'",
                temp_snapshot_directory.display()
            )
        })?;

        let snapshot_result = self
            .snapshot_ancillary_from_temp_directory(
                immutable_file_number,
                &temp_snapshot_directory,
                archive_name_without_extension,
            )
            .await;

        if let Err(e) = fs::remove_dir_all(&temp_snapshot_directory) {
            warn!(
                self.logger, "Failed to remove temporary snapshot ancillary directory '{}'", temp_snapshot_directory.display();
                "error" => ?e
            );
        }
        snapshot_result
    }

    async fn snapshot_immutable_trio(
        &self,
        immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        debug!(
            self.logger,
            "Snapshotting immutable trio {immutable_file_number} into archive '{archive_name_without_extension}'"
        );

        let files_to_archive = immutable_trio_names(immutable_file_number)
            .iter()
            .map(|filename| PathBuf::from(IMMUTABLE_DIR).join(filename))
            .collect();
        let appender = AppenderEntries::new(files_to_archive, self.db_directory.clone())?;

        self.snapshot(archive_name_without_extension, appender).await
    }

    async fn compute_immutable_files_total_uncompressed_size(
        &self,
        up_to_immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<u64> {
        if up_to_immutable_file_number == 0 {
            return Err(anyhow!(
                "Could not compute the total size without immutable files"
            ));
        }
        let immutable_directory = self.db_directory.join(IMMUTABLE_DIR);

        tokio::task::spawn_blocking(move || -> StdResult<_> {
            let immutable_paths = (1..=up_to_immutable_file_number)
                .flat_map(immutable_trio_names)
                .map(|filename| immutable_directory.join(filename))
                .collect();

            file_size::compute_size(immutable_paths)
        })
        .await?
    }

    fn compression_algorithm(&self) -> CompressionAlgorithm {
        self.compression_algorithm
    }
}

impl CompressedArchiveSnapshotter {
    /// Snapshotter factory
    pub fn new(
        cardano_node_version: Version,
        db_directory: PathBuf,
        ongoing_snapshot_directory: PathBuf,
        compression_algorithm: CompressionAlgorithm,
        file_archiver: Arc<FileArchiver>,
        ancillary_signer: Arc<dyn AncillarySigner>,
        logger: Logger,
    ) -> StdResult<CompressedArchiveSnapshotter> {
        if ongoing_snapshot_directory.exists() {
            fs::remove_dir_all(&ongoing_snapshot_directory).with_context(|| {
                format!(
                    "Can not remove snapshotter directory: '{}'.",
                    ongoing_snapshot_directory.display()
                )
            })?;
        }

        fs::create_dir(&ongoing_snapshot_directory).map_err(|e| {
            DependenciesBuilderError::Initialization {
                message: format!(
                    "Can not create snapshotter directory: '{}'.",
                    ongoing_snapshot_directory.display()
                ),
                error: Some(e.into()),
            }
        })?;

        Ok(Self {
            cardano_node_version,
            db_directory,
            ongoing_snapshot_directory,
            compression_algorithm,
            file_archiver,
            ancillary_signer,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    async fn snapshot<T: TarAppender + 'static>(
        &self,
        name_without_extension: &str,
        appender: T,
    ) -> StdResult<FileArchive> {
        let file_archiver = self.file_archiver.clone();
        let parameters = ArchiveParameters {
            archive_name_without_extension: name_without_extension.to_string(),
            target_directory: self.ongoing_snapshot_directory.clone(),
            compression_algorithm: self.compression_algorithm,
        };

        // spawn a separate thread to prevent blocking
        let file_archive = tokio::task::spawn_blocking(move || -> StdResult<FileArchive> {
            file_archiver.archive(parameters, appender)
        })
        .await??;

        Ok(file_archive)
    }

    fn temp_ancillary_snapshot_directory(&self, discriminator: &str) -> PathBuf {
        self.ongoing_snapshot_directory
            .join(format!("temp-ancillary-{discriminator}"))
    }

    async fn snapshot_ancillary_from_temp_directory(
        &self,
        immutable_file_number: ImmutableFileNumber,
        temp_snapshot_directory: &Path,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        let paths_to_include = self
            .get_files_and_directories_for_ancillary_snapshot(
                immutable_file_number,
                temp_snapshot_directory,
            )
            .await?;
        let signed_manifest = self
            .build_and_sign_ancillary_manifest(paths_to_include.clone(), temp_snapshot_directory)
            .await?;
        let appender =
            AppenderEntries::new(paths_to_include, temp_snapshot_directory.to_path_buf())?.chain(
                AppenderData::from_json(
                    PathBuf::from(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME),
                    &signed_manifest,
                )?,
            );
        self.snapshot(archive_name_without_extension, appender).await
    }

    /// Returns the list of files and directories to include in ancillary snapshot.
    ///
    /// Those files will be copied to the target folder in order to have fixed copies that do not
    /// change during the snapshot process.
    ///
    /// The immutable file included in the ancillary archive corresponds to the last one (and not finalized yet)
    /// when the immutable file number given to the function corresponds to the penultimate.
    async fn get_files_and_directories_for_ancillary_snapshot(
        &self,
        immutable_file_number: u64,
        target_folder: &Path,
    ) -> StdResult<Vec<PathBuf>> {
        let next_immutable_file_number = immutable_file_number + 1;
        let mut files_to_snapshot: Vec<PathBuf> = immutable_trio_names(next_immutable_file_number)
            .into_iter()
            .map(|filename| PathBuf::from(IMMUTABLE_DIR).join(filename))
            .collect();

        let db_ledger_dir = self.db_directory.join(LEDGER_DIR);
        let ledger_files = LedgerStateSnapshot::list_all_in_dir(&db_ledger_dir)?;

        let number_of_ledger_to_snapshot =
            if self.cardano_node_version < CARDANO_NODE_VERSION_WITH_UTXO_HD_SUPPORT {
                2
            } else {
                1
            };
        let latest_ledger_files: Vec<PathBuf> = ledger_files
            .iter()
            .rev()
            .take(number_of_ledger_to_snapshot)
            .flat_map(|ledger_state_snapshot| ledger_state_snapshot.get_files_relative_path())
            .map(|path| PathBuf::from(LEDGER_DIR).join(path))
            .collect();
        if latest_ledger_files.is_empty() {
            return Err(anyhow!(
                "No ledger state snapshot found in the ledger directory: '{}'",
                db_ledger_dir.display()
            ));
        }
        files_to_snapshot.extend(latest_ledger_files);

        fs::create_dir(target_folder.join(IMMUTABLE_DIR))
            .with_context(|| format!("Can not create folder: `{}`", target_folder.display()))?;
        fs::create_dir(target_folder.join(LEDGER_DIR))
            .with_context(|| format!("Can not create folder: `{}`", target_folder.display()))?;

        for file in &files_to_snapshot {
            // Some files to snapshot are in subfolders (i.e.: in-memory ledger snapshots files)
            if let Some(parent_dir) = file.parent() {
                let target_parent_dir = target_folder.join(parent_dir);
                if !target_parent_dir.exists() {
                    fs::create_dir_all(&target_parent_dir).with_context(|| {
                        format!("Can not create folder: `{}`", target_parent_dir.display())
                    })?;
                }
            }

            let source = self.db_directory.join(file);
            let target = target_folder.join(file);
            tokio::fs::copy(&source, &target).await.with_context(|| {
                format!(
                    "Failed to copy file `{}` to `{}`",
                    source.display(),
                    target.display()
                )
            })?;
        }

        Ok(files_to_snapshot)
    }

    async fn build_and_sign_ancillary_manifest(
        &self,
        paths_to_include: Vec<PathBuf>,
        temp_snapshot_directory: &Path,
    ) -> StdResult<AncillaryFilesManifest> {
        let mut manifest =
            AncillaryFilesManifest::from_paths(temp_snapshot_directory, paths_to_include).await?;
        let signature = self
            .ancillary_signer
            .compute_ancillary_manifest_signature(&manifest)
            .await?;
        manifest.set_signature(signature);

        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;
    use std::sync::Arc;

    use mithril_cardano_node_internal_database::test::DummyCardanoDbBuilder;
    use mithril_common::test::assert_equivalent;
    use mithril_common::{assert_dir_eq, current_function, temp_dir_create};
    use mithril_file_archiver::test::FileArchiveTestExtension;

    use crate::services::ancillary_signer::MockAncillarySigner;
    use crate::test::TestLogger;

    use super::*;

    const DUMMY_CARDANO_NODE_VERSION: Version = Version::new(1, 2, 3);

    fn list_files(test_dir: &Path) -> Vec<String> {
        fs::read_dir(test_dir)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_owned())
            .collect()
    }

    fn file_archiver_for_test(work_dir: &Path) -> FileArchiver {
        FileArchiver::new_with_default_parameters(
            work_dir.join("verification"),
            TestLogger::stdout(),
        )
    }

    fn snapshotter_for_test(
        test_directory: &Path,
        db_directory: &Path,
        compression_algorithm: CompressionAlgorithm,
    ) -> CompressedArchiveSnapshotter {
        CompressedArchiveSnapshotter::new(
            DUMMY_CARDANO_NODE_VERSION,
            db_directory.to_path_buf(),
            test_directory.join("ongoing_snapshot"),
            compression_algorithm,
            Arc::new(file_archiver_for_test(test_directory)),
            Arc::new(MockAncillarySigner::new()),
            TestLogger::stdout(),
        )
        .unwrap()
    }

    #[test]
    fn return_parametrized_compression_algorithm() {
        let test_dir = temp_dir_create!();
        let snapshotter = snapshotter_for_test(
            &test_dir,
            Path::new("whatever"),
            CompressionAlgorithm::Zstandard,
        );

        assert_eq!(
            CompressionAlgorithm::Zstandard,
            snapshotter.compression_algorithm()
        );
    }

    #[test]
    fn should_create_directory_if_does_not_exist() {
        let test_dir = temp_dir_create!();
        let ongoing_snapshot_directory = test_dir.join("ongoing_snapshot");
        let db_directory = test_dir.join("whatever");

        CompressedArchiveSnapshotter::new(
            DUMMY_CARDANO_NODE_VERSION,
            db_directory,
            ongoing_snapshot_directory.clone(),
            CompressionAlgorithm::Zstandard,
            Arc::new(file_archiver_for_test(&test_dir)),
            Arc::new(MockAncillarySigner::new()),
            TestLogger::stdout(),
        )
        .unwrap();

        assert!(ongoing_snapshot_directory.is_dir());
    }

    #[test]
    fn should_clean_ongoing_snapshot_directory_if_already_exists() {
        let test_dir = temp_dir_create!();
        let ongoing_snapshot_directory = test_dir.join("ongoing_snapshot");
        let db_directory = test_dir.join("whatever");

        fs::create_dir_all(&ongoing_snapshot_directory).unwrap();

        File::create(ongoing_snapshot_directory.join("whatever.txt")).unwrap();

        CompressedArchiveSnapshotter::new(
            DUMMY_CARDANO_NODE_VERSION,
            db_directory,
            ongoing_snapshot_directory.clone(),
            CompressionAlgorithm::Zstandard,
            Arc::new(file_archiver_for_test(&test_dir)),
            Arc::new(MockAncillarySigner::new()),
            TestLogger::stdout(),
        )
        .unwrap();

        assert_eq!(0, fs::read_dir(ongoing_snapshot_directory).unwrap().count());
    }

    #[tokio::test]
    async fn should_create_snapshots_in_its_ongoing_snapshot_directory() {
        let test_dir = temp_dir_create!();
        let pending_snapshot_directory = test_dir.join("pending_snapshot");
        let cardano_db = DummyCardanoDbBuilder::new(current_function!())
            .with_immutables(&[1])
            .append_immutable_trio()
            .build();

        let snapshotter = CompressedArchiveSnapshotter::new(
            DUMMY_CARDANO_NODE_VERSION,
            cardano_db.get_dir().clone(),
            pending_snapshot_directory.clone(),
            CompressionAlgorithm::Zstandard,
            Arc::new(file_archiver_for_test(&test_dir)),
            Arc::new(MockAncillarySigner::new()),
            TestLogger::stdout(),
        )
        .unwrap();
        let snapshot = snapshotter.snapshot_immutable_trio(1, "whatever").await.unwrap();

        assert_eq!(
            pending_snapshot_directory,
            snapshot.get_file_path().parent().unwrap()
        );
    }

    mod snapshot_immutable_trio {
        use super::*;

        #[tokio::test]
        async fn include_only_immutable_trio() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .with_legacy_ledger_snapshots(&[437])
                .with_volatile_files(&["blocks-0.dat"])
                .with_non_immutables(&["random_file.txt", "00002.trap"])
                .build();

            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );

            let snapshot = snapshotter.snapshot_immutable_trio(2, "immutable-2").await.unwrap();

            let unpack_dir = snapshot.unpack_zstandard(&test_dir);
            let unpacked_files = list_files(&unpack_dir);
            let unpacked_immutable_files = list_files(&unpack_dir.join(IMMUTABLE_DIR));

            assert_equivalent!(vec![IMMUTABLE_DIR.to_string()], unpacked_files);
            assert_equivalent!(
                vec![
                    "00002.chunk".to_string(),
                    "00002.primary".to_string(),
                    "00002.secondary".to_string(),
                ],
                unpacked_immutable_files,
            );
        }
    }

    mod snapshot_ancillary {
        use mithril_common::test::double::fake_keys;

        use super::*;

        #[tokio::test]
        async fn getting_files_to_include_for_legacy_ledger_snapshot_copy_them_to_a_target_directory_while_keeping_source_dir_structure()
         {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .with_legacy_ledger_snapshots(&[737])
                .build();
            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );
            let ancillary_snapshot_dir = test_dir.join("ancillary_snapshot");
            fs::create_dir(&ancillary_snapshot_dir).unwrap();

            snapshotter
                .get_files_and_directories_for_ancillary_snapshot(1, &ancillary_snapshot_dir)
                .await
                .unwrap();

            assert_dir_eq!(
                &ancillary_snapshot_dir,
                format!(
                    "* {IMMUTABLE_DIR}/
                     ** 00002.chunk
                     ** 00002.primary
                     ** 00002.secondary
                     * {LEDGER_DIR}/
                     ** 737"
                )
            );
        }

        #[tokio::test]
        async fn getting_files_to_include_for_in_memory_ledger_snapshot_copy_them_to_a_target_directory_while_keeping_source_dir_structure()
         {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .with_in_memory_ledger_snapshots(&[737])
                .build();
            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );
            let ancillary_snapshot_dir = test_dir.join("ancillary_snapshot");
            fs::create_dir(&ancillary_snapshot_dir).unwrap();

            snapshotter
                .get_files_and_directories_for_ancillary_snapshot(1, &ancillary_snapshot_dir)
                .await
                .unwrap();

            assert_dir_eq!(
                &ancillary_snapshot_dir,
                format!(
                    "* {IMMUTABLE_DIR}/
                     ** 00002.chunk
                     ** 00002.primary
                     ** 00002.secondary
                     * {LEDGER_DIR}/
                     ** 737/
                     *** {}/
                     **** {}
                     *** {}
                     *** {}",
                    LedgerStateSnapshot::IN_MEMORY_TABLES,
                    LedgerStateSnapshot::IN_MEMORY_TVAR,
                    LedgerStateSnapshot::IN_MEMORY_META,
                    LedgerStateSnapshot::IN_MEMORY_STATE,
                )
            );
        }

        #[tokio::test]
        async fn getting_files_to_include_fails_when_no_ledger_file_found() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .build();
            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );
            let ancillary_snapshot_dir = test_dir.join("ancillary_snapshot");
            fs::create_dir(&ancillary_snapshot_dir).unwrap();

            snapshotter
                .get_files_and_directories_for_ancillary_snapshot(1, &ancillary_snapshot_dir)
                .await
                .expect_err("Should fail if no ledger file found");
        }

        #[tokio::test]
        async fn delete_temporary_working_directory_after_snapshot_is_created() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .with_legacy_ledger_snapshots(&[637])
                .build();
            let snapshotter = CompressedArchiveSnapshotter {
                ancillary_signer: Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    fake_keys::signable_manifest_signature()[0],
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            snapshotter.snapshot_ancillary(1, "ancillary").await.unwrap();

            let temp_ancillary_snapshot_dir =
                snapshotter.temp_ancillary_snapshot_directory("ancillary");
            assert!(
                !temp_ancillary_snapshot_dir.exists(),
                "Expected temporary ancillary snapshot directory to be deleted, but it still exists: {}",
                temp_ancillary_snapshot_dir.display()
            );
        }

        #[tokio::test]
        async fn delete_temporary_working_directory_even_if_snapshot_creation_fails() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .with_legacy_ledger_snapshots(&[637])
                .build();
            let snapshotter = CompressedArchiveSnapshotter {
                ancillary_signer: Arc::new(MockAncillarySigner::that_fails_with_message("failure")),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            snapshotter.snapshot_ancillary(1, "ancillary").await.unwrap_err();

            let temp_ancillary_snapshot_dir =
                snapshotter.temp_ancillary_snapshot_directory("ancillary");
            assert!(
                !temp_ancillary_snapshot_dir.exists(),
                "Expected temporary ancillary snapshot directory to be deleted, but it still exists: {}",
                temp_ancillary_snapshot_dir.display()
            );
        }

        #[tokio::test]
        async fn create_archive_should_embed_only_two_last_ledgers_and_last_immutables_for_cardano_node_below_10_4_1()
         {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .with_legacy_ledger_snapshots(&[437, 537, 637, 737])
                .with_non_ledger_files(&["9not_included"])
                .with_volatile_files(&["blocks-0.dat", "blocks-1.dat", "blocks-2.dat"])
                .build();
            fs::create_dir(cardano_db.get_dir().join("whatever")).unwrap();

            let snapshotter = CompressedArchiveSnapshotter {
                cardano_node_version: Version::new(10, 4, 0),
                ancillary_signer: Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    fake_keys::signable_manifest_signature()[0],
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            let snapshot = snapshotter.snapshot_ancillary(2, "ancillary").await.unwrap();

            let unpack_dir = snapshot.unpack_zstandard(&test_dir);
            assert_dir_eq!(
                &unpack_dir,
                // Only the two last ledger files should be included
                format!(
                    "* {IMMUTABLE_DIR}/
                     ** 00003.chunk
                     ** 00003.primary
                     ** 00003.secondary
                     * {LEDGER_DIR}/
                     ** 637
                     ** 737
                     * {}",
                    AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME
                )
            );
        }

        #[tokio::test]
        async fn create_archive_should_embed_only_the_last_ledger_and_last_immutables_for_cardano_node_greater_or_equal_to_10_4_1()
         {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .with_legacy_ledger_snapshots(&[437, 537, 637, 737])
                .with_non_ledger_files(&["9not_included"])
                .with_volatile_files(&["blocks-0.dat", "blocks-1.dat", "blocks-2.dat"])
                .build();
            fs::create_dir(cardano_db.get_dir().join("whatever")).unwrap();

            let snapshotter = CompressedArchiveSnapshotter {
                cardano_node_version: CARDANO_NODE_VERSION_WITH_UTXO_HD_SUPPORT,
                ancillary_signer: Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    fake_keys::signable_manifest_signature()[0],
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            let snapshot = snapshotter.snapshot_ancillary(2, "ancillary").await.unwrap();

            let unpack_dir = snapshot.unpack_zstandard(&test_dir);
            assert_dir_eq!(
                &unpack_dir,
                // Only the last ledger files should be included
                format!(
                    "* {IMMUTABLE_DIR}/
                     ** 00003.chunk
                     ** 00003.primary
                     ** 00003.secondary
                     * {LEDGER_DIR}/
                     ** 737
                     * {}",
                    AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME
                )
            );
        }

        #[tokio::test]
        async fn create_archive_fail_if_manifest_signing_fail() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2])
                .with_legacy_ledger_snapshots(&[737])
                .build();

            let snapshotter = CompressedArchiveSnapshotter {
                ancillary_signer: Arc::new(MockAncillarySigner::that_fails_with_message(
                    "MockAncillarySigner failed",
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            let err = snapshotter
                .snapshot_ancillary(1, "ancillary")
                .await
                .expect_err("Must fail if manifest signing fails");
            assert!(
                err.to_string().contains("MockAncillarySigner failed"),
                "Expected error message to be raised by the mock ancillary signer, but got: '{err:?}'",
            );
        }

        #[tokio::test]
        async fn create_archive_of_legacy_ledger_snapshot_generate_sign_and_include_manifest_file()
        {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .with_legacy_ledger_snapshots(&[537, 637, 737])
                .with_non_immutables(&["not_to_include.txt"])
                .build();
            File::create(cardano_db.get_dir().join("not_to_include_as_well.txt")).unwrap();

            let snapshotter = CompressedArchiveSnapshotter {
                ancillary_signer: Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    fake_keys::signable_manifest_signature()[0],
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            let archive = snapshotter.snapshot_ancillary(2, "ancillary").await.unwrap();
            let unpacked = archive.unpack_zstandard(test_dir);
            let manifest_path = unpacked.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME);

            assert!(manifest_path.exists());

            let manifest = serde_json::from_reader::<_, AncillaryFilesManifest>(
                File::open(&manifest_path).unwrap(),
            )
            .unwrap();

            assert_eq!(
                vec![
                    PathBuf::from(IMMUTABLE_DIR).join("00003.chunk"),
                    PathBuf::from(IMMUTABLE_DIR).join("00003.primary"),
                    PathBuf::from(IMMUTABLE_DIR).join("00003.secondary"),
                    PathBuf::from(LEDGER_DIR).join("637"),
                    PathBuf::from(LEDGER_DIR).join("737"),
                ],
                manifest.files()
            );
            assert_eq!(
                Some(fake_keys::signable_manifest_signature()[0].try_into().unwrap()),
                manifest.signature()
            )
        }

        #[tokio::test]
        async fn create_archive_of_in_memory_ledger_snapshot_generate_sign_and_include_manifest_file()
         {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .with_in_memory_ledger_snapshots(&[537, 637, 737])
                .with_non_immutables(&["not_to_include.txt"])
                .build();
            File::create(cardano_db.get_dir().join("not_to_include_as_well.txt")).unwrap();

            let snapshotter = CompressedArchiveSnapshotter {
                ancillary_signer: Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    fake_keys::signable_manifest_signature()[0],
                )),
                ..snapshotter_for_test(
                    &test_dir,
                    cardano_db.get_dir(),
                    CompressionAlgorithm::Zstandard,
                )
            };

            let archive = snapshotter.snapshot_ancillary(2, "ancillary").await.unwrap();
            let unpacked = archive.unpack_zstandard(test_dir);
            let manifest_path = unpacked.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME);

            assert!(manifest_path.exists());

            let manifest = serde_json::from_reader::<_, AncillaryFilesManifest>(
                File::open(&manifest_path).unwrap(),
            )
            .unwrap();

            assert_eq!(
                vec![
                    PathBuf::from(IMMUTABLE_DIR).join("00003.chunk"),
                    PathBuf::from(IMMUTABLE_DIR).join("00003.primary"),
                    PathBuf::from(IMMUTABLE_DIR).join("00003.secondary"),
                    PathBuf::from(LEDGER_DIR)
                        .join("637")
                        .join(LedgerStateSnapshot::IN_MEMORY_META),
                    PathBuf::from(LEDGER_DIR)
                        .join("637")
                        .join(LedgerStateSnapshot::IN_MEMORY_STATE),
                    PathBuf::from(LEDGER_DIR)
                        .join("637")
                        .join(LedgerStateSnapshot::IN_MEMORY_TABLES)
                        .join(LedgerStateSnapshot::IN_MEMORY_TVAR),
                    PathBuf::from(LEDGER_DIR)
                        .join("737")
                        .join(LedgerStateSnapshot::IN_MEMORY_META),
                    PathBuf::from(LEDGER_DIR)
                        .join("737")
                        .join(LedgerStateSnapshot::IN_MEMORY_STATE),
                    PathBuf::from(LEDGER_DIR)
                        .join("737")
                        .join(LedgerStateSnapshot::IN_MEMORY_TABLES)
                        .join(LedgerStateSnapshot::IN_MEMORY_TVAR),
                ],
                manifest.files()
            );
            assert_eq!(
                Some(fake_keys::signable_manifest_signature()[0].try_into().unwrap()),
                manifest.signature()
            )
        }
    }

    mod compute_immutable_total_and_average_uncompressed_size {
        use mithril_common::current_function;

        use super::*;

        #[tokio::test]
        async fn should_compute_the_total_size_of_the_immutables() {
            let test_dir = temp_dir_create!();
            let immutable_trio_file_size = 777;

            let cardano_db = DummyCardanoDbBuilder::new(current_function!())
                .with_immutables(&[1, 2, 3])
                .set_immutable_trio_file_size(immutable_trio_file_size)
                .with_legacy_ledger_snapshots(&[737])
                .set_ledger_file_size(6666)
                .with_volatile_files(&["blocks-0.dat"])
                .set_volatile_file_size(99)
                .build();

            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );

            let sizes = snapshotter
                .compute_immutable_files_total_uncompressed_size(2)
                .await
                .unwrap();

            assert_eq!(immutable_trio_file_size * 2, sizes)
        }

        #[tokio::test]
        async fn should_return_an_error_when_compute_up_to_immutable_0() {
            let test_dir = temp_dir_create!();
            let cardano_db = DummyCardanoDbBuilder::new(current_function!()).build();

            let snapshotter = snapshotter_for_test(
                &test_dir,
                cardano_db.get_dir(),
                CompressionAlgorithm::Zstandard,
            );

            snapshotter
                .compute_immutable_files_total_uncompressed_size(0)
                .await
                .expect_err("Should return an error when no immutable file number");
        }
    }
}
