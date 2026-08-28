use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, error};

use mithril_common::{
    CardanoNetwork, StdResult,
    entities::{CardanoDbBeacon, CompressionAlgorithm, DigestLocation},
    logging::LoggerExtensions,
    messages::CardanoDatabaseDigestListItemMessage,
};
use mithril_file_archiver::{ArchiveParameters, FileArchive, FileArchiver, appender::AppenderFile};

use crate::{
    DumbUploader, FileUploader, ImmutableFileDigestMapper,
    file_uploaders::{CloudUploader, LocalUploader},
    tools::url_sanitizer::SanitizedUrlWithTrailingSlash,
};

/// The [DigestFileUploader] trait allows identifying uploaders that return locations for digest files.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DigestFileUploader: Send + Sync {
    /// Uploads the file at the given filepath and returns the location of the uploaded file.
    async fn upload(
        &self,
        filepath: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
    ) -> StdResult<DigestLocation>;
}

#[async_trait]
impl DigestFileUploader for DumbUploader {
    async fn upload(
        &self,
        filepath: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
    ) -> StdResult<DigestLocation> {
        let uri = FileUploader::upload(self, filepath).await?.into();

        Ok(DigestLocation::CloudStorage {
            uri,
            compression_algorithm,
        })
    }
}

#[async_trait]
impl DigestFileUploader for LocalUploader {
    async fn upload(
        &self,
        filepath: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
    ) -> StdResult<DigestLocation> {
        let uri = FileUploader::upload(self, filepath).await?.into();

        Ok(DigestLocation::CloudStorage {
            uri,
            compression_algorithm,
        })
    }
}

#[async_trait]
impl DigestFileUploader for CloudUploader {
    async fn upload(
        &self,
        filepath: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
    ) -> StdResult<DigestLocation> {
        let uri = FileUploader::upload(self, filepath).await?.into();

        Ok(DigestLocation::CloudStorage {
            uri,
            compression_algorithm,
        })
    }
}

#[derive(Debug)]
pub struct DigestUpload {
    pub locations: Vec<DigestLocation>,
    pub size: u64,
}

pub struct DigestSnapshotter {
    pub file_archiver: Arc<FileArchiver>,
    pub target_location: PathBuf,
    pub compression_algorithm: CompressionAlgorithm,
}

impl DigestSnapshotter {
    fn create_archive_file(
        &self,
        filename_without_extensions: &str,
        digest_file_path: &Path,
    ) -> StdResult<FileArchive> {
        let digests_archive = self
            .file_archiver
            .archive(
                ArchiveParameters {
                    archive_name_without_extension: filename_without_extensions.to_string(),
                    target_directory: self.target_location.clone(),
                    compression_algorithm: self.compression_algorithm,
                },
                AppenderFile::append_at_archive_root(digest_file_path.to_path_buf())?,
            )
            .with_context(|| {
                format!(
                    "Could not create snapshot of digest file: '{}'",
                    digest_file_path.display()
                )
            })?;

        Ok(digests_archive)
    }
}

pub struct DigestArtifactBuilder {
    /// Aggregator URL prefix
    aggregator_url_prefix: SanitizedUrlWithTrailingSlash,

    /// Uploaders
    uploaders: Vec<Arc<dyn DigestFileUploader>>,

    digest_snapshotter: DigestSnapshotter,

    network: CardanoNetwork,

    digests_dir: PathBuf,

    immutable_file_digest_mapper: Arc<dyn ImmutableFileDigestMapper>,

    logger: Logger,
}

impl DigestArtifactBuilder {
    /// Creates a new [DigestArtifactBuilder].
    pub fn new(
        aggregator_url_prefix: SanitizedUrlWithTrailingSlash,
        uploaders: Vec<Arc<dyn DigestFileUploader>>,
        digest_snapshotter: DigestSnapshotter,
        network: CardanoNetwork,
        digests_dir: PathBuf,
        immutable_file_digest_mapper: Arc<dyn ImmutableFileDigestMapper>,
        logger: Logger,
    ) -> StdResult<Self> {
        Ok(Self {
            aggregator_url_prefix,
            uploaders,
            digest_snapshotter,
            network,
            digests_dir,
            immutable_file_digest_mapper,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    pub async fn upload(&self, beacon: &CardanoDbBeacon) -> StdResult<DigestUpload> {
        let filename_without_extensions =
            Self::get_digests_file_name_without_extension(&self.network, beacon);
        let digest_path = self.create_digest_file(&filename_without_extensions).await?;
        let digest_archive = self
            .digest_snapshotter
            .create_archive_file(&filename_without_extensions, &digest_path)?;

        let locations = self.upload_digest_file(&digest_archive).await;

        self.cleanup_uploaded_artifacts(&digest_path, &digest_archive)?;

        Ok(DigestUpload {
            locations: locations?,
            size: digest_archive.get_uncompressed_size(),
        })
    }

    fn cleanup_uploaded_artifacts(
        &self,
        digest_path: &PathBuf,
        digest_archive: &FileArchive,
    ) -> StdResult<()> {
        fs::remove_file(digest_path).with_context(|| {
            format!("Could not remove digest file: '{}'", digest_path.display())
        })?;

        let digest_archive_path = digest_archive.get_file_path();
        if digest_archive_path.exists() {
            fs::remove_file(digest_archive_path).with_context(|| {
                format!(
                    "Could not remove digest archive file: '{}'",
                    digest_archive_path.display()
                )
            })?;
        }
        Ok(())
    }

    async fn create_digest_file(&self, filename_without_extensions: &str) -> StdResult<PathBuf> {
        let immutable_file_digest_map = self
            .immutable_file_digest_mapper
            .get_immutable_file_digest_map()
            .await?
            .into_iter()
            .map(
                |(immutable_file_name, digest)| CardanoDatabaseDigestListItemMessage {
                    immutable_file_name,
                    digest,
                },
            )
            .collect::<Vec<_>>();

        let digests_file_path =
            self.digests_dir.join(format!("{filename_without_extensions}.json"));

        if let Some(digests_dir) = digests_file_path.parent() {
            fs::create_dir_all(digests_dir).with_context(|| {
                format!(
                    "Can not create digests directory: '{}'",
                    digests_dir.display()
                )
            })?;
        }

        let digest_file = fs::File::create(digests_file_path.clone())?;
        serde_json::to_writer(digest_file, &immutable_file_digest_map)?;

        Ok(digests_file_path)
    }

    /// Uploads the digest file and returns the locations of the uploaded files.
    async fn upload_digest_file(
        &self,
        digest_archive: &FileArchive,
    ) -> StdResult<Vec<DigestLocation>> {
        let mut locations = Vec::<DigestLocation>::new();
        for uploader in &self.uploaders {
            let result = uploader
                .upload(
                    digest_archive.get_file_path(),
                    Some(digest_archive.get_compression_algorithm()),
                )
                .await;
            match result {
                Ok(location) => {
                    locations.push(location);
                }
                Err(e) => {
                    error!(
                        self.logger, "Failed to upload digest file";
                        "error" => ?e
                    );
                }
            }
        }

        locations.push(self.aggregator_digests_route_location()?);

        Ok(locations)
    }

    fn aggregator_digests_route_location(&self) -> StdResult<DigestLocation> {
        Ok(DigestLocation::Aggregator {
            uri: self
                .aggregator_url_prefix
                .join("artifact/cardano-database/digests")?
                .to_string(),
        })
    }

    fn get_digests_file_name_without_extension(
        network: &CardanoNetwork,
        beacon: &CardanoDbBeacon,
    ) -> String {
        format!(
            "{}-e{}-i{}.digests",
            network, *beacon.epoch, beacon.immutable_file_number
        )
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use std::{collections::BTreeMap, fs::read_to_string};

    use mithril_common::{
        current_function,
        entities::{CardanoDbBeacon, CompressionAlgorithm},
        messages::{CardanoDatabaseDigestListItemMessage, CardanoDatabaseDigestListMessage},
        test::{TempDir, assert_equivalent, double::Dummy},
    };
    use mithril_file_archiver::{FileArchiver, test::unpack_archive};

    use crate::{
        file_uploaders::FileUploadRetryPolicy,
        immutable_file_digest_mapper::MockImmutableFileDigestMapper, test::TestLogger,
    };

    use super::*;

    fn fake_uploader_returning_error() -> MockDigestFileUploader {
        let mut uploader = MockDigestFileUploader::new();
        uploader
            .expect_upload()
            .return_once(|_, _| Err(anyhow!("Failure while uploading...")));

        uploader
    }

    fn fake_uploader(
        location_uri: &str,
        compression_algorithm: Option<CompressionAlgorithm>,
    ) -> MockDigestFileUploader {
        let uri = location_uri.to_string();
        let mut uploader = MockDigestFileUploader::new();
        uploader.expect_upload().times(1).return_once(move |_, _| {
            Ok(DigestLocation::CloudStorage {
                uri,
                compression_algorithm,
            })
        });

        uploader
    }

    fn path_content(path: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|res| res.unwrap().path())
            .collect()
    }

    fn build_local_uploader(path: &Path) -> LocalUploader {
        std::fs::create_dir_all(path).unwrap();
        LocalUploader::new(
            SanitizedUrlWithTrailingSlash::parse("http://server/").unwrap(),
            path,
            FileUploadRetryPolicy::never(),
            TestLogger::stdout(),
        )
    }

    fn build_dummy_immutable_file_digest_mapper() -> MockImmutableFileDigestMapper {
        let mut immutable_file_digest_mapper = MockImmutableFileDigestMapper::new();
        immutable_file_digest_mapper
            .expect_get_immutable_file_digest_map()
            .returning(|| Ok(BTreeMap::new()));
        immutable_file_digest_mapper
    }

    fn file_archiver_for_test(work_dir: &Path) -> FileArchiver {
        FileArchiver::new_with_default_parameters(
            work_dir.join("verification"),
            TestLogger::stdout(),
        )
    }

    #[tokio::test]
    async fn digest_artifact_builder_return_digests_route_on_aggregator() {
        let temp_dir = TempDir::create("digest", current_function!());

        let mut immutable_file_digest_mapper = MockImmutableFileDigestMapper::new();
        immutable_file_digest_mapper
            .expect_get_immutable_file_digest_map()
            .returning(|| Ok(BTreeMap::new()));

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            temp_dir,
            Arc::new(immutable_file_digest_mapper),
            TestLogger::stdout(),
        )
        .unwrap();

        let upload_info = builder.upload(&CardanoDbBeacon::new(4, 123)).await.unwrap();
        assert_eq!(
            vec!(DigestLocation::Aggregator {
                uri: "https://aggregator/artifact/cardano-database/digests".to_string()
            }),
            upload_info.locations
        );
    }

    #[tokio::test]
    async fn digest_artifact_builder_return_size_of_digest_file() {
        let temp_dir = TempDir::create("digest", current_function!());

        let mut immutable_file_digest_mapper = MockImmutableFileDigestMapper::new();
        immutable_file_digest_mapper
            .expect_get_immutable_file_digest_map()
            .returning(|| Ok(BTreeMap::new()));

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            temp_dir,
            Arc::new(immutable_file_digest_mapper),
            TestLogger::stdout(),
        )
        .unwrap();

        let beacon = CardanoDbBeacon::new(4, 123);
        let upload_info = builder.upload(&beacon).await.unwrap();

        let digest_path = builder.create_digest_file("digests").await.unwrap();

        let expected_size = std::fs::metadata(digest_path).unwrap().len();
        assert!(expected_size > 0);
        assert_eq!(expected_size, upload_info.size);
    }

    #[tokio::test]
    async fn upload_digest_file_should_log_upload_errors() {
        let temp_dir = TempDir::create("digest", current_function!());
        let (logger, log_inspector) = TestLogger::memory();
        let mut uploader = MockDigestFileUploader::new();
        uploader
            .expect_upload()
            .return_once(|_, _| Err(anyhow!("Failure while uploading...")));

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![Arc::new(uploader)],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            PathBuf::from("/tmp/whatever"),
            Arc::new(MockImmutableFileDigestMapper::new()),
            logger,
        )
        .unwrap();

        let _ = builder.upload_digest_file(&FileArchive::dummy()).await;

        assert!(log_inspector.contains_log("Failure while uploading..."));
    }

    #[tokio::test]
    async fn upload_digest_file_should_not_error_even_if_no_location_returned_from_uploaders() {
        let temp_dir = TempDir::create("digest", current_function!());
        let uploader = fake_uploader_returning_error();

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![Arc::new(uploader)],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            PathBuf::from("/tmp/whatever"),
            Arc::new(MockImmutableFileDigestMapper::new()),
            TestLogger::stdout(),
        )
        .unwrap();

        let locations = builder.upload_digest_file(&FileArchive::dummy()).await.unwrap();

        assert!(!locations.is_empty());
    }

    #[tokio::test]
    async fn upload_digest_file_should_return_location_even_with_uploaders_errors() {
        let temp_dir = TempDir::create("digest", current_function!());
        let first_uploader = fake_uploader_returning_error();
        let second_uploader = fake_uploader("an_uri", Some(CompressionAlgorithm::Zstandard));
        let third_uploader = fake_uploader_returning_error();

        let uploaders: Vec<Arc<dyn DigestFileUploader>> = vec![
            Arc::new(first_uploader),
            Arc::new(second_uploader),
            Arc::new(third_uploader),
        ];

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            uploaders,
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            PathBuf::from("/tmp/whatever"),
            Arc::new(MockImmutableFileDigestMapper::new()),
            TestLogger::stdout(),
        )
        .unwrap();

        let locations = builder.upload_digest_file(&FileArchive::dummy()).await.unwrap();

        assert_equivalent!(
            locations,
            vec![
                DigestLocation::CloudStorage {
                    uri: "an_uri".to_string(),
                    compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                },
                DigestLocation::Aggregator {
                    uri: "https://aggregator/artifact/cardano-database/digests".to_string(),
                },
            ],
        );
    }

    #[tokio::test]
    async fn upload_digest_file_should_return_all_uploaders_returned_locations() {
        let temp_dir = TempDir::create("digest", current_function!());
        let first_uploader = fake_uploader("an_uri", Some(CompressionAlgorithm::Zstandard));
        let second_uploader = fake_uploader("another_uri", Some(CompressionAlgorithm::Zstandard));

        let uploaders: Vec<Arc<dyn DigestFileUploader>> =
            vec![Arc::new(first_uploader), Arc::new(second_uploader)];

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            uploaders,
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            PathBuf::from("/tmp/whatever"),
            Arc::new(MockImmutableFileDigestMapper::new()),
            TestLogger::stdout(),
        )
        .unwrap();

        let locations = builder.upload_digest_file(&FileArchive::dummy()).await.unwrap();

        assert_equivalent!(
            locations,
            vec![
                DigestLocation::CloudStorage {
                    uri: "an_uri".to_string(),
                    compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                },
                DigestLocation::CloudStorage {
                    uri: "another_uri".to_string(),
                    compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                },
                DigestLocation::Aggregator {
                    uri: "https://aggregator/artifact/cardano-database/digests".to_string(),
                },
            ],
        );
    }

    #[tokio::test]
    async fn create_digest_file_should_create_json_file_with_all_digests() {
        let temp_dir = TempDir::create("digest", current_function!());
        let mut immutable_file_digest_mapper = MockImmutableFileDigestMapper::new();
        immutable_file_digest_mapper
            .expect_get_immutable_file_digest_map()
            .returning(|| {
                Ok(BTreeMap::from([(
                    "06685.chunk".to_string(),
                    "0af556ab2620dd9363bf76963a231abe8948a500ea6be31b131d87907ab09b1e".to_string(),
                )]))
            });

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&temp_dir)),
                target_location: temp_dir.clone(),
                compression_algorithm: CompressionAlgorithm::Zstandard,
            },
            CardanoNetwork::TestNet(123),
            temp_dir,
            Arc::new(immutable_file_digest_mapper),
            TestLogger::stdout(),
        )
        .unwrap();

        let digest_file = builder.create_digest_file("digests").await.unwrap();

        let file_content = read_to_string(digest_file).unwrap();
        let digest_content: CardanoDatabaseDigestListMessage =
            serde_json::from_str(&file_content).unwrap();

        assert_eq!(
            digest_content,
            vec![CardanoDatabaseDigestListItemMessage {
                immutable_file_name: "06685.chunk".to_string(),
                digest: "0af556ab2620dd9363bf76963a231abe8948a500ea6be31b131d87907ab09b1e"
                    .to_string(),
            }]
        );
    }

    #[tokio::test]
    async fn upload_should_upload_a_digest_archive_file_and_delete_created_files() {
        let tmp_dir = TempDir::create("digest", current_function!());
        let digests_dir = tmp_dir.join("digest");
        let digests_archive_dir = tmp_dir.join("archive");
        let uploader_path = tmp_dir.join("uploaded_digests");

        let compression_algorithm = CompressionAlgorithm::Zstandard;
        let beacon = CardanoDbBeacon::new(3, 456);
        let network = CardanoNetwork::TestNet(24);

        let builder = DigestArtifactBuilder::new(
            SanitizedUrlWithTrailingSlash::parse("https://aggregator/").unwrap(),
            vec![Arc::new(build_local_uploader(&uploader_path))],
            DigestSnapshotter {
                file_archiver: Arc::new(file_archiver_for_test(&tmp_dir)),
                target_location: digests_archive_dir.clone(),
                compression_algorithm,
            },
            network,
            digests_dir.clone(),
            Arc::new(build_dummy_immutable_file_digest_mapper()),
            TestLogger::stdout(),
        )
        .unwrap();

        let _locations = builder.upload(&beacon).await.unwrap();

        // Check uploader archive contains digests.json
        {
            let file_name_without_extension =
                DigestArtifactBuilder::get_digests_file_name_without_extension(&network, &beacon);
            let digest_archive_path = uploader_path.join(format!(
                "{file_name_without_extension}.{}",
                compression_algorithm.tar_file_extension(),
            ));
            assert!(
                digest_archive_path.exists(),
                "Archive should have been uploaded to {}",
                digest_archive_path.display()
            );

            let unpack_dir = tmp_dir.join("unpack");
            unpack_archive(&digest_archive_path, &unpack_dir).unwrap();

            let digest_file_path = unpack_dir.join(format!("{file_name_without_extension}.json"));
            assert!(digest_file_path.is_file());
        }

        // Check that all files have been deleted
        {
            let remaining_files = path_content(&digests_dir);
            assert!(
                remaining_files.is_empty(),
                "There should be no remaining files in digests folder, but found: {remaining_files:?}"
            );

            let remaining_files = path_content(&digests_archive_dir);
            assert!(
                remaining_files.is_empty(),
                "There should be no remaining files in archive folder, but found: {remaining_files:?}"
            );
        }
    }

    #[tokio::test]
    async fn get_digest_file_name_include_beacon_information() {
        let beacon = CardanoDbBeacon::new(5, 456);
        let network = CardanoNetwork::MainNet;
        let digest_name =
            DigestArtifactBuilder::get_digests_file_name_without_extension(&network, &beacon);

        assert_eq!(digest_name, "mainnet-e5-i456.digests");
    }
}
