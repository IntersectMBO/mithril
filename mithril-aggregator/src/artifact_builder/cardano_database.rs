use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use semver::Version;

use mithril_common::{
    CardanoNetwork, StdResult,
    entities::{
        AncillaryLocations, CardanoDatabaseSnapshot, CardanoDatabaseSnapshotArtifactData,
        CardanoDbBeacon, Certificate, DigestsLocations, ImmutablesLocations,
        ProtocolMessagePartKey, SignedEntityType,
    },
};

use crate::artifact_builder::{AncillaryArtifactBuilder, ArtifactBuilder};

use super::{DigestArtifactBuilder, ImmutableArtifactBuilder};

pub struct CardanoDatabaseArtifactBuilder {
    network: CardanoNetwork,
    cardano_node_version: Version,
    ancillary_builder: Arc<AncillaryArtifactBuilder>,
    immutable_builder: Arc<ImmutableArtifactBuilder>,
    digest_builder: Arc<DigestArtifactBuilder>,
}

impl CardanoDatabaseArtifactBuilder {
    pub fn new(
        network: CardanoNetwork,
        cardano_node_version: &Version,
        ancillary_builder: Arc<AncillaryArtifactBuilder>,
        immutable_builder: Arc<ImmutableArtifactBuilder>,
        digest_builder: Arc<DigestArtifactBuilder>,
    ) -> Self {
        Self {
            network,
            cardano_node_version: cardano_node_version.clone(),
            ancillary_builder,
            immutable_builder,
            digest_builder,
        }
    }
}

#[async_trait]
impl ArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot> for CardanoDatabaseArtifactBuilder {
    async fn compute_artifact(
        &self,
        beacon: CardanoDbBeacon,
        certificate: &Certificate,
    ) -> StdResult<CardanoDatabaseSnapshot> {
        let merkle_root = certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::CardanoDatabaseMerkleRoot)
            .with_context(
                || "Can not find CardanoDatabaseMerkleRoot protocol message part in certificate",
            )
            .with_context(|| {
                format!(
                    "Can not compute CardanoDatabase artifact for signed_entity: {:?}",
                    SignedEntityType::CardanoDatabase(beacon.clone())
                )
            })?;

        let ancillary_upload = self.ancillary_builder.upload(&beacon).await?;
        let immutables_upload = self.immutable_builder.upload(beacon.immutable_file_number).await?;
        let digest_upload = self.digest_builder.upload(&beacon).await?;

        let content = CardanoDatabaseSnapshotArtifactData {
            total_db_size_uncompressed: ancillary_upload.size + immutables_upload.total_size,
            digests: DigestsLocations {
                size_uncompressed: digest_upload.size,
                locations: digest_upload.locations,
            },
            immutables: ImmutablesLocations {
                average_size_uncompressed: immutables_upload.average_size,
                locations: immutables_upload.locations,
            },
            ancillary: AncillaryLocations {
                size_uncompressed: ancillary_upload.size,
                locations: ancillary_upload.locations,
            },
        };

        let cardano_database = CardanoDatabaseSnapshot::new(
            merkle_root.to_string(),
            self.network,
            beacon,
            content,
            &self.cardano_node_version,
        );

        Ok(cardano_database)
    }
}

#[cfg(test)]
mod tests {
    use mockall::{Predicate, predicate};
    use std::path::Path;
    use std::{collections::BTreeMap, path::PathBuf};

    use mithril_cardano_node_internal_database::entities::AncillaryFilesManifest;
    use mithril_cardano_node_internal_database::test::DummyCardanoDbBuilder;
    use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, LEDGER_DIR, immutable_trio_names};

    use mithril_common::{
        CardanoNetwork,
        entities::{
            AncillaryLocation, CompressionAlgorithm, DigestLocation, ImmutableFileNumber,
            ImmutablesLocation, MultiFilesUri, ProtocolMessage, ProtocolMessagePartKey,
            TemplateUri,
        },
        test::{
            TempDir,
            double::{fake_data, fake_keys},
        },
    };

    use crate::{
        artifact_builder::{
            DigestSnapshotter, MockAncillaryFileUploader, MockImmutableFilesUploader,
        },
        immutable_file_digest_mapper::MockImmutableFileDigestMapper,
        services::CompressedArchiveSnapshotter,
        services::ancillary_signer::MockAncillarySigner,
        test::TestLogger,
        tools::{file_archiver::FileArchiver, url_sanitizer::SanitizedUrlWithTrailingSlash},
    };

    use super::*;

    const DUMMY_CARDANO_NODE_VERSION: Version = Version::new(1, 2, 3);

    fn get_test_directory(dir_name: &str) -> PathBuf {
        TempDir::create("cardano_database", dir_name)
    }

    async fn get_expected_manifest_size(
        cardano_db_dir: &Path,
        ancillary_immutable_file_number: ImmutableFileNumber,
        ancillary_ledger_file_name: &str,
        ancillary_manifest_signature: &str,
    ) -> u64 {
        let mut manifest_dummy = AncillaryFilesManifest::from_paths(
            cardano_db_dir,
            [
                immutable_trio_names(ancillary_immutable_file_number)
                    .into_iter()
                    .map(|filename| PathBuf::from(IMMUTABLE_DIR).join(filename))
                    .collect(),
                vec![PathBuf::from(LEDGER_DIR).join(ancillary_ledger_file_name)],
            ]
            .concat(),
        )
        .await
        .unwrap();
        manifest_dummy.set_signature(ancillary_manifest_signature.try_into().unwrap());

        serde_json::to_string(&manifest_dummy).unwrap().len() as u64
    }

    #[tokio::test]
    async fn should_compute_valid_artifact() {
        let test_dir = get_test_directory("should_compute_valid_artifact");

        let beacon = CardanoDbBeacon::new(123, 3);
        let network = CardanoNetwork::TestNet(123);
        let immutable_trio_file_size = 777;
        let ledger_file_size = 6666;
        let volatile_file_size = 99;
        let cardano_db = DummyCardanoDbBuilder::new("cdb-should_compute_valid_artifact")
            .with_immutables(&[0, 1, 2, 3])
            .append_immutable_trio()
            .set_immutable_trio_file_size(immutable_trio_file_size)
            .with_legacy_ledger_snapshots(&[437])
            .set_ledger_file_size(ledger_file_size)
            .with_volatile_files(&["blocks-0.dat"])
            .set_volatile_file_size(volatile_file_size)
            .build();

        let ancillary_manifest_signature = fake_keys::signable_manifest_signature()[0];

        // The ancillary archive also contains a signed manifest file whose size IS INCLUDED in
        // the total size and ancillary artifact size
        let manifest_size = get_expected_manifest_size(
            cardano_db.get_dir(),
            4,
            "437",
            ancillary_manifest_signature,
        )
        .await;
        let expected_average_immutable_size = immutable_trio_file_size;
        let expected_ancillary_size = immutable_trio_file_size + ledger_file_size;
        let expected_total_size = 4 * immutable_trio_file_size + ledger_file_size + manifest_size;

        let snapshotter = Arc::new(
            CompressedArchiveSnapshotter::new(
                DUMMY_CARDANO_NODE_VERSION,
                cardano_db.get_dir().to_path_buf(),
                test_dir.join("ongoing_snapshots"),
                CompressionAlgorithm::Zstandard,
                Arc::new(FileArchiver::new_for_test(test_dir.join("verification"))),
                Arc::new(MockAncillarySigner::that_succeeds_with_signature(
                    ancillary_manifest_signature,
                )),
                TestLogger::stdout(),
            )
            .unwrap(),
        );

        let ancillary_artifact_builder = {
            let mut ancillary_uploader = MockAncillaryFileUploader::new();
            ancillary_uploader.expect_upload().return_once(|_, _| {
                Ok(AncillaryLocation::CloudStorage {
                    uri: "ancillary_uri".to_string(),
                    compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                })
            });

            AncillaryArtifactBuilder::new(
                vec![Arc::new(ancillary_uploader)],
                snapshotter.clone(),
                network,
                TestLogger::stdout(),
            )
            .unwrap()
        };

        fn predicate_length(length: u64) -> impl Predicate<[PathBuf]> {
            predicate::function(move |p: &[_]| p.len() == length as usize)
        }

        let immutable_artifact_builder = {
            // We upload the immutable files in the [0,beacon.immutable_file_number] range
            let number_of_immutable_file_loaded = beacon.immutable_file_number + 1;
            let mut immutable_uploader = MockImmutableFilesUploader::new();
            immutable_uploader
                .expect_batch_upload()
                .with(
                    predicate_length(number_of_immutable_file_loaded),
                    predicate::eq(Some(CompressionAlgorithm::Zstandard)),
                )
                .return_once(|_, _| {
                    Ok(ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "immutable_template_uri".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    })
                });

            ImmutableArtifactBuilder::new(
                cardano_db.get_immutable_dir().to_path_buf(),
                vec![Arc::new(immutable_uploader)],
                snapshotter,
                TestLogger::stdout(),
            )
            .unwrap()
        };

        let digest_artifact_builder = {
            let mut immutable_file_digest_mapper = MockImmutableFileDigestMapper::new();

            immutable_file_digest_mapper
                .expect_get_immutable_file_digest_map()
                .returning(|| Ok(BTreeMap::new()));

            DigestArtifactBuilder::new(
                SanitizedUrlWithTrailingSlash::parse("http://aggregator_uri").unwrap(),
                vec![],
                DigestSnapshotter {
                    file_archiver: Arc::new(FileArchiver::new_for_test(
                        test_dir.join("verification"),
                    )),
                    target_location: test_dir.clone(),
                    compression_algorithm: CompressionAlgorithm::Zstandard,
                },
                network,
                test_dir.join("digests"),
                Arc::new(immutable_file_digest_mapper),
                TestLogger::stdout(),
            )
            .unwrap()
        };

        let cardano_database_artifact_builder = CardanoDatabaseArtifactBuilder::new(
            network,
            &Version::parse("1.0.0").unwrap(),
            Arc::new(ancillary_artifact_builder),
            Arc::new(immutable_artifact_builder),
            Arc::new(digest_artifact_builder),
        );

        let certificate_with_merkle_root = {
            let mut protocol_message = ProtocolMessage::new();
            protocol_message.set_message_part(
                ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
                "merkleroot".to_string(),
            );
            Certificate {
                protocol_message,
                ..fake_data::certificate("certificate-123".to_string())
            }
        };

        let artifact = cardano_database_artifact_builder
            .compute_artifact(beacon.clone(), &certificate_with_merkle_root)
            .await
            .unwrap();

        let expected_ancillary_locations = vec![AncillaryLocation::CloudStorage {
            uri: "ancillary_uri".to_string(),
            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
        }];

        let expected_immutables_locations = vec![ImmutablesLocation::CloudStorage {
            uri: MultiFilesUri::Template(TemplateUri("immutable_template_uri".to_string())),
            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
        }];

        let expected_digest_locations = vec![DigestLocation::Aggregator {
            uri: "http://aggregator_uri/artifact/cardano-database/digests".to_string(),
        }];

        let artifact_expected = CardanoDatabaseSnapshot::new(
            "merkleroot".to_string(),
            network,
            beacon,
            CardanoDatabaseSnapshotArtifactData {
                total_db_size_uncompressed: expected_total_size,
                digests: DigestsLocations {
                    size_uncompressed: artifact.digests.size_uncompressed,
                    locations: expected_digest_locations,
                },
                immutables: ImmutablesLocations {
                    average_size_uncompressed: expected_average_immutable_size,
                    locations: expected_immutables_locations,
                },
                ancillary: AncillaryLocations {
                    size_uncompressed: expected_ancillary_size + manifest_size,
                    locations: expected_ancillary_locations,
                },
            },
            &Version::parse("1.0.0").unwrap(),
        );

        assert!(artifact.digests.size_uncompressed > 0);
        assert_eq!(artifact_expected, artifact);
    }
}
