use std::{
    collections::BTreeMap,
    fmt, fs,
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use slog::warn;
use thiserror::Error;

use mithril_cardano_node_internal_database::{
    IMMUTABLE_DIR,
    digesters::{CardanoImmutableDigester, ImmutableDigester, ImmutableDigesterError},
    entities::ImmutableFile,
};
use mithril_common::{
    crypto_helper::{MKProof, MKTree, MKTreeNode, MKTreeStoreInMemory},
    entities::{
        DigestLocation, HexEncodedDigest, ImmutableFileName, ImmutableFileNumber,
        ProtocolMessagePartKey,
    },
    messages::{
        CardanoDatabaseDigestListItemMessage, CardanoDatabaseSnapshotMessage, CertificateMessage,
        DigestsMessagePart,
    },
};

use crate::{
    MithrilError, MithrilResult,
    cardano_database_client::ImmutableFileRange,
    feedback::MithrilEvent,
    file_downloader::{DownloadEvent, FileDownloader, FileDownloaderUri},
    utils::{
        TempDirectoryProvider, create_directory_if_not_exists, delete_directory,
        read_files_in_directory,
    },
};

/// Represents the verified digests and the Merkle tree built from them.
pub struct VerifiedDigests {
    /// A map of immutable file names to their corresponding verified digests.
    pub digests: BTreeMap<ImmutableFileName, HexEncodedDigest>,
    /// The Merkle tree built from the digests.
    pub merkle_tree: MKTree<MKTreeStoreInMemory>,
}

const MERKLE_PROOF_COMPUTATION_ERROR: &str = "Merkle proof computation failed";

/// Type containing the lists of immutable files that are missing or tampered.
#[derive(Debug, PartialEq)]
pub struct ImmutableVerificationResult {
    /// The immutables files directory.
    pub immutables_dir: PathBuf,
    /// List of missing immutable files.
    pub missing: Vec<ImmutableFileName>,
    /// List of tampered immutable files.
    pub tampered: Vec<ImmutableFileName>,
    /// List of non-verifiable immutable files.
    pub non_verifiable: Vec<ImmutableFileName>,
}

/// Cardano database Verification related errors.
#[derive(Error, Debug)]
pub enum CardanoDatabaseVerificationError {
    /// Error related to the verification of immutable files.
    ImmutableFilesVerification(ImmutableVerificationResult),

    /// Error related to the immutable files digests computation.
    DigestsComputation(#[from] ImmutableDigesterError),

    /// Error related to the Merkle proof verification.
    MerkleProofVerification(#[source] MithrilError),

    /// Error related to the immutable files range.
    ImmutableFilesRangeCreation(#[source] MithrilError),
}

impl fmt::Display for CardanoDatabaseVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardanoDatabaseVerificationError::ImmutableFilesVerification(lists) => {
                fn get_first_10_files_path(
                    files: &[ImmutableFileName],
                    immutables_dir: &Path,
                ) -> String {
                    files
                        .iter()
                        .take(10)
                        .map(|file| immutables_dir.join(file).to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                }

                if !lists.missing.is_empty() {
                    let missing_files_subset =
                        get_first_10_files_path(&lists.missing, &lists.immutables_dir);
                    writeln!(
                        f,
                        "Number of missing immutable files: {}",
                        lists.missing.len()
                    )?;
                    writeln!(f, "First 10 missing immutable files paths:")?;
                    writeln!(f, "{missing_files_subset}")?;
                }
                if !lists.missing.is_empty() && !lists.tampered.is_empty() {
                    writeln!(f)?;
                }
                if !lists.tampered.is_empty() {
                    let tampered_files_subset =
                        get_first_10_files_path(&lists.tampered, &lists.immutables_dir);
                    writeln!(
                        f,
                        "Number of tampered immutable files: {}",
                        lists.tampered.len()
                    )?;
                    writeln!(f, "First 10 tampered immutable files paths:")?;
                    writeln!(f, "{tampered_files_subset}")?;
                }
                if (!lists.missing.is_empty() || !lists.tampered.is_empty())
                    && !lists.non_verifiable.is_empty()
                {
                    writeln!(f)?;
                }
                if !lists.non_verifiable.is_empty() {
                    let non_verifiable_files_subset =
                        get_first_10_files_path(&lists.non_verifiable, &lists.immutables_dir);
                    writeln!(
                        f,
                        "Number of non verifiable immutable files: {}",
                        lists.non_verifiable.len()
                    )?;
                    writeln!(f, "First 10 non verifiable immutable files paths:")?;
                    writeln!(f, "{non_verifiable_files_subset}")?;
                }
                Ok(())
            }
            CardanoDatabaseVerificationError::DigestsComputation(e) => {
                write!(f, "Immutable files digester error: {e:?}")
            }
            CardanoDatabaseVerificationError::MerkleProofVerification(e) => {
                write!(f, "Merkle proof verification error: {e:?}")
            }
            CardanoDatabaseVerificationError::ImmutableFilesRangeCreation(e) => {
                write!(f, "Immutable files range error: {e:?}")
            }
        }
    }
}

/// Represents the immutable files that were not verified during the digest verification process.
#[derive(PartialEq, Debug)]
pub(crate) struct ImmutableFilesNotVerified {
    /// List of immutable files that were tampered (i.e. their digest does not match the verified digest)
    pub tampered_files: Vec<ImmutableFileName>,
    /// List of immutable files that could not be verified (i.e., not present in the digests)
    pub non_verifiable_files: Vec<ImmutableFileName>,
}

impl VerifiedDigests {
    pub(crate) fn list_immutable_files_not_verified(
        &self,
        computed_digests: &BTreeMap<ImmutableFile, HexEncodedDigest>,
    ) -> ImmutableFilesNotVerified {
        let mut tampered_files = vec![];
        let mut non_verifiable_files = vec![];

        for (immutable_file, digest) in computed_digests.iter() {
            let immutable_file_name_to_verify = immutable_file.filename.clone();
            match self.digests.get(&immutable_file_name_to_verify) {
                Some(verified_digest) if verified_digest != digest => {
                    tampered_files.push(immutable_file_name_to_verify);
                }
                None => {
                    non_verifiable_files.push(immutable_file_name_to_verify);
                }
                _ => {}
            }
        }

        ImmutableFilesNotVerified {
            tampered_files,
            non_verifiable_files,
        }
    }
}

pub struct InternalArtifactProver {
    http_file_downloader: Arc<dyn FileDownloader>,
    temp_directory_provider: Arc<dyn TempDirectoryProvider>,
    logger: slog::Logger,
}

impl InternalArtifactProver {
    /// Constructs a new `InternalArtifactProver`.
    pub fn new(
        http_file_downloader: Arc<dyn FileDownloader>,
        temp_directory_provider: Arc<dyn TempDirectoryProvider>,
        logger: slog::Logger,
    ) -> Self {
        Self {
            http_file_downloader,
            temp_directory_provider,
            logger,
        }
    }

    fn check_merkle_root_is_signed_by_certificate(
        certificate: &CertificateMessage,
        merkle_root: &MKTreeNode,
    ) -> MithrilResult<()> {
        let mut message = certificate.protocol_message.clone();
        message.set_message_part(
            ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
            merkle_root.to_hex(),
        );

        if !certificate.match_message(&message) {
            return Err(anyhow!(
                "Certificate message does not match the computed message for certificate {}",
                certificate.hash
            ));
        }

        Ok(())
    }

    /// Download digests and verify its authenticity against the certificate.
    pub async fn download_and_verify_digests(
        &self,
        certificate: &CertificateMessage,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
    ) -> MithrilResult<VerifiedDigests> {
        let digest_target_dir = self.digest_target_dir();
        delete_directory(&digest_target_dir)?;
        self.download_unpack_digest_file(&cardano_database_snapshot.digests, &digest_target_dir)
            .await?;
        let last_immutable_file_number = cardano_database_snapshot.beacon.immutable_file_number;

        let downloaded_digests = self.read_digest_file(&digest_target_dir)?;
        delete_directory(&digest_target_dir)?;

        let filtered_digests = downloaded_digests
            .clone()
            .into_iter()
            .filter(|(immutable_file_name, _)| {
                match ImmutableFile::new(Path::new(immutable_file_name).to_path_buf()) {
                    Ok(immutable_file) => immutable_file.number <= last_immutable_file_number,
                    Err(_) => false,
                }
            })
            .collect::<BTreeMap<_, _>>();

        let filtered_digests_values = filtered_digests.values().collect::<Vec<_>>();
        let merkle_tree: MKTree<MKTreeStoreInMemory> = MKTree::new(&filtered_digests_values)?;

        Self::check_merkle_root_is_signed_by_certificate(
            certificate,
            &merkle_tree.compute_root()?,
        )?;

        Ok(VerifiedDigests {
            digests: filtered_digests,
            merkle_tree,
        })
    }

    fn immutable_dir(db_dir: &Path) -> PathBuf {
        db_dir.join(IMMUTABLE_DIR)
    }

    fn list_missing_immutable_files(
        database_dir: &Path,
        immutable_file_number_range: &RangeInclusive<ImmutableFileNumber>,
    ) -> Vec<ImmutableFileName> {
        let immutable_dir = Self::immutable_dir(database_dir);
        let mut missing_files = Vec::new();

        for immutable_file_number in immutable_file_number_range.clone() {
            for immutable_type in ["chunk", "primary", "secondary"] {
                let file_name = format!("{immutable_file_number:05}.{immutable_type}");
                if !immutable_dir.join(&file_name).exists() {
                    missing_files.push(ImmutableFileName::from(file_name));
                }
            }
        }

        missing_files
    }

    pub async fn verify_cardano_database(
        &self,
        _certificate: &CertificateMessage,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
        immutable_file_range: &ImmutableFileRange,
        allow_missing: bool,
        database_dir: &Path,
        verified_digests: &VerifiedDigests,
    ) -> Result<MKProof, CardanoDatabaseVerificationError> {
        let immutable_file_number_range = immutable_file_range
            .to_range_inclusive(cardano_database_snapshot.beacon.immutable_file_number)
            .map_err(CardanoDatabaseVerificationError::ImmutableFilesRangeCreation)?;
        let missing_immutable_files = if allow_missing {
            vec![]
        } else {
            Self::list_missing_immutable_files(database_dir, &immutable_file_number_range)
        };
        let immutable_digester = CardanoImmutableDigester::new(None, self.logger.clone());
        let computed_digest_entries = immutable_digester
            .compute_digests_for_range(database_dir, &immutable_file_number_range)
            .await?
            .entries;
        let computed_digests = computed_digest_entries
            .values()
            .map(MKTreeNode::from)
            .collect::<Vec<_>>();

        let proof_result = verified_digests.merkle_tree.compute_proof(&computed_digests);
        if let Ok(ref merkle_proof) = proof_result
            && missing_immutable_files.is_empty()
        {
            merkle_proof
                .verify()
                .map_err(CardanoDatabaseVerificationError::MerkleProofVerification)?;

            return Ok(merkle_proof.clone());
        }

        let (tampered, non_verifiable) = match proof_result {
            Err(e) => {
                warn!(self.logger, "{MERKLE_PROOF_COMPUTATION_ERROR}: {e:}");
                let verified_digests =
                    verified_digests.list_immutable_files_not_verified(&computed_digest_entries);

                (
                    verified_digests.tampered_files,
                    verified_digests.non_verifiable_files,
                )
            }
            Ok(_) => (vec![], vec![]),
        };
        Err(
            CardanoDatabaseVerificationError::ImmutableFilesVerification(
                ImmutableVerificationResult {
                    immutables_dir: Self::immutable_dir(database_dir),
                    missing: missing_immutable_files,
                    tampered,
                    non_verifiable,
                },
            ),
        )
    }

    async fn download_unpack_digest_file(
        &self,
        digests_locations: &DigestsMessagePart,
        digests_file_target_dir: &Path,
    ) -> MithrilResult<()> {
        create_directory_if_not_exists(digests_file_target_dir)?;
        let mut locations_sorted = digests_locations.sanitized_locations()?;
        locations_sorted.sort();
        for location in locations_sorted {
            let download_id = MithrilEvent::new_cardano_database_download_id();
            let (file_downloader, compression_algorithm) = match &location {
                DigestLocation::CloudStorage {
                    uri: _,
                    compression_algorithm,
                } => (self.http_file_downloader.clone(), *compression_algorithm),
                DigestLocation::Aggregator { .. } => (self.http_file_downloader.clone(), None),
                // Note: unknown locations should have been filtered out by `sanitized_locations`
                DigestLocation::Unknown => unreachable!(),
            };
            let file_downloader_uri: FileDownloaderUri = location.try_into()?;
            let downloaded = file_downloader
                .download_unpack(
                    &file_downloader_uri,
                    digests_locations.size_uncompressed,
                    digests_file_target_dir,
                    compression_algorithm,
                    DownloadEvent::Digest {
                        download_id: download_id.clone(),
                    },
                )
                .await;
            match downloaded {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    slog::error!(
                        self.logger,
                        "Failed downloading and unpacking digest for location {file_downloader_uri:?}"; "error" => ?e
                    );
                }
            }
        }

        Err(anyhow!(
            "Failed downloading and unpacking digests for all locations"
        ))
    }

    fn read_digest_file(
        &self,
        digest_file_target_dir: &Path,
    ) -> MithrilResult<BTreeMap<ImmutableFileName, HexEncodedDigest>> {
        let digest_files = read_files_in_directory(digest_file_target_dir)?;
        if digest_files.len() > 1 {
            return Err(anyhow!(
                "Multiple digest files found in directory: {digest_file_target_dir:?}"
            ));
        }
        if digest_files.is_empty() {
            return Err(anyhow!(
                "No digest file found in directory: {digest_file_target_dir:?}"
            ));
        }

        let digest_file = &digest_files[0];
        let content = fs::read_to_string(digest_file)
            .with_context(|| format!("Failed reading digest file: {digest_file:?}"))?;
        let digest_messages: Vec<CardanoDatabaseDigestListItemMessage> =
            serde_json::from_str(&content)
                .with_context(|| format!("Failed deserializing digest file: {digest_file:?}"))?;
        let digest_map = digest_messages
            .into_iter()
            .map(|message| (message.immutable_file_name, message.digest))
            .collect::<BTreeMap<_, _>>();

        Ok(digest_map)
    }

    fn digest_target_dir(&self) -> PathBuf {
        self.temp_directory_provider.temp_dir()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::sync::Arc;

    use mithril_common::{
        current_function,
        entities::{CardanoDbBeacon, Epoch, HexEncodedDigest},
        messages::CardanoDatabaseDigestListItemMessage,
        test::TempDir,
    };

    use crate::{
        cardano_database_client::CardanoDatabaseClientDependencyInjector, common::test::Dummy,
        file_downloader::MockFileDownloaderBuilder, test_utils::TestLogger,
        utils::TimestampTempDirectoryProvider,
    };

    use super::*;

    fn remove_immutable_files<T: AsRef<Path>>(database_dir: &Path, immutable_file_names: &[T]) {
        for immutable_file_name in immutable_file_names {
            let immutable_file_path = InternalArtifactProver::immutable_dir(database_dir)
                .join(immutable_file_name.as_ref());
            std::fs::remove_file(immutable_file_path).unwrap();
        }
    }

    fn tamper_immutable_files<T: AsRef<Path>>(database_dir: &Path, immutable_file_names: &[T]) {
        for immutable_file_name in immutable_file_names {
            let immutable_file_path = InternalArtifactProver::immutable_dir(database_dir)
                .join(immutable_file_name.as_ref());
            std::fs::write(immutable_file_path, "tampered content").unwrap();
        }
    }

    mod list_immutable_files_not_verified {

        use super::*;

        fn fake_immutable(filename: &str) -> ImmutableFile {
            ImmutableFile {
                path: PathBuf::from("whatever"),
                number: 1,
                filename: filename.to_string(),
            }
        }

        #[test]
        fn should_return_empty_list_when_no_tampered_files() {
            let digests_to_verify = BTreeMap::from([
                (fake_immutable("00001.chunk"), "digest-1".to_string()),
                (fake_immutable("00002.chunk"), "digest-2".to_string()),
            ]);

            let verified_digests = VerifiedDigests {
                digests: BTreeMap::from([
                    ("00001.chunk".to_string(), "digest-1".to_string()),
                    ("00002.chunk".to_string(), "digest-2".to_string()),
                ]),
                merkle_tree: MKTree::new(&["whatever"]).unwrap(),
            };

            let invalid_files =
                verified_digests.list_immutable_files_not_verified(&digests_to_verify);

            assert_eq!(
                invalid_files,
                ImmutableFilesNotVerified {
                    tampered_files: vec![],
                    non_verifiable_files: vec![],
                }
            );
        }

        #[test]
        fn should_return_list_with_tampered_files() {
            let digests_to_verify = BTreeMap::from([
                (fake_immutable("00001.chunk"), "digest-1".to_string()),
                (fake_immutable("00002.chunk"), "digest-2".to_string()),
            ]);

            let verified_digests = VerifiedDigests {
                digests: BTreeMap::from([
                    ("00001.chunk".to_string(), "digest-1".to_string()),
                    ("00002.chunk".to_string(), "INVALID".to_string()),
                ]),
                merkle_tree: MKTree::new(&["whatever"]).unwrap(),
            };

            let invalid_files =
                verified_digests.list_immutable_files_not_verified(&digests_to_verify);

            assert_eq!(
                invalid_files,
                ImmutableFilesNotVerified {
                    tampered_files: vec!["00002.chunk".to_string()],
                    non_verifiable_files: vec![],
                }
            );
        }

        #[test]
        fn should_return_list_with_non_verifiable() {
            let digests_to_verify = BTreeMap::from([
                (fake_immutable("00001.chunk"), "digest-1".to_string()),
                (
                    fake_immutable("00002.not.verifiable"),
                    "digest-2".to_string(),
                ),
            ]);

            let verified_digests = VerifiedDigests {
                digests: BTreeMap::from([("00001.chunk".to_string(), "digest-1".to_string())]),
                merkle_tree: MKTree::new(&["whatever"]).unwrap(),
            };

            let invalid_files =
                verified_digests.list_immutable_files_not_verified(&digests_to_verify);

            assert_eq!(
                invalid_files,
                ImmutableFilesNotVerified {
                    tampered_files: vec![],
                    non_verifiable_files: vec!["00002.not.verifiable".to_string()],
                }
            );
        }
    }

    mod download_and_verify_digests {
        use mithril_common::{
            StdResult, current_function,
            entities::{ProtocolMessage, ProtocolMessagePartKey},
            messages::DigestsMessagePart,
        };

        use crate::utils::TimestampTempDirectoryProvider;

        use super::*;

        fn write_digest_file(
            digest_dir: &Path,
            digests: &BTreeMap<ImmutableFile, HexEncodedDigest>,
        ) -> StdResult<()> {
            let digest_file_path = digest_dir.join("digests.json");
            if !digest_dir.exists() {
                fs::create_dir_all(digest_dir).unwrap();
            }

            let immutable_digest_messages = digests
                .iter()
                .map(
                    |(immutable_file, digest)| CardanoDatabaseDigestListItemMessage {
                        immutable_file_name: immutable_file.filename.clone(),
                        digest: digest.to_string(),
                    },
                )
                .collect::<Vec<_>>();
            serde_json::to_writer(
                fs::File::create(digest_file_path).unwrap(),
                &immutable_digest_messages,
            )?;

            Ok(())
        }

        fn build_digests_map(size: usize) -> BTreeMap<ImmutableFile, HexEncodedDigest> {
            let mut digests = BTreeMap::new();
            for i in 1..=size {
                for name in ["chunk", "primary", "secondary"] {
                    let immutable_file_name = format!("{i:05}.{name}");
                    let immutable_file =
                        ImmutableFile::new(PathBuf::from(immutable_file_name)).unwrap();
                    let digest = format!("digest-{i}-{name}");
                    digests.insert(immutable_file, digest);
                }
            }

            digests
        }

        #[tokio::test]
        async fn download_and_verify_digest_should_return_digest_map_according_to_beacon() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 42,
            };
            let hightest_immutable_number_in_digest_file =
                123 + beacon.immutable_file_number as usize;
            let digests_in_certificate_map =
                build_digests_map(beacon.immutable_file_number as usize);
            let protocol_message_merkle_root = {
                let digests_in_certificate_values =
                    digests_in_certificate_map.values().cloned().collect::<Vec<_>>();
                let certificate_merkle_tree: MKTree<MKTreeStoreInMemory> =
                    MKTree::new(&digests_in_certificate_values).unwrap();

                certificate_merkle_tree.compute_root().unwrap().to_hex()
            };
            let mut protocol_message = ProtocolMessage::new();
            protocol_message.set_message_part(
                ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
                protocol_message_merkle_root,
            );
            let certificate = CertificateMessage {
                protocol_message: protocol_message.clone(),
                signed_message: protocol_message.compute_hash(),
                ..CertificateMessage::dummy()
            };

            let digests_location = "http://whatever/digests.json";
            let cardano_database_snapshot = CardanoDatabaseSnapshotMessage {
                beacon,
                digests: DigestsMessagePart {
                    size_uncompressed: 1024,
                    locations: vec![DigestLocation::CloudStorage {
                        uri: digests_location.to_string(),
                        compression_algorithm: None,
                    }],
                },
                ..CardanoDatabaseSnapshotMessage::dummy()
            };
            let temp_directory_provider =
                Arc::new(TimestampTempDirectoryProvider::new(current_function!()));
            let digest_target_dir = temp_directory_provider.temp_dir();
            let digest_target_dir_clone = digest_target_dir.clone();
            let http_file_downloader = Arc::new(
                MockFileDownloaderBuilder::default()
                    .with_file_uri(digests_location)
                    .with_target_dir(digest_target_dir.clone())
                    .with_compression(None)
                    .with_returning(Box::new(move |_, _, _, _, _| {
                        write_digest_file(
                            &digest_target_dir_clone,
                            &build_digests_map(hightest_immutable_number_in_digest_file),
                        )?;

                        Ok(())
                    }))
                    .build(),
            );
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(http_file_downloader)
                .with_temp_directory_provider(temp_directory_provider)
                .build_cardano_database_client();

            let verified_digests = client
                .download_and_verify_digests(&certificate, &cardano_database_snapshot)
                .await
                .unwrap();

            let expected_digests_in_certificate = digests_in_certificate_map
                .iter()
                .map(|(immutable_file, digest)| {
                    (immutable_file.filename.clone(), digest.to_string())
                })
                .collect();
            assert_eq!(verified_digests.digests, expected_digests_in_certificate);

            assert!(!digest_target_dir.exists());
        }
    }

    mod download_unpack_digest_file {

        use mithril_common::entities::CompressionAlgorithm;

        use crate::file_downloader::MockFileDownloader;

        use super::*;

        #[tokio::test]
        async fn fails_if_no_location_is_retrieved() {
            let target_dir = Path::new(".");
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_compression(None)
                        .with_failure()
                        .with_times(2)
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            artifact_prover
                .download_unpack_digest_file(
                    &DigestsMessagePart {
                        locations: vec![
                            DigestLocation::CloudStorage {
                                uri: "http://whatever-1/digests.json".to_string(),
                                compression_algorithm: None,
                            },
                            DigestLocation::Aggregator {
                                uri: "http://whatever-2/digest".to_string(),
                            },
                        ],
                        size_uncompressed: 0,
                    },
                    target_dir,
                )
                .await
                .expect_err("download_unpack_digest_file should fail");
        }

        #[tokio::test]
        async fn fails_if_all_locations_are_unknown() {
            let target_dir = Path::new(".");
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(MockFileDownloader::new()),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            artifact_prover
                .download_unpack_digest_file(
                    &DigestsMessagePart {
                        locations: vec![DigestLocation::Unknown],
                        size_uncompressed: 0,
                    },
                    target_dir,
                )
                .await
                .expect_err("download_unpack_digest_file should fail");
        }

        #[tokio::test]
        async fn succeeds_if_at_least_one_location_is_retrieved() {
            let target_dir = Path::new(".");
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_compression(None)
                        .with_failure()
                        .next_call()
                        .with_compression(None)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            artifact_prover
                .download_unpack_digest_file(
                    &DigestsMessagePart {
                        locations: vec![
                            DigestLocation::CloudStorage {
                                uri: "http://whatever-1/digests.json".to_string(),
                                compression_algorithm: None,
                            },
                            DigestLocation::Aggregator {
                                uri: "http://whatever-2/digest".to_string(),
                            },
                        ],
                        size_uncompressed: 0,
                    },
                    target_dir,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn succeeds_when_first_location_is_retrieved() {
            let target_dir = Path::new(".");
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_compression(None)
                        .with_times(1)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            artifact_prover
                .download_unpack_digest_file(
                    &DigestsMessagePart {
                        locations: vec![
                            DigestLocation::CloudStorage {
                                uri: "http://whatever-1/digests.json".to_string(),
                                compression_algorithm: None,
                            },
                            DigestLocation::Aggregator {
                                uri: "http://whatever-2/digest".to_string(),
                            },
                        ],
                        size_uncompressed: 0,
                    },
                    target_dir,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn should_call_download_with_compression_algorithm() {
            let target_dir = Path::new(".");
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_compression(Some(CompressionAlgorithm::Zstandard))
                        .with_times(1)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            artifact_prover
                .download_unpack_digest_file(
                    &DigestsMessagePart {
                        locations: vec![
                            DigestLocation::CloudStorage {
                                uri: "http://whatever-1/digests.tar.zst".to_string(),
                                compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                            },
                            DigestLocation::Aggregator {
                                uri: "http://whatever-2/digest".to_string(),
                            },
                        ],
                        size_uncompressed: 0,
                    },
                    target_dir,
                )
                .await
                .unwrap();
        }
    }

    mod read_digest_file {

        use super::*;

        fn create_valid_fake_digest_file(
            file_path: &Path,
            digest_messages: &[CardanoDatabaseDigestListItemMessage],
        ) {
            let mut file = fs::File::create(file_path).unwrap();
            let digest_json = serde_json::to_string(&digest_messages).unwrap();
            file.write_all(digest_json.as_bytes()).unwrap();
        }

        fn create_invalid_fake_digest_file(file_path: &Path) {
            let mut file = fs::File::create(file_path).unwrap();
            file.write_all(b"incorrect-digest").unwrap();
        }

        #[test]
        fn read_digest_file_fails_when_no_digest_file() {
            let target_dir = TempDir::new(
                "cardano_database_client",
                "read_digest_file_fails_when_no_digest_file",
            )
            .build();
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_times(0)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );
            artifact_prover
                .read_digest_file(&target_dir)
                .expect_err("read_digest_file should fail");
        }

        #[test]
        fn read_digest_file_fails_when_multiple_digest_files() {
            let target_dir = TempDir::new(
                "cardano_database_client",
                "read_digest_file_fails_when_multiple_digest_files",
            )
            .build();
            create_valid_fake_digest_file(&target_dir.join("digests.json"), &[]);
            create_valid_fake_digest_file(&target_dir.join("digests-2.json"), &[]);
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_times(0)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );
            artifact_prover
                .read_digest_file(&target_dir)
                .expect_err("read_digest_file should fail");
        }

        #[test]
        fn read_digest_file_fails_when_invalid_unique_digest_file() {
            let target_dir = TempDir::new(
                "cardano_database_client",
                "read_digest_file_fails_when_invalid_unique_digest_file",
            )
            .build();
            create_invalid_fake_digest_file(&target_dir.join("digests.json"));
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_times(0)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );
            artifact_prover
                .read_digest_file(&target_dir)
                .expect_err("read_digest_file should fail");
        }

        #[test]
        fn read_digest_file_succeeds_when_valid_unique_digest_file() {
            let target_dir = TempDir::new(
                "cardano_database_client",
                "read_digest_file_succeeds_when_valid_unique_digest_file",
            )
            .build();
            let digest_messages = vec![
                CardanoDatabaseDigestListItemMessage {
                    immutable_file_name: "00001.chunk".to_string(),
                    digest: "digest-1".to_string(),
                },
                CardanoDatabaseDigestListItemMessage {
                    immutable_file_name: "00002.chunk".to_string(),
                    digest: "digest-2".to_string(),
                },
            ];
            create_valid_fake_digest_file(&target_dir.join("digests.json"), &digest_messages);
            let artifact_prover = InternalArtifactProver::new(
                Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_times(0)
                        .with_success()
                        .build(),
                ),
                Arc::new(TimestampTempDirectoryProvider::new(current_function!())),
                TestLogger::stdout(),
            );

            let digests = artifact_prover.read_digest_file(&target_dir).unwrap();
            assert_eq!(
                BTreeMap::from([
                    ("00001.chunk".to_string(), "digest-1".to_string()),
                    ("00002.chunk".to_string(), "digest-2".to_string())
                ]),
                digests
            )
        }
    }

    mod list_missing_immutable_files {
        use mithril_cardano_node_internal_database::test::DummyCardanoDbBuilder;
        use mithril_common::temp_dir_create;

        use super::*;

        #[test]
        fn should_return_empty_list_if_no_missing_files() {
            let immutable_files_in_db = 1..=10;
            let range_to_verify = 3..=5;
            let cardano_db =
                DummyCardanoDbBuilder::new(&format!("{}", temp_dir_create!().display()))
                    .with_immutables(&immutable_files_in_db.collect::<Vec<_>>())
                    .append_immutable_trio()
                    .build();

            let missing_files = InternalArtifactProver::list_missing_immutable_files(
                cardano_db.get_dir(),
                &range_to_verify,
            );

            assert!(missing_files.is_empty());
        }

        #[test]
        fn should_return_empty_list_if_missing_files_outside_range() {
            let immutable_files_in_db = 1..=10;
            let range_to_verify = 3..=5;
            let cardano_db =
                DummyCardanoDbBuilder::new(&format!("{}", temp_dir_create!().display()))
                    .with_immutables(&immutable_files_in_db.collect::<Vec<_>>())
                    .append_immutable_trio()
                    .build();
            let files_to_remove = vec!["00002.chunk", "00006.primary"];
            remove_immutable_files(cardano_db.get_dir(), &files_to_remove);

            let missing_files = InternalArtifactProver::list_missing_immutable_files(
                cardano_db.get_dir(),
                &range_to_verify,
            );

            assert!(missing_files.is_empty());
        }

        #[test]
        fn should_return_list_of_missing_files_inside_range() {
            let immutable_files_in_db = 1..=10;
            let range_to_verify = 3..=5;
            let cardano_db =
                DummyCardanoDbBuilder::new(&format!("{}", temp_dir_create!().display()))
                    .with_immutables(&immutable_files_in_db.collect::<Vec<_>>())
                    .append_immutable_trio()
                    .build();
            let files_to_remove = vec!["00004.chunk", "00005.primary"];
            remove_immutable_files(cardano_db.get_dir(), &files_to_remove);

            let missing_files = InternalArtifactProver::list_missing_immutable_files(
                cardano_db.get_dir(),
                &range_to_verify,
            );

            assert_eq!(missing_files, files_to_remove);
        }
    }

    mod verify_cardano_database {

        use std::{collections::BTreeMap, ops::RangeInclusive, path::PathBuf};

        use mithril_cardano_node_internal_database::{
            digesters::{CardanoImmutableDigester, ImmutableDigester},
            test::DummyCardanoDbBuilder,
        };
        use mithril_common::{
            entities::{CardanoDbBeacon, Epoch, ImmutableFileNumber, ProtocolMessage},
            messages::CertificateMessage,
        };

        use crate::cardano_database_client::ImmutableFileRange;
        use crate::common::test::Dummy;
        use crate::{cardano_database_client::VerifiedDigests, test_utils::TestLogger};

        use super::*;

        async fn prepare_db_and_verified_digests(
            dir_name: &str,
            beacon: &CardanoDbBeacon,
            immutable_file_range: &RangeInclusive<ImmutableFileNumber>,
        ) -> (PathBuf, CertificateMessage, VerifiedDigests) {
            let cardano_db = DummyCardanoDbBuilder::new(dir_name)
                .with_immutables(&immutable_file_range.clone().collect::<Vec<_>>())
                .append_immutable_trio()
                .build();
            let database_dir = cardano_db.get_dir();
            let immutable_digester = CardanoImmutableDigester::new(None, TestLogger::stdout());
            let computed_digests = immutable_digester
                .compute_digests_for_range(database_dir, immutable_file_range)
                .await
                .unwrap();

            let digests = computed_digests
                .entries
                .iter()
                .map(|(immutable_file, digest)| (immutable_file.filename.clone(), digest.clone()))
                .collect::<BTreeMap<_, _>>();

            let merkle_tree = immutable_digester
                .compute_merkle_tree(database_dir, beacon)
                .await
                .unwrap();

            let verified_digests = VerifiedDigests {
                digests,
                merkle_tree,
            };

            let certificate = {
                let protocol_message_merkle_root =
                    verified_digests.merkle_tree.compute_root().unwrap().to_hex();
                let mut protocol_message = ProtocolMessage::new();
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
                    protocol_message_merkle_root,
                );

                CertificateMessage {
                    protocol_message: protocol_message.clone(),
                    signed_message: protocol_message.compute_hash(),
                    ..CertificateMessage::dummy()
                }
            };

            (database_dir.to_owned(), certificate, verified_digests)
        }

        fn to_vec_immutable_file_name(list: &[&str]) -> Vec<ImmutableFileName> {
            list.iter().map(|s| ImmutableFileName::from(*s)).collect()
        }

        #[tokio::test]
        async fn succeeds() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 10,
            };
            let immutable_file_range = 1..=15;
            let immutable_file_range_to_prove = ImmutableFileRange::Range(2, 4);
            let (database_dir, certificate, verified_digests) = prepare_db_and_verified_digests(
                "verify_cardano_database_succeeds",
                &beacon,
                &immutable_file_range,
            )
            .await;

            let expected_merkle_root =
                verified_digests.merkle_tree.compute_root().unwrap().to_owned();

            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            let merkle_proof = client
                .verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &immutable_file_range_to_prove,
                    false,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .unwrap();

            merkle_proof.verify().unwrap();
            let merkle_proof_root = merkle_proof.root().to_owned();
            assert_eq!(expected_merkle_root, merkle_proof_root);
        }

        #[tokio::test]
        async fn should_fail_if_immutable_is_missing_and_allow_missing_not_set() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 10,
            };
            let immutable_file_range = 1..=15;
            let immutable_file_range_to_prove = ImmutableFileRange::Range(2, 4);
            let (database_dir, certificate, verified_digests) = prepare_db_and_verified_digests(
                "verify_cardano_database_should_fail_if_immutable_is_missing_and_allow_missing_not_set",
                &beacon,
                &immutable_file_range,
            )
            .await;
            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            let files_to_remove = vec!["00003.chunk", "00004.primary"];
            remove_immutable_files(&database_dir, &files_to_remove);

            let allow_missing = false;
            let error = client
                .verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &immutable_file_range_to_prove,
                    allow_missing,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .expect_err("verify_cardano_database should fail if a immutable is missing");

            let error_lists = match error {
                CardanoDatabaseVerificationError::ImmutableFilesVerification(lists) => lists,
                _ => panic!("Expected ImmutableFilesVerification error, got: {error}"),
            };

            assert_eq!(
                error_lists,
                ImmutableVerificationResult {
                    immutables_dir: InternalArtifactProver::immutable_dir(&database_dir),
                    missing: to_vec_immutable_file_name(&files_to_remove),
                    tampered: vec![],
                    non_verifiable: vec![],
                }
            );
        }

        #[tokio::test]
        async fn should_success_if_immutable_is_missing_and_allow_missing_is_set() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 10,
            };
            let immutable_file_range = 1..=15;
            let immutable_file_range_to_prove = ImmutableFileRange::Range(2, 4);
            let (database_dir, certificate, verified_digests) = prepare_db_and_verified_digests(
                "verify_cardano_database_should_success_if_immutable_is_missing_and_allow_missing_is_set",
                &beacon,
                &immutable_file_range,
            )
            .await;
            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            let files_to_remove = vec!["00003.chunk", "00004.primary"];
            remove_immutable_files(&database_dir, &files_to_remove);

            let allow_missing = true;
            client.verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &immutable_file_range_to_prove,
                    allow_missing,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .expect(
                    "verify_cardano_database should succeed if a immutable is missing but 'allow_missing' is set",
                );
        }

        #[tokio::test]
        async fn should_fail_if_immutable_is_tampered() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 10,
            };
            let immutable_file_range = 1..=15;
            let immutable_file_range_to_prove = ImmutableFileRange::Range(2, 4);
            let (database_dir, certificate, verified_digests) = prepare_db_and_verified_digests(
                "verify_cardano_database_should_fail_if_immutable_is_tampered",
                &beacon,
                &immutable_file_range,
            )
            .await;
            let (logger, log_inspector) = TestLogger::memory();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_logger(logger)
                .build_cardano_database_client();

            let files_to_tamper = vec!["00003.chunk", "00004.primary"];
            tamper_immutable_files(&database_dir, &files_to_tamper);

            let error = client
                .verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &immutable_file_range_to_prove,
                    false,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .expect_err("verify_cardano_database should fail if a immutable is missing");

            assert!(log_inspector.contains_log(MERKLE_PROOF_COMPUTATION_ERROR));

            let error_lists = match error {
                CardanoDatabaseVerificationError::ImmutableFilesVerification(lists) => lists,
                _ => panic!("Expected ImmutableFilesVerification error, got: {error}"),
            };
            assert_eq!(
                error_lists,
                ImmutableVerificationResult {
                    immutables_dir: InternalArtifactProver::immutable_dir(&database_dir),
                    missing: vec![],
                    tampered: to_vec_immutable_file_name(&files_to_tamper),
                    non_verifiable: vec![],
                }
            )
        }

        #[tokio::test]
        async fn should_fail_if_immutables_are_missing_and_tampered() {
            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 10,
            };
            let immutable_file_range = 1..=15;
            let immutable_file_range_to_prove = ImmutableFileRange::Range(2, 4);
            let (database_dir, certificate, verified_digests) = prepare_db_and_verified_digests(
                "verify_cardano_database_should_fail_if_immutables_are_missing_and_tampered",
                &beacon,
                &immutable_file_range,
            )
            .await;

            let files_to_remove = vec!["00003.chunk"];
            let files_to_tamper = vec!["00004.primary"];
            remove_immutable_files(&database_dir, &files_to_remove);
            tamper_immutable_files(&database_dir, &files_to_tamper);

            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();
            let error = client
                .verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &immutable_file_range_to_prove,
                    false,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .expect_err("verify_cardano_database should fail if a immutable is missing");

            let error_lists = match error {
                CardanoDatabaseVerificationError::ImmutableFilesVerification(lists) => lists,
                _ => panic!("Expected ImmutableFilesVerification error, got: {error}"),
            };
            assert_eq!(
                error_lists,
                ImmutableVerificationResult {
                    immutables_dir: InternalArtifactProver::immutable_dir(&database_dir),
                    missing: to_vec_immutable_file_name(&files_to_remove),
                    tampered: to_vec_immutable_file_name(&files_to_tamper),
                    non_verifiable: vec![],
                }
            )
        }

        #[tokio::test]
        async fn should_fail_if_there_is_more_local_immutable_than_verified_digest() {
            let last_verified_digest_number = 10;
            let last_local_immutable_file_number = 15;
            let range_of_non_verifiable_files =
                last_verified_digest_number + 1..=last_local_immutable_file_number;

            let expected_non_verifiable_files: Vec<ImmutableFileName> =
                (range_of_non_verifiable_files)
                    .flat_map(|i| {
                        [
                            format!("{i:05}.chunk"),
                            format!("{i:05}.primary"),
                            format!("{i:05}.secondary"),
                        ]
                    })
                    .collect();

            let beacon = CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: last_verified_digest_number,
            };
            //create verified digests for immutable files 1 to 10
            let (_, certificate, verified_digests) = prepare_db_and_verified_digests(
                "database_dir_for_verified_digests",
                &beacon,
                &(1..=last_verified_digest_number),
            )
            .await;
            //create a local database with immutable files 1 to 15
            let (database_dir, _, _) = prepare_db_and_verified_digests(
                "database_dir_for_local_immutables",
                &beacon,
                &(1..=last_local_immutable_file_number),
            )
            .await;

            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();
            let error = client
                .verify_cardano_database(
                    &certificate,
                    &CardanoDatabaseSnapshotMessage::dummy(),
                    &ImmutableFileRange::Range(1, 15),
                    false,
                    &database_dir,
                    &verified_digests,
                )
                .await
                .expect_err(
                    "verify_cardano_database should fail if there is more local immutable than verified digest",
                );

            let error_lists = match error {
                CardanoDatabaseVerificationError::ImmutableFilesVerification(lists) => lists,
                _ => panic!("Expected ImmutableFilesVerification error, got: {error}"),
            };
            assert_eq!(
                error_lists,
                ImmutableVerificationResult {
                    immutables_dir: InternalArtifactProver::immutable_dir(&database_dir),
                    missing: vec![],
                    tampered: vec![],
                    non_verifiable: expected_non_verifiable_files,
                }
            );
        }
    }

    mod cardano_database_verification_error {
        use super::*;

        fn generate_immutable_files_verification_error(
            missing_range: Option<RangeInclusive<usize>>,
            tampered_range: Option<RangeInclusive<usize>>,
            non_verifiable_range: Option<RangeInclusive<usize>>,
            immutable_path: &str,
        ) -> CardanoDatabaseVerificationError {
            let missing: Vec<ImmutableFileName> = match missing_range {
                Some(range) => range
                    .map(|i| ImmutableFileName::from(format!("{i:05}.chunk")))
                    .collect(),
                None => vec![],
            };
            let tampered: Vec<ImmutableFileName> = match tampered_range {
                Some(range) => range
                    .map(|i| ImmutableFileName::from(format!("{i:05}.chunk")))
                    .collect(),
                None => vec![],
            };

            let non_verifiable: Vec<ImmutableFileName> = match non_verifiable_range {
                Some(range) => range
                    .map(|i| ImmutableFileName::from(format!("{i:05}.chunk")))
                    .collect(),
                None => vec![],
            };

            CardanoDatabaseVerificationError::ImmutableFilesVerification(
                ImmutableVerificationResult {
                    immutables_dir: PathBuf::from(immutable_path),
                    missing,
                    tampered,
                    non_verifiable,
                },
            )
        }

        fn normalize_path_separators(s: &str) -> String {
            s.replace('\\', "/")
        }

        #[test]
        fn display_immutable_files_verification_error_should_displayed_lists_with_10_elements() {
            let error = generate_immutable_files_verification_error(
                Some(1..=15),
                Some(20..=31),
                Some(40..=41),
                "/path/to/immutables",
            );

            let display = normalize_path_separators(&format!("{error}"));

            assert_eq!(
                display,
                r###"Number of missing immutable files: 15
First 10 missing immutable files paths:
/path/to/immutables/00001.chunk
/path/to/immutables/00002.chunk
/path/to/immutables/00003.chunk
/path/to/immutables/00004.chunk
/path/to/immutables/00005.chunk
/path/to/immutables/00006.chunk
/path/to/immutables/00007.chunk
/path/to/immutables/00008.chunk
/path/to/immutables/00009.chunk
/path/to/immutables/00010.chunk

Number of tampered immutable files: 12
First 10 tampered immutable files paths:
/path/to/immutables/00020.chunk
/path/to/immutables/00021.chunk
/path/to/immutables/00022.chunk
/path/to/immutables/00023.chunk
/path/to/immutables/00024.chunk
/path/to/immutables/00025.chunk
/path/to/immutables/00026.chunk
/path/to/immutables/00027.chunk
/path/to/immutables/00028.chunk
/path/to/immutables/00029.chunk

Number of non verifiable immutable files: 2
First 10 non verifiable immutable files paths:
/path/to/immutables/00040.chunk
/path/to/immutables/00041.chunk
"###
            );
        }

        #[test]
        fn display_immutable_files_should_display_tampered_files_only() {
            let error = generate_immutable_files_verification_error(
                None,
                Some(1..=1),
                None,
                "/path/to/immutables",
            );

            let display = normalize_path_separators(&format!("{error}"));

            assert_eq!(
                display,
                r###"Number of tampered immutable files: 1
First 10 tampered immutable files paths:
/path/to/immutables/00001.chunk
"###
            );
        }

        #[test]
        fn display_immutable_files_should_display_missing_files_only() {
            let error = generate_immutable_files_verification_error(
                Some(1..=1),
                None,
                None,
                "/path/to/immutables",
            );

            let display = normalize_path_separators(&format!("{error}"));

            assert_eq!(
                display,
                r###"Number of missing immutable files: 1
First 10 missing immutable files paths:
/path/to/immutables/00001.chunk
"###
            );
        }

        #[test]
        fn display_immutable_files_should_display_non_verifiable_files_only() {
            let error = generate_immutable_files_verification_error(
                None,
                None,
                Some(1..=5),
                "/path/to/immutables",
            );

            let display = normalize_path_separators(&format!("{error}"));

            assert_eq!(
                display,
                r###"Number of non verifiable immutable files: 5
First 10 non verifiable immutable files paths:
/path/to/immutables/00001.chunk
/path/to/immutables/00002.chunk
/path/to/immutables/00003.chunk
/path/to/immutables/00004.chunk
/path/to/immutables/00005.chunk
"###
            );
        }
    }
}
