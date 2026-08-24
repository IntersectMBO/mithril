use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entities::{CardanoDbBeacon, CompressionAlgorithm};

use super::{CardanoNetwork, MultiFilesUri};

/// Structure holding artifacts data needed to create a Cardano database snapshot.
pub struct CardanoDatabaseSnapshotArtifactData {
    /// Size of the uncompressed Cardano database files.
    pub total_db_size_uncompressed: u64,

    /// Locations of the Cardano database digests.
    pub digests: DigestsLocations,

    /// Locations of the Cardano database immutables.
    pub immutables: ImmutablesLocations,

    /// Locations of the Cardano database ancillary.
    pub ancillary: AncillaryLocations,
}

/// Cardano database snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoDatabaseSnapshot {
    /// Unique hash of the Cardano database snapshot.
    pub hash: String,

    /// Merkle root of the Cardano database snapshot.
    pub merkle_root: String,

    /// Cardano network.
    pub network: CardanoNetwork,

    /// Mithril beacon on the Cardano chain.
    pub beacon: CardanoDbBeacon,

    /// Size of the uncompressed Cardano database files.
    pub total_db_size_uncompressed: u64,

    /// Locations of the Cardano database digests.
    pub digests: DigestsLocations,

    /// Locations of the Cardano database immutables.
    pub immutables: ImmutablesLocations,

    /// Locations of the Cardano database ancillary.
    pub ancillary: AncillaryLocations,

    /// Version of the Cardano node used to create the snapshot.
    pub cardano_node_version: String,
}

impl CardanoDatabaseSnapshot {
    /// [CardanoDatabaseSnapshot] factory
    pub fn new(
        merkle_root: String,
        network: CardanoNetwork,
        beacon: CardanoDbBeacon,
        content: CardanoDatabaseSnapshotArtifactData,
        cardano_node_version: &Version,
    ) -> Self {
        let cardano_node_version = format!("{cardano_node_version}");
        let mut cardano_database_snapshot = Self {
            hash: "".to_string(),
            merkle_root,
            network,
            beacon,
            digests: content.digests,
            immutables: content.immutables,
            ancillary: content.ancillary,
            total_db_size_uncompressed: content.total_db_size_uncompressed,
            cardano_node_version,
        };
        cardano_database_snapshot.hash = cardano_database_snapshot.compute_hash();

        cardano_database_snapshot
    }

    /// Cardano database snapshot hash computation
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.beacon.epoch.to_be_bytes());
        hasher.update(self.merkle_root.as_bytes());

        hex::encode(hasher.finalize())
    }
}

/// Locations of the immutable file digests.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DigestLocation {
    /// Cloud storage location.
    CloudStorage {
        /// URI of the cloud storage location.
        uri: String,

        /// Compression algorithm of the Cardano database artifacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        compression_algorithm: Option<CompressionAlgorithm>,
    },
    /// Aggregator digest route location.
    Aggregator {
        /// URI of the aggregator digests route location.
        uri: String,
    },
    /// Catchall for unknown location variants.
    #[serde(other)]
    Unknown,
}

/// Locations of the immutable files.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ImmutablesLocation {
    /// Cloud storage location.
    CloudStorage {
        /// URI of the cloud storage location.
        uri: MultiFilesUri,

        /// Compression algorithm of the Cardano database artifacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        compression_algorithm: Option<CompressionAlgorithm>,
    },
    /// IPFS location.
    Ipfs {
        /// URI of the IPFS location.
        uri: MultiFilesUri,

        /// Compression algorithm of the Cardano database artifacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        compression_algorithm: Option<CompressionAlgorithm>,
    },
    /// Catchall for unknown location variants.
    #[serde(other)]
    Unknown,
}

/// Locations of the ancillary files.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AncillaryLocation {
    /// Cloud storage location.
    CloudStorage {
        /// URI of the cloud storage location.
        uri: String,

        /// Compression algorithm of the Cardano database artifacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        compression_algorithm: Option<CompressionAlgorithm>,
    },
    /// Catchall for unknown location variants.
    #[serde(other)]
    Unknown,
}

/// Digests locations of the Cardano database related files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestsLocations {
    /// Size of the uncompressed digests file.
    pub size_uncompressed: u64,

    /// Locations of the immutable files digests.
    pub locations: Vec<DigestLocation>,
}

/// Immutables locations of the Cardano database related files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmutablesLocations {
    /// Average size for one immutable file.
    pub average_size_uncompressed: u64,

    /// Locations of the immutable files.
    pub locations: Vec<ImmutablesLocation>,
}

/// Ancillary locations of the Cardano database related files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncillaryLocations {
    /// Size of the uncompressed ancillary file.
    pub size_uncompressed: u64,

    /// Locations of the ancillary files.
    pub locations: Vec<AncillaryLocation>,
}

#[cfg(test)]
mod tests {
    use crate::entities::TemplateUri;

    use super::*;

    fn dummy() -> CardanoDatabaseSnapshot {
        CardanoDatabaseSnapshot::new(
            "mk-root-1111111111".to_string(),
            CardanoNetwork::TestNet(87),
            CardanoDbBeacon::new(2222, 55555),
            CardanoDatabaseSnapshotArtifactData {
                total_db_size_uncompressed: 0,
                digests: DigestsLocations {
                    size_uncompressed: 0,
                    locations: vec![],
                },
                immutables: ImmutablesLocations {
                    average_size_uncompressed: 0,
                    locations: vec![],
                },
                ancillary: AncillaryLocations {
                    size_uncompressed: 0,
                    locations: vec![],
                },
            },
            &Version::new(1, 0, 0),
        )
    }

    mod cardano_database_snapshot_compute_hash {
        use super::*;

        #[test]
        fn test_cardano_database_snapshot_compute_hash() {
            let cardano_database_snapshot = CardanoDatabaseSnapshot {
                merkle_root: "mk-root-123".to_string(),
                beacon: CardanoDbBeacon::new(123, 98),
                ..dummy()
            };

            assert_eq!(
                "b1cc5e0deaa7856e8e811e349d6e639fa667aa70288602955f438c5893ce29c8",
                cardano_database_snapshot.compute_hash()
            );
        }

        #[test]
        fn compute_hash_returns_same_hash_with_same_cardano_database_snapshot() {
            assert_eq!(
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash(),
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash()
            );
        }

        #[test]
        fn compute_hash_returns_different_hash_with_different_merkle_root() {
            assert_ne!(
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash(),
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-456".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash()
            );
        }

        #[test]
        fn compute_hash_returns_different_hash_with_same_epoch_in_beacon() {
            assert_eq!(
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash(),
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 12),
                    ..dummy()
                }
                .compute_hash()
            );
        }

        #[test]
        fn compute_hash_returns_different_hash_with_different_beacon() {
            assert_ne!(
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(123, 98),
                    ..dummy()
                }
                .compute_hash(),
                CardanoDatabaseSnapshot {
                    merkle_root: "mk-root-123".to_string(),
                    beacon: CardanoDbBeacon::new(456, 98),
                    ..dummy()
                }
                .compute_hash()
            );
        }
    }

    #[test]
    fn should_not_display_compression_algorithm_in_json_ancillary_location_when_none() {
        let json = serde_json::json!(AncillaryLocation::CloudStorage {
            uri: "https://example.com".to_string(),
            compression_algorithm: None,
        });
        assert_eq!(
            json.to_string(),
            r#"{"type":"cloud_storage","uri":"https://example.com"}"#
        );
    }

    #[test]
    fn should_not_display_compression_algorithm_in_json_digests_location_when_none() {
        let json = serde_json::json!(DigestLocation::CloudStorage {
            uri: "https://example.com".to_string(),
            compression_algorithm: None,
        });
        assert_eq!(
            json.to_string(),
            r#"{"type":"cloud_storage","uri":"https://example.com"}"#
        );
    }

    #[test]
    fn should_not_display_compression_algorithm_in_json_immutable_cloud_storage_location_when_none()
    {
        let json = serde_json::json!(ImmutablesLocation::CloudStorage {
            uri: MultiFilesUri::Template(TemplateUri("https://example.com".to_string())),
            compression_algorithm: None,
        });
        assert_eq!(
            json.to_string(),
            r#"{"type":"cloud_storage","uri":{"Template":"https://example.com"}}"#
        );
    }

    #[test]
    fn should_not_display_compression_algorithm_in_json_immutable_ipfs_location_when_none() {
        let json = serde_json::json!(ImmutablesLocation::Ipfs {
            uri: MultiFilesUri::Template(TemplateUri("https://example.com".to_string())),
            compression_algorithm: None,
        });
        assert_eq!(
            json.to_string(),
            r#"{"type":"ipfs","uri":{"Template":"https://example.com"}}"#
        );
    }
}
