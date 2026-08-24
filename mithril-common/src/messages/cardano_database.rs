use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::StdResult;
use crate::entities::{
    AncillaryLocation, AncillaryLocations, CardanoDbBeacon, DigestLocation, DigestsLocations,
    ImmutablesLocation, ImmutablesLocations,
};

/// The message part that represents the locations of the Cardano database digests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestsMessagePart {
    /// Size of the uncompressed digests file.
    pub size_uncompressed: u64,

    /// Locations of the digests.
    pub locations: Vec<DigestLocation>,
}

impl DigestsMessagePart {
    /// Return the list of locations without the unknown locations, failing if all locations are unknown.
    pub fn sanitized_locations(&self) -> StdResult<Vec<DigestLocation>> {
        let sanitized_locations: Vec<_> = self
            .locations
            .iter()
            .filter(|l| !matches!(l, DigestLocation::Unknown))
            .cloned()
            .collect();

        if sanitized_locations.is_empty() {
            Err(anyhow!("All digests locations are unknown."))
        } else {
            Ok(sanitized_locations)
        }
    }
}

/// The message part that represents the locations of the Cardano database immutables.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmutablesMessagePart {
    /// Average size for one immutable file.
    pub average_size_uncompressed: u64,

    /// Locations of the immutable files.
    pub locations: Vec<ImmutablesLocation>,
}

impl ImmutablesMessagePart {
    /// Return the list of locations without the unknown locations, failing if all locations are unknown.
    pub fn sanitized_locations(&self) -> StdResult<Vec<ImmutablesLocation>> {
        let sanitized_locations: Vec<_> = self
            .locations
            .iter()
            .filter(|l| {
                !matches!(
                    l,
                    // Temporarily exclude IPFS locations until the download is implemented.
                    ImmutablesLocation::Unknown | ImmutablesLocation::Ipfs { .. }
                )
            })
            .cloned()
            .collect();

        if sanitized_locations.is_empty() {
            Err(anyhow!("All locations are unknown."))
        } else {
            Ok(sanitized_locations)
        }
    }
}

/// The message part that represents the locations of the Cardano database ancillary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncillaryMessagePart {
    /// Size of the uncompressed ancillary file.
    pub size_uncompressed: u64,

    /// Locations of the ancillary files.
    pub locations: Vec<AncillaryLocation>,
}

impl AncillaryMessagePart {
    /// Return the list of locations without the unknown locations, failing if all locations are unknown.
    pub fn sanitized_locations(&self) -> StdResult<Vec<AncillaryLocation>> {
        let sanitized_locations: Vec<_> = self
            .locations
            .iter()
            .filter(|l| !matches!(l, AncillaryLocation::Unknown))
            .cloned()
            .collect();

        if sanitized_locations.is_empty() {
            Err(anyhow!("All locations are unknown."))
        } else {
            Ok(sanitized_locations)
        }
    }
}

impl From<DigestsLocations> for DigestsMessagePart {
    fn from(part: DigestsLocations) -> Self {
        Self {
            size_uncompressed: part.size_uncompressed,
            locations: part.locations,
        }
    }
}

impl From<ImmutablesLocations> for ImmutablesMessagePart {
    fn from(part: ImmutablesLocations) -> Self {
        Self {
            average_size_uncompressed: part.average_size_uncompressed,
            locations: part.locations,
        }
    }
}

impl From<AncillaryLocations> for AncillaryMessagePart {
    fn from(part: AncillaryLocations) -> Self {
        Self {
            size_uncompressed: part.size_uncompressed,
            locations: part.locations,
        }
    }
}

/// Cardano database snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoDatabaseSnapshotMessage {
    /// Hash of the Cardano database snapshot.
    pub hash: String,

    /// Merkle root of the Cardano database snapshot.
    pub merkle_root: String,

    /// Cardano network
    pub network: String,

    /// Mithril beacon on the Cardano chain.
    pub beacon: CardanoDbBeacon,

    /// Hash of the associated certificate
    pub certificate_hash: String,

    /// Size of the uncompressed Cardano database files.
    pub total_db_size_uncompressed: u64,

    /// Locations of the the immutable file digests.
    pub digests: DigestsMessagePart,

    /// Locations of the immutable files.
    pub immutables: ImmutablesMessagePart,

    /// Locations of the ancillary files.
    pub ancillary: AncillaryMessagePart,

    /// Version of the Cardano node used to create the snapshot.
    pub cardano_node_version: String,

    /// Date and time at which the snapshot was created
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use crate::entities::{CompressionAlgorithm, Epoch, MultiFilesUri, TemplateUri};

    use super::*;

    const CURRENT_JSON: &str = r#"
    {
        "hash": "d4071d518a3ace0f6c04a9c0745b9e9560e3e2af1b373bafc4e0398423e9abfb",
        "merkle_root": "c8224920b9f5ad7377594eb8a15f34f08eb3103cc5241d57cafc5638403ec7c6",
        "network": "preview",
        "beacon": {
            "epoch": 123,
            "immutable_file_number": 2345
        },
        "certificate_hash": "f6c01b373bafc4e039844071d5da3ace4a9c0745b9e9560e3e2af01823e9abfb",
        "total_db_size_uncompressed": 800796318,
        "digests": {
            "size_uncompressed": 1024,
            "locations": [
                {
                    "type": "aggregator",
                    "uri": "https://host-1/digest-1"
                }
            ]
        },
        "immutables": {
            "average_size_uncompressed": 2048,
            "locations": [
                {
                    "type": "cloud_storage",
                    "uri": {
                        "Template": "https://host-1/immutables-{immutable_file_number}"
                    },
                    "compression_algorithm": "zstandard"
                },
                {
                    "type": "cloud_storage",
                    "uri": {
                        "Template": "https://host-2/immutables-{immutable_file_number}"
                    }
                },
                {
                    "type": "ipfs",
                    "uri": {
                        "Template": "QmSiDJUe8MsPRwbAJuT5PtRmxXLJVsUK1j2ZSN3SKkAN6Z/{immutable_file_number}"
                    }
                }
            ]
        },
        "ancillary": {
            "size_uncompressed": 4096,
            "locations": [
                {
                    "type": "cloud_storage",
                    "uri": "https://host-1/ancillary-3",
                    "compression_algorithm": "zstandard"
                }
            ]
        },
        "cardano_node_version": "0.0.1",
        "created_at": "2023-01-19T13:43:05.618857482Z"
    }"#;

    fn golden_current_message() -> CardanoDatabaseSnapshotMessage {
        CardanoDatabaseSnapshotMessage {
            hash: "d4071d518a3ace0f6c04a9c0745b9e9560e3e2af1b373bafc4e0398423e9abfb".to_string(),
            merkle_root: "c8224920b9f5ad7377594eb8a15f34f08eb3103cc5241d57cafc5638403ec7c6"
                .to_string(),
            network: "preview".to_string(),
            beacon: CardanoDbBeacon {
                epoch: Epoch(123),
                immutable_file_number: 2345,
            },
            certificate_hash: "f6c01b373bafc4e039844071d5da3ace4a9c0745b9e9560e3e2af01823e9abfb"
                .to_string(),
            total_db_size_uncompressed: 800796318,
            created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                .unwrap()
                .with_timezone(&Utc),
            digests: DigestsMessagePart {
                size_uncompressed: 1024,
                locations: vec![DigestLocation::Aggregator {
                    uri: "https://host-1/digest-1".to_string(),
                }],
            },
            immutables: ImmutablesMessagePart {
                average_size_uncompressed: 2048,
                locations: vec![
                    ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "https://host-1/immutables-{immutable_file_number}".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    },
                    ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "https://host-2/immutables-{immutable_file_number}".to_string(),
                        )),
                        compression_algorithm: None,
                    },
                    ImmutablesLocation::Ipfs {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "QmSiDJUe8MsPRwbAJuT5PtRmxXLJVsUK1j2ZSN3SKkAN6Z/{immutable_file_number}".to_string(),
                        )),
                        compression_algorithm: None,
                    },
                ],
            },
            ancillary: AncillaryMessagePart {
                size_uncompressed: 4096,
                locations: vec![AncillaryLocation::CloudStorage {
                    uri: "https://host-1/ancillary-3".to_string(),
                    compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                }],
            },
            cardano_node_version: "0.0.1".to_string(),
        }
    }

    #[test]
    fn test_current_json_deserialized_into_current_message() {
        let json = CURRENT_JSON;
        let message: CardanoDatabaseSnapshotMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be successfully parsed into a CardanoDatabaseSnapshotMessage instance.",
        );

        assert_eq!(golden_current_message(), message);
    }

    #[test]
    fn test_a_future_json_deserialized_with_unknown_location_types() {
        let json = r#"
        {
            "hash": "d4071d518a3ace0f6c04a9c0745b9e9560e3e2af1b373bafc4e0398423e9abfb",
            "merkle_root": "c8224920b9f5ad7377594eb8a15f34f08eb3103cc5241d57cafc5638403ec7c6",
            "network": "preview",
            "beacon": {
                "epoch": 123,
                "immutable_file_number": 2345
            },
            "certificate_hash": "f6c01b373bafc4e039844071d5da3ace4a9c0745b9e9560e3e2af01823e9abfb",
            "total_db_size_uncompressed": 800796318,
            "digests": {
                "size_uncompressed": 1024,
                "locations": [
                    {
                        "type": "whatever",
                        "new_field": "digest-1"
                    }
                ]
            },
            "immutables": {
                "average_size_uncompressed": 512,
                "locations": [
                    {
                        "type": "whatever",
                        "new_field": [123, 125]
                    }
                ]
            },
            "ancillary": {
                "size_uncompressed": 4096,
                "locations": [
                    {
                        "type": "whatever",
                        "new_field": "ancillary-3"
                    }
                ]
            },
            "compression_algorithm": "zstandard",
            "cardano_node_version": "0.0.1",
            "created_at": "2023-01-19T13:43:05.618857482Z"
        }"#;
        let message: CardanoDatabaseSnapshotMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be successfully parsed into a CardanoDatabaseSnapshotMessage instance.",
        );

        assert_eq!(message.digests.locations.len(), 1);
        assert_eq!(DigestLocation::Unknown, message.digests.locations[0]);

        assert_eq!(message.immutables.locations.len(), 1);
        assert_eq!(ImmutablesLocation::Unknown, message.immutables.locations[0]);

        assert_eq!(message.ancillary.locations.len(), 1);
        assert_eq!(AncillaryLocation::Unknown, message.ancillary.locations[0]);
    }

    mod sanitize_immutable_locations {
        use super::*;

        #[test]
        fn succeeds_and_leave_all_locations_intact_if_no_unknown_location() {
            let immutable_locations = ImmutablesMessagePart {
                locations: vec![ImmutablesLocation::CloudStorage {
                    uri: MultiFilesUri::Template(TemplateUri(
                        "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                    )),
                    compression_algorithm: None,
                }],
                average_size_uncompressed: 512,
            };

            let sanitize_locations = immutable_locations
                .sanitized_locations()
                .expect("Should succeed since there are no unknown locations.");
            assert_eq!(sanitize_locations, immutable_locations.locations);
        }

        #[test]
        fn succeeds_and_remove_unknown_locations_if_some_locations_are_not_unknown() {
            let immutable_locations = ImmutablesMessagePart {
                locations: vec![
                    ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: None,
                    },
                    ImmutablesLocation::Unknown,
                ],
                average_size_uncompressed: 512,
            };

            let sanitize_locations = immutable_locations
                .sanitized_locations()
                .expect("Should succeed since not all locations are unknown.");
            assert_eq!(
                sanitize_locations,
                vec![ImmutablesLocation::CloudStorage {
                    uri: MultiFilesUri::Template(TemplateUri(
                        "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                    )),
                    compression_algorithm: None,
                }]
            );
        }

        #[test]
        fn fails_if_all_locations_are_unknown() {
            ImmutablesMessagePart {
                locations: vec![ImmutablesLocation::Unknown],
                average_size_uncompressed: 512,
            }
            .sanitized_locations()
            .expect_err("Should fail since all locations are unknown.");
        }

        // Temporarily exclude IPFS locations until the download is implemented.
        #[test]
        fn fails_if_all_locations_are_ipfs() {
            ImmutablesMessagePart {
                locations: vec![ImmutablesLocation::Ipfs {
                    uri: MultiFilesUri::Template(TemplateUri(
                        "Whatever_CID/{immutable_file_number}.tar.zst".to_string(),
                    )),
                    compression_algorithm: None,
                }],
                average_size_uncompressed: 512,
            }
            .sanitized_locations()
            .expect_err("Should fail since all locations are IPFS.");
        }
    }

    mod sanitize_ancillary_locations {
        use super::*;

        #[test]
        fn succeeds_and_leave_all_locations_intact_if_no_unknown_location() {
            let ancillary_locations = AncillaryMessagePart {
                locations: vec![AncillaryLocation::CloudStorage {
                    uri: "http://whatever/ancillary.tar.zst".to_string(),
                    compression_algorithm: None,
                }],
                size_uncompressed: 1024,
            };

            let sanitize_locations = ancillary_locations
                .sanitized_locations()
                .expect("Should succeed since there are no unknown locations.");
            assert_eq!(sanitize_locations, ancillary_locations.locations);
        }

        #[test]
        fn succeeds_and_remove_unknown_locations_if_some_locations_are_not_unknown() {
            let ancillary_locations = AncillaryMessagePart {
                locations: vec![
                    AncillaryLocation::CloudStorage {
                        uri: "http://whatever/digests.tar.zst".to_string(),
                        compression_algorithm: None,
                    },
                    AncillaryLocation::Unknown,
                ],
                size_uncompressed: 512,
            };

            let sanitize_locations = ancillary_locations
                .sanitized_locations()
                .expect("Should succeed since not all locations are unknown.");
            assert_eq!(
                sanitize_locations,
                vec![AncillaryLocation::CloudStorage {
                    uri: "http://whatever/digests.tar.zst".to_string(),
                    compression_algorithm: None,
                }]
            );
        }

        #[test]
        fn fails_if_all_locations_are_unknown() {
            AncillaryMessagePart {
                locations: vec![AncillaryLocation::Unknown],
                size_uncompressed: 512,
            }
            .sanitized_locations()
            .expect_err("Should fail since all locations are unknown.");
        }
    }

    mod sanitize_digests_locations {
        use super::*;

        #[test]
        fn succeeds_and_leave_all_locations_intact_if_no_unknown_location() {
            let digests_locations = DigestsMessagePart {
                locations: vec![DigestLocation::CloudStorage {
                    uri: "http://whatever/digests.tar.zst".to_string(),
                    compression_algorithm: None,
                }],
                size_uncompressed: 512,
            };

            let sanitize_locations = digests_locations
                .sanitized_locations()
                .expect("Should succeed since there are no unknown locations.");
            assert_eq!(sanitize_locations, digests_locations.locations);
        }

        #[test]
        fn succeeds_and_remove_unknown_locations_if_some_locations_are_not_unknown() {
            let digests_locations = DigestsMessagePart {
                locations: vec![
                    DigestLocation::CloudStorage {
                        uri: "http://whatever/digests.tar.zst".to_string(),
                        compression_algorithm: None,
                    },
                    DigestLocation::Unknown,
                ],
                size_uncompressed: 512,
            };

            let sanitize_locations = digests_locations
                .sanitized_locations()
                .expect("Should succeed since not all locations are unknown.");
            assert_eq!(
                sanitize_locations,
                vec![DigestLocation::CloudStorage {
                    uri: "http://whatever/digests.tar.zst".to_string(),
                    compression_algorithm: None,
                }]
            );
        }

        #[test]
        fn fails_if_all_locations_are_unknown() {
            DigestsMessagePart {
                locations: vec![DigestLocation::Unknown],
                size_uncompressed: 512,
            }
            .sanitized_locations()
            .expect_err("Should fail since all locations are unknown.");
        }
    }
}
