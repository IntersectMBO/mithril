use chrono::{DateTime, Utc};

use crate::test::double::{Dummy, fake_data, fake_keys};

mod stm {
    use mithril_stm::{AncillaryGenesisData, AncillaryProofInput};

    use super::*;

    impl Dummy for AncillaryProofInput {
        /// Return a dummy [AncillaryProofInput] carrying no data (test-only).
        fn dummy() -> Self {
            Self::new(
                None,
                AncillaryGenesisData::new(
                    #[cfg(feature = "future_snark")]
                    Vec::new(),
                    #[cfg(feature = "future_snark")]
                    None,
                    #[cfg(feature = "future_snark")]
                    None,
                ),
                #[cfg(feature = "future_snark")]
                Vec::new(),
            )
        }
    }
}

mod entities {
    use crate::crypto_helper::MKTreeStoreInMemory;
    use crate::entities::*;
    use crate::test::entities_extensions::{
        CardanoTransactionsSetProofTestExtension, MkSetProofTestExtension,
    };

    use super::*;

    impl Dummy for ChainPoint {
        /// Return a dummy [ChainPoint] (test-only).
        fn dummy() -> Self {
            Self {
                slot_number: SlotNumber(100),
                block_number: BlockNumber(0),
                block_hash: "block_hash-50".to_string(),
            }
        }
    }

    impl Dummy for CardanoTransactionsSetProof {
        /// Return a dummy [CardanoTransactionsSetProof] (test-only).
        fn dummy() -> Self {
            let leaves = [
                (BlockNumber(0), "tx-1".to_string()),
                (BlockNumber(1), "tx-2".to_string()),
                (BlockNumber(1), "tx-3".to_string()),
                (BlockNumber(10), "tx-4".to_string()),
                (BlockNumber(20), "tx-5".to_string()),
                (BlockNumber(22), "tx-6".to_string()),
            ];

            Self::from_leaves::<MKTreeStoreInMemory>(&leaves).unwrap()
        }
    }

    impl Dummy for SignedEntityConfig {
        /// Return a dummy [SignedEntityConfig] (test-only).
        fn dummy() -> Self {
            Self {
                allowed_discriminants: SignedEntityTypeDiscriminants::all(),
                cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions_signing_config: Some(
                    CardanoBlocksTransactionsSigningConfig::dummy(),
                ),
            }
        }
    }

    impl Dummy for CardanoTransactionsSigningConfig {
        /// Return a dummy [CardanoTransactionsSigningConfig] (test-only).
        fn dummy() -> Self {
            Self {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(15),
            }
        }
    }

    impl Dummy for CardanoBlocksTransactionsSigningConfig {
        /// Return a dummy [CardanoBlocksTransactionsSigningConfig] (test-only).
        fn dummy() -> Self {
            Self {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(15),
            }
        }
    }

    impl Dummy for MkSetProof<CardanoBlock> {
        fn dummy() -> Self {
            let blocks = [
                CardanoBlock::new("block_hash-10", BlockNumber(10), SlotNumber(15)),
                CardanoBlock::new("block_hash-11", BlockNumber(11), SlotNumber(16)),
                CardanoBlock::new("block_hash-20", BlockNumber(20), SlotNumber(25)),
            ];
            Self::from_leaves::<MKTreeStoreInMemory>(&blocks).unwrap()
        }
    }

    impl Dummy for MkSetProof<CardanoTransaction> {
        fn dummy() -> Self {
            let transactions = [
                CardanoTransaction::new(
                    "tx_hash-1",
                    BlockNumber(10),
                    SlotNumber(15),
                    "block_hash-10",
                ),
                CardanoTransaction::new(
                    "tx_hash-2",
                    BlockNumber(11),
                    SlotNumber(16),
                    "block_hash-11",
                ),
                CardanoTransaction::new(
                    "tx_hash-3",
                    BlockNumber(15),
                    SlotNumber(25),
                    "block_hash-15",
                ),
            ];
            Self::from_leaves::<MKTreeStoreInMemory>(&transactions).unwrap()
        }
    }

    impl Dummy for SignedEntityType {
        /// Return a dummy [SignedEntityType] (test-only).
        fn dummy() -> Self {
            Self::MithrilStakeDistribution(Epoch(5))
        }
    }

    impl Dummy for SupportedEra {
        /// Return a dummy [SupportedEra] (test-only).
        fn dummy() -> Self {
            Self::eras().first().unwrap().to_owned()
        }
    }

    impl Dummy for TimePoint {
        /// Return a dummy [TimePoint] (test-only).
        fn dummy() -> Self {
            Self::new(10, 100, ChainPoint::dummy())
        }
    }

    impl Dummy for ClientError {
        /// Return a dummy [ClientError] (test-only).
        fn dummy() -> Self {
            Self::new("error", "error message")
        }
    }

    impl Dummy for ServerError {
        /// Return a dummy [ServerError] (test-only).
        fn dummy() -> Self {
            Self::new("error")
        }
    }
}

mod messages {
    use std::collections::BTreeSet;

    use chrono::Duration;

    use mithril_stm::AggregateSignatureType;

    use crate::crypto_helper::KesEvolutions;
    use crate::entities::{
        AncillaryLocation, BlockNumber, BlockNumberOffset, CardanoBlock,
        CardanoBlocksTransactionsSigningConfig, CardanoDbBeacon, CardanoTransaction,
        CardanoTransactionsSetProof, CardanoTransactionsSigningConfig, CompressionAlgorithm,
        DigestLocation, Epoch, ImmutablesLocation, MkSetProof, MultiFilesUri, ProtocolMessage,
        ProtocolMessagePartKey, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, StakeDistribution, StakeDistributionParty, SupportedEra,
        TemplateUri,
    };
    use crate::messages::*;

    use super::*;

    impl Dummy for CardanoTransactionsSetProofMessagePart {
        /// Return a dummy [CardanoTransactionsSetProofMessagePart] (test-only).
        fn dummy() -> Self {
            CardanoTransactionsSetProof::dummy().try_into().unwrap()
        }
    }

    impl Dummy for MkSetProofMessagePart<CardanoBlockMessagePart> {
        /// Return a dummy [`MkSetProofMessagePart<CardanoBlockMessagePart>`] (test-only).
        fn dummy() -> Self {
            MkSetProof::<CardanoBlock>::dummy().try_into().unwrap()
        }
    }

    impl Dummy for MkSetProofMessagePart<CardanoTransactionMessagePart> {
        /// Return a dummy [`MkSetProofMessagePart<CardanoTransactionMessagePart>`] (test-only).
        fn dummy() -> Self {
            MkSetProof::<CardanoTransaction>::dummy().try_into().unwrap()
        }
    }

    impl Dummy for CardanoBlocksProofsMessage {
        /// Return a dummy [CardanoBlocksProofsMessage] (test-only).
        fn dummy() -> Self {
            CardanoBlocksProofsMessage::new(
                "cert-hash-123",
                Some(MkSetProofMessagePart::dummy()),
                vec![
                    "non-certified-block-1".to_string(),
                    "non-certified-block-2".to_string(),
                ],
                BlockNumber(100),
                BlockNumberOffset(15),
            )
        }
    }

    impl Dummy for CardanoTransactionsProofsV2Message {
        /// Return a dummy [CardanoTransactionsProofsV2Message] (test-only).
        fn dummy() -> Self {
            CardanoTransactionsProofsV2Message::new(
                "cert-hash-123",
                Some(MkSetProofMessagePart::dummy()),
                vec!["non-certified-tx-1".to_string(), "non-certified-tx-2".to_string()],
                BlockNumber(100),
                BlockNumberOffset(15),
            )
        }
    }

    impl Dummy for CertificateMetadataMessagePart {
        /// Return a dummy [CertificateMetadataMessagePart] (test-only).
        fn dummy() -> Self {
            let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47Z")
                .unwrap()
                .with_timezone(&Utc);

            Self {
                network: "testnet".to_string(),
                protocol_version: "0.1.0".to_string(),
                protocol_parameters: ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at: initiated_at + Duration::try_seconds(100).unwrap(),
                signers: vec![
                    StakeDistributionParty {
                        party_id: "1".to_string(),
                        stake: 10,
                    },
                    StakeDistributionParty {
                        party_id: "2".to_string(),
                        stake: 20,
                    },
                ],
            }
        }
    }

    impl Dummy for SignerWithStakeMessagePart {
        /// Return a dummy [SignerWithStakeMessagePart] (test-only).
        fn dummy() -> Self {
            Self {
                party_id: "pool1m8crhnqj5k2kyszf5j2scshupystyxc887zdfrpzh6ty6eun4fx".to_string(),
                verification_key_for_concatenation: fake_keys::signer_verification_key()[0]
                    .to_string(),
                verification_key_signature_for_concatenation: Some(
                    fake_keys::signer_verification_key_signature()[0].to_string(),
                ),
                operational_certificate: Some(fake_keys::operational_certificate()[0].to_string()),
                kes_evolutions: Some(KesEvolutions(6)),
                stake: 234,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
            }
        }
    }

    impl Dummy for SignerMessagePart {
        /// Return a dummy [SignerMessagePart] (test-only).
        fn dummy() -> Self {
            Self {
                party_id: "pool1m8crhnqj5k2kyszf5j2scshupystyxc887zdfrpzh6ty6eun4fx".to_string(),
                verification_key_for_concatenation: fake_keys::signer_verification_key()[0]
                    .to_string(),
                verification_key_signature_for_concatenation: Some(
                    fake_keys::signer_verification_key_signature()[0].to_string(),
                ),
                operational_certificate: Some(fake_keys::operational_certificate()[0].to_string()),
                kes_evolutions: Some(KesEvolutions(6)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
            }
        }
    }

    impl Dummy for AggregatorFeaturesMessage {
        /// Return a dummy [AggregatorFeaturesMessage] (test-only).
        fn dummy() -> Self {
            AggregatorFeaturesMessage {
                open_api_version: "0.0.1".to_string(),
                documentation_url: "https://example.com".to_string(),
                capabilities: AggregatorCapabilities {
                    signed_entity_types: BTreeSet::from([
                        SignedEntityTypeDiscriminants::MithrilStakeDistribution.into(),
                    ]),
                    aggregate_signature_type: AggregateSignatureType::Concatenation,
                    cardano_transactions_prover: None,
                },
            }
        }
    }

    impl Dummy for AggregatorStatusMessage {
        /// Return a dummy [AggregatorStatusMessage] (test-only).
        fn dummy() -> Self {
            AggregatorStatusMessage {
                epoch: Epoch(10),
                cardano_era: "conway".to_string(),
                cardano_network: "devnet".to_string(),
                mithril_era: SupportedEra::Pythagoras,
                cardano_node_version: "10.4.1".to_string(),
                aggregator_node_version: "0.6.24".to_string(),
                protocol_parameters: ProtocolParameters::new(1000, 100, 0.123),
                next_protocol_parameters: ProtocolParameters::new(2000, 200, 0.321),
                total_signers: 10,
                total_next_signers: 15,
                total_stakes_signers: 100_000,
                total_next_stakes_signers: 150_000,
                total_cardano_spo: 100,
                total_cardano_stake: 1_000_000,
            }
        }
    }

    impl Dummy for CardanoDatabaseSnapshotMessage {
        /// Return a dummy [CardanoDatabaseSnapshotMessage] (test-only).
        fn dummy() -> Self {
            Self {
                hash: "d4071d518a3ace0f6c04a9c0745b9e9560e3e2af1b373bafc4e0398423e9abfb"
                    .to_string(),
                merkle_root: "c8224920b9f5ad7377594eb8a15f34f08eb3103cc5241d57cafc5638403ec7c6"
                    .to_string(),
                network: "preview".to_string(),
                beacon: CardanoDbBeacon {
                    epoch: Epoch(123),
                    immutable_file_number: 2345,
                },
                certificate_hash:
                    "f6c01b373bafc4e039844071d5da3ace4a9c0745b9e9560e3e2af01823e9abfb".to_string(),
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
                    average_size_uncompressed: 512,
                    locations: vec![
                        ImmutablesLocation::CloudStorage {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "https://host-1/immutables-2".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                        ImmutablesLocation::CloudStorage {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "https://host-2/immutables-2".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                    ],
                },
                ancillary: AncillaryMessagePart {
                    size_uncompressed: 2048,
                    locations: vec![AncillaryLocation::CloudStorage {
                        uri: "https://host-1/ancillary-3".to_string(),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },
                cardano_node_version: "0.0.1".to_string(),
            }
        }
    }

    impl Dummy for CardanoDatabaseDigestListItemMessage {
        /// Return a dummy [CardanoDatabaseDigestListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                immutable_file_name: "06685.chunk".to_string(),
                digest: "0af556ab2620dd9363bf76963a231abe8948a500ea6be31b131d87907ab09b1e"
                    .to_string(),
            }
        }
    }

    impl Dummy for CardanoDatabaseImmutableFilesRestoredMessage {
        /// Return a dummy [CardanoDatabaseImmutableFilesRestoredMessage] (test-only).
        fn dummy() -> Self {
            Self {
                nb_immutable_files: 34,
            }
        }
    }

    impl Dummy for CardanoDatabaseSnapshotListItemMessage {
        /// Return a dummy [CardanoDatabaseSnapshotListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                hash: "d4071d518a3ace0f6c04a9c0745b9e9560e3e2af1b373bafc4e0398423e9abfb"
                    .to_string(),
                merkle_root: "c8224920b9f5ad7377594eb8a15f34f08eb3103cc5241d57cafc5638403ec7c6"
                    .to_string(),
                beacon: CardanoDbBeacon {
                    epoch: Epoch(123),
                    immutable_file_number: 2345,
                },
                certificate_hash:
                    "f6c01b373bafc4e039844071d5da3ace4a9c0745b9e9560e3e2af01823e9abfb".to_string(),
                total_db_size_uncompressed: 800796318,
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
                cardano_node_version: "0.0.1".to_string(),
            }
        }
    }

    impl Dummy for CardanoStakeDistributionMessage {
        /// Return a dummy [CardanoStakeDistributionMessage] (test-only).
        fn dummy() -> Self {
            Self {
                epoch: Epoch(1),
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                stake_distribution: StakeDistribution::from([("pool-123".to_string(), 1000)]),
                created_at: DateTime::parse_from_rfc3339("2024-07-29T16:15:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CardanoStakeDistributionListItemMessage {
        /// Return a dummy [CardanoStakeDistributionListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                epoch: Epoch(1),
                hash: "hash-123".to_string(),
                certificate_hash: "certificate-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2024-07-29T16:15:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CardanoTransactionSnapshotMessage {
        /// Return a dummy [CardanoTransactionSnapshotMessage] (test-only).
        fn dummy() -> Self {
            Self {
                merkle_root: "mkroot-123".to_string(),
                epoch: Epoch(10),
                block_number: BlockNumber(100),
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CardanoTransactionSnapshotListItemMessage {
        /// Return a dummy [CardanoTransactionSnapshotListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                merkle_root: "mkroot-123".to_string(),
                epoch: Epoch(10),
                block_number: BlockNumber(100),
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CardanoBlocksTransactionsSnapshotMessage {
        /// Return a dummy [CardanoBlocksTransactionsSnapshotMessage] (test-only).
        fn dummy() -> Self {
            Self {
                merkle_root: "mkroot-123".to_string(),
                epoch: Epoch(10),
                block_number_signed: BlockNumber(100),
                block_number_tip: BlockNumber(115),
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CardanoBlocksTransactionsSnapshotListItemMessage {
        /// Return a dummy [CardanoBlocksTransactionsSnapshotListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                merkle_root: "mkroot-123".to_string(),
                epoch: Epoch(10),
                block_number_signed: BlockNumber(100),
                block_number_tip: BlockNumber(115),
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for CertificateMessage {
        /// Return a dummy [CertificateMessage] (test-only).
        fn dummy() -> Self {
            let mut protocol_message = ProtocolMessage::new();
            protocol_message.set_message_part(
                ProtocolMessagePartKey::SnapshotDigest,
                "snapshot-digest-123".to_string(),
            );
            protocol_message.set_message_part(
                ProtocolMessagePartKey::NextAggregateVerificationKey,
                fake_keys::aggregate_verification_key_for_concatenation()[1].to_owned(),
            );
            let epoch = Epoch(10);

            Self {
                hash: "hash".to_string(),
                previous_hash: "previous_hash".to_string(),
                epoch,
                signed_entity_type: SignedEntityType::MithrilStakeDistribution(epoch).into(),
                metadata: CertificateMetadataMessagePart::dummy(),
                protocol_message: protocol_message.clone(),
                signed_message: "signed_message".to_string(),
                aggregate_verification_key:
                    fake_keys::aggregate_verification_key_for_concatenation()[0].to_owned(),
                #[cfg(feature = "future_snark")]
                aggregate_verification_key_snark: None,
                ancillary_prover_data: None,
                ancillary_verifier_data: None,
                multi_signature: fake_keys::multi_signature()[0].to_owned(),
                genesis_signature: String::new(),
                #[cfg(feature = "future_snark")]
                genesis_schnorr_signature: String::new(),
            }
        }
    }

    impl Dummy for CertificateListItemMessage {
        /// Return a dummy [CertificateListItemMessage] (test-only).
        fn dummy() -> Self {
            let mut protocol_message = ProtocolMessage::new();
            protocol_message.set_message_part(
                ProtocolMessagePartKey::SnapshotDigest,
                "snapshot-digest-123".to_string(),
            );
            protocol_message.set_message_part(
                ProtocolMessagePartKey::NextAggregateVerificationKey,
                "next-avk-123".to_string(),
            );
            let epoch = Epoch(10);

            Self {
                hash: "hash".to_string(),
                previous_hash: "previous_hash".to_string(),
                epoch,
                signed_entity_type: SignedEntityType::MithrilStakeDistribution(epoch).into(),
                metadata: CertificateListItemMessageMetadata {
                    network: "testnet".to_string(),
                    protocol_version: "0.1.0".to_string(),
                    protocol_parameters: ProtocolParameters::new(1000, 100, 0.123),
                    initiated_at: DateTime::parse_from_rfc3339("2024-02-12T13:11:47Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    sealed_at: DateTime::parse_from_rfc3339("2024-02-12T13:12:57Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    total_signers: 2,
                },
                protocol_message: protocol_message.clone(),
                signed_message: "signed_message".to_string(),
                aggregate_verification_key: "aggregate_verification_key".to_string(),
            }
        }
    }

    impl Dummy for EpochSettingsMessage {
        /// Return a dummy [EpochSettingsMessage] (test-only).
        fn dummy() -> Self {
            #[allow(deprecated)]
            Self {
                epoch: Epoch(10),
                signer_registration_protocol_parameters: Some(ProtocolParameters {
                    k: 5,
                    m: 100,
                    phi_f: 0.65,
                }),
                current_signers: [SignerMessagePart::dummy()].to_vec(),
                next_signers: [SignerMessagePart::dummy()].to_vec(),
                cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
            }
        }
    }

    impl Dummy for ProtocolConfigurationMessage {
        /// Return a dummy [ProtocolConfigurationMessage] (test-only).
        fn dummy() -> Self {
            Self {
                protocol_parameters: ProtocolParameters {
                    k: 5,
                    m: 100,
                    phi_f: 0.65,
                },
                cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions_signing_config: Some(
                    CardanoBlocksTransactionsSigningConfig::dummy(),
                ),
                available_signed_entity_types: SignedEntityTypeDiscriminantsMessage::all_known(),
            }
        }
    }

    impl Dummy for MithrilStakeDistributionMessage {
        /// Return a dummy [MithrilStakeDistributionMessage] (test-only).
        fn dummy() -> Self {
            Self {
                epoch: Epoch(1),
                signers_with_stake: vec![SignerWithStakeMessagePart::dummy()],
                hash: "hash-123".to_string(),
                certificate_hash: "cert-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
                protocol_parameters: fake_data::protocol_parameters(),
            }
        }
    }

    impl Dummy for MithrilStakeDistributionListItemMessage {
        /// Return a dummy [MithrilStakeDistributionListItemMessage] (test-only).
        fn dummy() -> Self {
            Self {
                epoch: Epoch(1),
                hash: "hash-123".to_string(),
                certificate_hash: "certificate-hash-123".to_string(),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for RegisterSignatureMessageHttp {
        /// Return a dummy [RegisterSignatureMessageHttp] (test-only).
        fn dummy() -> Self {
            use crate::entities::Epoch;
            Self {
                signed_entity_type: SignedEntityType::MithrilStakeDistribution(Epoch(5)).into(),
                party_id: "party_id".to_string(),
                signature: fake_keys::single_signature()[0].to_string(),
                won_indexes: vec![1, 3],
                signed_message: "6a7e737c312972d2346b65ac3075696e04286d046dddaf8004121e3d5e27cc0d"
                    .to_string(),
            }
        }
    }

    impl Dummy for RegisterSignatureMessageDmq {
        /// Return a dummy [RegisterSignatureMessageDmq] (test-only).
        fn dummy() -> Self {
            use crate::entities::Epoch;
            Self {
                signed_entity_type: SignedEntityType::MithrilStakeDistribution(Epoch(5)).into(),
                signature: fake_keys::single_signature()[0].try_into().unwrap(),
            }
        }
    }

    impl Dummy for RegisterSignerMessage {
        /// Return a dummy [RegisterSignerMessage] (test-only).
        fn dummy() -> Self {
            Self {
                epoch: Epoch(1),
                party_id: "pool1m8crhnqj5k2kyszf5j2scshupystyxc887zdfrpzh6ty6eun4fx".to_string(),
                verification_key_for_concatenation: fake_keys::signer_verification_key()[0]
                    .to_string(),
                verification_key_signature_for_concatenation: Some(
                    fake_keys::signer_verification_key_signature()[0].to_string(),
                ),
                operational_certificate: Some(fake_keys::operational_certificate()[0].to_string()),
                kes_evolutions: Some(KesEvolutions(6)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
            }
        }
    }
}

mod signable_builder {
    use crate::entities::{
        CardanoBlocksTransactionsSnapshot, CardanoStakeDistribution, CardanoTransactionsSnapshot,
        Epoch, MithrilStakeDistribution, SignedEntityType,
    };
    use crate::signable_builder::SignedEntity;

    use super::*;

    impl Dummy for SignedEntity<MithrilStakeDistribution> {
        /// Create a dummy [SignedEntity] for [MithrilStakeDistribution] entity
        fn dummy() -> Self {
            SignedEntity {
                signed_entity_id: "mithril-stake-distribution-id-123".to_string(),
                signed_entity_type: SignedEntityType::MithrilStakeDistribution(Epoch(1)),
                certificate_id: "certificate-hash-123".to_string(),
                artifact: fake_data::mithril_stake_distribution(
                    Epoch(1),
                    fake_data::signers_with_stakes(5),
                ),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for SignedEntity<CardanoTransactionsSnapshot> {
        /// Create a dummy [SignedEntity] for [CardanoTransactionsSnapshot] entity
        fn dummy() -> Self {
            let block_number = crate::entities::BlockNumber(50);
            SignedEntity {
                signed_entity_id: "snapshot-id-123".to_string(),
                signed_entity_type: SignedEntityType::CardanoTransactions(Epoch(5), block_number),
                certificate_id: "certificate-hash-123".to_string(),
                artifact: CardanoTransactionsSnapshot::new("mkroot123".to_string(), block_number),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for SignedEntity<CardanoBlocksTransactionsSnapshot> {
        /// Create a dummy [SignedEntity] for [CardanoBlocksTransactionsSnapshot] entity
        fn dummy() -> Self {
            let block_number = crate::entities::BlockNumber(50);
            let block_number_offset = crate::entities::BlockNumberOffset(15);
            SignedEntity {
                signed_entity_id: "snapshot-id-123".to_string(),
                signed_entity_type: SignedEntityType::CardanoBlocksTransactions(
                    Epoch(5),
                    block_number,
                    block_number_offset,
                ),
                certificate_id: "certificate-hash-123".to_string(),
                artifact: fake_data::cardano_blocks_transactions_snapshot(
                    block_number,
                    block_number_offset,
                ),
                created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }

    impl Dummy for SignedEntity<CardanoStakeDistribution> {
        /// Create a dummy [SignedEntity] for [CardanoStakeDistribution] entity
        fn dummy() -> Self {
            SignedEntity {
                signed_entity_id: "cardano-stake-distribution-id-123".to_string(),
                signed_entity_type: SignedEntityType::CardanoStakeDistribution(Epoch(1)),
                certificate_id: "certificate-hash-123".to_string(),
                artifact: fake_data::cardano_stake_distribution(Epoch(1)),
                created_at: DateTime::parse_from_rfc3339("2024-07-29T16:15:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
    }
}
