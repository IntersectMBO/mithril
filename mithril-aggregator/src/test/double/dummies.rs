use std::collections::BTreeSet;

use chrono::Utc;
use uuid::Uuid;

use mithril_common::{
    entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
        ProtocolParameters, SignedEntityTypeDiscriminants,
    },
    test::double::{Dummy, fake_data},
};

use crate::commands::HumanReadableProtocolConfiguration;

mod record {
    use mithril_common::entities::{ProtocolMessage, SignedEntityType};

    use crate::database::record::{ImmutableFileDigestRecord, OpenMessageRecord};

    use super::*;

    impl Dummy for ImmutableFileDigestRecord {
        /// Create a dumb ImmutableFileDigestRecord instance mainly for test purposes
        fn dummy() -> Self {
            Self {
                immutable_file_name: "123.chunk".to_string(),
                digest: "dummy_digest".to_string(),
            }
        }
    }

    impl Dummy for OpenMessageRecord {
        /// Create a dumb OpenMessage instance mainly for test purposes
        fn dummy() -> Self {
            let beacon = fake_data::beacon();
            let epoch = beacon.epoch;
            let signed_entity_type = SignedEntityType::CardanoDatabase(beacon);

            Self {
                open_message_id: Uuid::parse_str("193d1442-e89b-43cf-9519-04d8db9a12ff").unwrap(),
                epoch,
                signed_entity_type,
                protocol_message: ProtocolMessage::new(),
                is_certified: false,
                is_expired: false,
                created_at: Utc::now(),
                expires_at: None,
            }
        }
    }
}

mod entities {
    use mithril_common::entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, ProtocolMessage,
        SignedEntityType,
    };

    use crate::entities::{AggregatorEpochSettings, LeaderAggregatorEpochSettings, OpenMessage};

    use super::*;

    impl Dummy for AggregatorEpochSettings {
        /// Create a dummy `AggregatorEpochSettings`
        fn dummy() -> Self {
            // Aggregator Epoch settings
            AggregatorEpochSettings {
                protocol_parameters: fake_data::protocol_parameters(),
                cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions_signing_config: Some(
                    CardanoBlocksTransactionsSigningConfig::dummy(),
                ),
            }
        }
    }

    impl Dummy for LeaderAggregatorEpochSettings {
        /// Create a dummy `LeaderAggregatorEpochSettings`
        fn dummy() -> Self {
            let beacon = fake_data::beacon();
            let signers = fake_data::signers(5);

            LeaderAggregatorEpochSettings {
                epoch: beacon.epoch,
                current_signers: signers[1..3].to_vec(),
                next_signers: signers[2..5].to_vec(),
            }
        }
    }

    impl Dummy for OpenMessage {
        fn dummy() -> Self {
            let beacon = fake_data::beacon();
            let epoch = beacon.epoch;
            let signed_entity_type = SignedEntityType::CardanoDatabase(beacon);

            Self {
                epoch,
                signed_entity_type,
                protocol_message: ProtocolMessage::new(),
                is_certified: false,
                is_expired: false,
                single_signatures: vec![
                    fake_data::single_signature(vec![1, 4, 5]),
                    fake_data::single_signature(vec![2, 3, 8]),
                ],
                created_at: Utc::now(),
                expires_at: None,
            }
        }
    }
}

impl Dummy for HumanReadableProtocolConfiguration {
    fn dummy() -> Self {
        HumanReadableProtocolConfiguration::new(
            Epoch(42),
            ProtocolParameters::new(10, 20, 0.123),
            Some(CardanoTransactionsSigningConfig::dummy()),
            Some(CardanoBlocksTransactionsSigningConfig::dummy()),
            BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoDatabase,
            ]),
        )
    }
}
