use std::collections::BTreeSet;

use mithril_common::{
    entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig,
        SignedEntityTypeDiscriminants,
    },
    test::double::{Dummy, fake_data},
};

use crate::{
    ProtocolConfigurationForEpoch,
    model::{
        MithrilNetworkConfiguration, MithrilNetworkConfigurationForEpoch,
        SignedEntityTypeConfiguration,
    },
};

impl Dummy for MithrilNetworkConfiguration {
    /// Return a dummy [MithrilNetworkConfiguration] (test-only).
    fn dummy() -> Self {
        let beacon = fake_data::beacon();

        Self {
            epoch: beacon.epoch,
            configuration_for_aggregation: MithrilNetworkConfigurationForEpoch::dummy(),
            configuration_for_next_aggregation: MithrilNetworkConfigurationForEpoch::dummy(),
            configuration_for_registration: MithrilNetworkConfigurationForEpoch::dummy(),
        }
    }
}

impl Dummy for MithrilNetworkConfigurationForEpoch {
    /// Return a dummy for [EpochConfiguration] (test-only).
    fn dummy() -> Self {
        Self {
            protocol_parameters: fake_data::protocol_parameters(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            signed_entity_types_config: SignedEntityTypeConfiguration {
                cardano_transactions: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig::dummy()),
            },
        }
    }
}

impl Dummy for ProtocolConfigurationForEpoch {
    /// Return a dummy for [ProtocolConfigurationForEpoch] (test-only).
    fn dummy() -> Self {
        Self {
            protocol_parameters: fake_data::protocol_parameters(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            ]),
            cardano_transactions: Some(CardanoTransactionsSigningConfig::dummy()),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig::dummy()),
        }
    }
}

impl Dummy for SignedEntityTypeConfiguration {
    /// Return a dummy [SignedEntityTypeConfiguration] (test-only).
    fn dummy() -> Self {
        Self {
            cardano_transactions: Some(CardanoTransactionsSigningConfig::dummy()),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig::dummy()),
        }
    }
}
