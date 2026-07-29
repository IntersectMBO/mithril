use std::collections::{BTreeMap, BTreeSet};

use mithril_common::{
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
    },
    messages::SignedEntityTypeDiscriminantsMessage,
    test::double::{Dummy, fake_data},
};

use crate::{
    cardano_chain::message::{
        CardanoBlocksTransactionsSigningConfigMessage, CardanoTransactionsSigningConfigMessage,
        ProtocolConfigurationForEpochMessage, ProtocolParametersMessage,
    },
    model::{
        ConfigurationComputerFromMarkers, MithrilNetworkConfiguration,
        MithrilNetworkConfigurationForEpoch, ProtocolConfigurationForEpoch,
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
    /// Return a dummy for [MithrilNetworkConfigurationForEpoch] (test-only).
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

impl Dummy for ConfigurationComputerFromMarkers {
    fn dummy() -> Self {
        let conf_a = ProtocolConfigurationForEpoch {
            protocol_parameters: ProtocolParameters {
                k: 1,
                m: 2,
                phi_f: 0.3,
            },
            ..Dummy::dummy()
        };
        let conf_b = ProtocolConfigurationForEpoch {
            protocol_parameters: ProtocolParameters {
                k: 4,
                m: 5,
                phi_f: 0.6,
            },
            ..Dummy::dummy()
        };
        let mut markers = BTreeMap::new();
        markers.insert(Epoch(42), conf_a);
        markers.insert(Epoch(53), conf_b);
        Self { markers }
    }
}

impl Dummy for ProtocolParametersMessage {
    fn dummy() -> Self {
        Self {
            k: 1,
            m: 2,
            phi_f: 0.3,
        }
    }
}

impl Dummy for CardanoTransactionsSigningConfigMessage {
    fn dummy() -> Self {
        Self {
            security_parameter: BlockNumberOffset(10),
            step: BlockNumber(5),
        }
    }
}

impl Dummy for CardanoBlocksTransactionsSigningConfigMessage {
    fn dummy() -> Self {
        Self {
            security_parameter: BlockNumberOffset(11),
            step: BlockNumber(7),
        }
    }
}

impl Dummy for ProtocolConfigurationForEpochMessage {
    fn dummy() -> Self {
        Self {
            protocol_parameters: Dummy::dummy(),
            enabled_signed_entity_types: SignedEntityTypeDiscriminantsMessage::all_known(),
            cardano_transactions: Some(Dummy::dummy()),
            cardano_blocks_transactions: Some(Dummy::dummy()),
        }
    }
}
