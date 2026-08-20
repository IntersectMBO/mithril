//! Helper to generate configurations for tests

use std::collections::BTreeSet;

use mithril_common::{
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, ProtocolParameters,
        SignedEntityTypeDiscriminants::{
            self, CardanoBlocksTransactions, CardanoDatabase, CardanoStakeDistribution,
            CardanoTransactions,
        },
    },
    messages::SignedEntityTypeDiscriminantsMessage,
};

use crate::{
    cardano_chain::message::{
        CardanoBlocksTransactionsSigningConfigMessage, CardanoTransactionsSigningConfigMessage,
        ProtocolConfigurationForEpochMessage, ProtocolParametersMessage,
    },
    model::ProtocolConfigurationForEpoch,
};

/// Instanciate a unique ProtocolConfigurationForEpochMessage based on char
pub fn generate_configuration_message(conf: char) -> ProtocolConfigurationForEpochMessage {
    ProtocolConfigurationForEpochMessage {
        protocol_parameters: ProtocolParametersMessage {
            k: conf as u64,
            m: conf as u64,
            phi_f: 1.2,
        },
        cardano_transactions: Some(CardanoTransactionsSigningConfigMessage {
            security_parameter: BlockNumberOffset(10),
            step: BlockNumber(20),
        }),
        cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfigMessage {
            security_parameter: BlockNumberOffset(30),
            step: BlockNumber(40),
        }),
        enabled_signed_entity_types: BTreeSet::from([
            SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
            SignedEntityTypeDiscriminantsMessage::Known(CardanoBlocksTransactions),
            SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
            SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
        ]),
    }
}

/// Instantiate a unique ProtocolConfigurationForEpoch based on char
pub fn generate_configuration(conf: char) -> ProtocolConfigurationForEpoch {
    ProtocolConfigurationForEpoch {
        protocol_parameters: ProtocolParameters {
            k: conf as u64,
            m: conf as u64,
            phi_f: 1.2,
        },
        cardano_transactions: Some(CardanoTransactionsSigningConfig {
            security_parameter: BlockNumberOffset(10),
            step: BlockNumber(20),
        }),
        cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
            security_parameter: BlockNumberOffset(30),
            step: BlockNumber(40),
        }),
        enabled_signed_entity_types: BTreeSet::from([
            SignedEntityTypeDiscriminants::CardanoTransactions,
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            SignedEntityTypeDiscriminants::CardanoDatabase,
            SignedEntityTypeDiscriminants::CardanoStakeDistribution,
        ]),
    }
}
