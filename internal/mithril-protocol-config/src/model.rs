//! Model definitions for Mithril Protocol Configuration.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use mithril_common::{
    entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
        ProtocolParameters, SignedEntityTypeDiscriminants,
    },
    messages::{ProtocolConfigurationMessage, SignedEntityTypeDiscriminantsMessage},
};

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]

/// Custom configuration for the signed entity types
pub struct SignedEntityTypeConfiguration {
    /// Signing configuration for Cardano transactions
    pub cardano_transactions: Option<CardanoTransactionsSigningConfig>,

    /// Signing configuration for Cardano blocks and transactions
    pub cardano_blocks_transactions: Option<CardanoBlocksTransactionsSigningConfig>,
}

/// A Mithril network configuration
#[derive(PartialEq, Clone, Debug)]
pub struct MithrilNetworkConfiguration {
    /// Epoch
    pub epoch: Epoch,

    /// Configuration for aggregation
    pub configuration_for_aggregation: MithrilNetworkConfigurationForEpoch,

    /// Configuration for next aggregation
    pub configuration_for_next_aggregation: MithrilNetworkConfigurationForEpoch,

    /// Configuration for registration
    pub configuration_for_registration: MithrilNetworkConfigurationForEpoch,
}

//A epoch configuration
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
/// A network configuration available for an epoch
pub struct MithrilNetworkConfigurationForEpoch {
    /// Cryptographic protocol parameters (`k`, `m` and `phi_f`)
    pub protocol_parameters: ProtocolParameters,

    /// List of available types of certifications
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,

    /// Custom configurations for signed entity types
    pub signed_entity_types_config: SignedEntityTypeConfiguration,
}

impl From<ProtocolConfigurationMessage> for MithrilNetworkConfigurationForEpoch {
    fn from(message: ProtocolConfigurationMessage) -> Self {
        MithrilNetworkConfigurationForEpoch {
            protocol_parameters: message.protocol_parameters,
            enabled_signed_entity_types:
                SignedEntityTypeDiscriminantsMessage::into_known_discriminants(
                    message.available_signed_entity_types,
                ),
            signed_entity_types_config: SignedEntityTypeConfiguration {
                cardano_transactions: message.cardano_transactions_signing_config,
                cardano_blocks_transactions: message.cardano_blocks_transactions_signing_config,
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use mithril_common::messages::{
        DiscontinuedSignedEntityType, SignedEntityTypeDiscriminantsMessage,
    };
    use mithril_common::test::double::Dummy;

    use super::*;

    #[test]
    fn convert_from_protocol_conf_message_to_network_config_remove_unknown_and_discontinued_discriminants()
     {
        let message = ProtocolConfigurationMessage {
            available_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminantsMessage::Known(
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                ),
                SignedEntityTypeDiscriminantsMessage::Discontinued(
                    DiscontinuedSignedEntityType::CardanoImmutableFilesFull,
                ),
                SignedEntityTypeDiscriminantsMessage::Unknown,
            ]),
            ..Dummy::dummy()
        };
        let network_config = MithrilNetworkConfigurationForEpoch::from(message);

        assert_eq!(
            BTreeSet::from([SignedEntityTypeDiscriminants::MithrilStakeDistribution]),
            network_config.enabled_signed_entity_types,
        );
    }
}
