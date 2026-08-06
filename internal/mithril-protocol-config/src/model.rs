//! Model definitions for Mithril Protocol Configuration and ProtocolConfigurationMarkersReader

use std::collections::{BTreeMap, BTreeSet};

use mithril_common::{
    entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
        InconsistentSignedEntityConfigError, ProtocolParameters, SignedEntityConfigValidator,
        SignedEntityTypeDiscriminants,
    },
    messages::{ProtocolConfigurationMessage, SignedEntityTypeDiscriminantsMessage},
};

#[derive(PartialEq, Clone, Debug)]

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

/// A network configuration available for an epoch for MithrilNetworkConfigurationProvider
#[derive(PartialEq, Clone, Debug)]
pub struct MithrilNetworkConfigurationForEpoch {
    /// Cryptographic protocol parameters (`k`, `m` and `phi_f`)
    pub protocol_parameters: ProtocolParameters,

    /// List of available types of certifications
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,

    /// Custom configurations for signed entity types
    pub signed_entity_types_config: SignedEntityTypeConfiguration,
}

impl MithrilNetworkConfigurationForEpoch {
    /// Ensures signed-entity configuration is consistent
    /// and clean if needed `enabled_signed_entity_types` with the validated usable subset.
    pub(crate) fn ensure_consistency<F>(mut self, consistency_error_inspector: F) -> Self
    where
        F: FnOnce(&InconsistentSignedEntityConfigError),
    {
        if let Err(err) = SignedEntityConfigValidator::check_consistency(
            &self.enabled_signed_entity_types,
            &self.signed_entity_types_config.cardano_transactions,
            &self.signed_entity_types_config.cardano_blocks_transactions,
        ) {
            consistency_error_inspector(&err);
            self.enabled_signed_entity_types = err.usable_discriminants;
        }

        self
    }
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

/// A network configuration available for an epoch for ProtocolConfigurationMarkersReader
#[derive(PartialEq, Clone, Debug)]
pub struct ProtocolConfigurationForEpoch {
    /// Cryptographic protocol parameters (`k`, `m` and `phi_f`)
    pub protocol_parameters: ProtocolParameters,

    /// List of available types of certifications
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,

    /// Signing configuration for Cardano transactions
    pub cardano_transactions: Option<CardanoTransactionsSigningConfig>,

    /// Signing configuration for Cardano blocks and transactions
    pub cardano_blocks_transactions: Option<CardanoBlocksTransactionsSigningConfig>,
}

/// Configuration containing markers by epoch
#[derive(Default, PartialEq, Clone, Debug)]
pub struct ConfigurationResolverFromMarkers {
    /// BTreeMap association of ProtocolConfigurationForEpoch to a coresponding Epoch
    pub markers: BTreeMap<Epoch, ProtocolConfigurationForEpoch>,
}

impl ConfigurationResolverFromMarkers {
    /// Create a new instance with the given markers.
    pub fn new(markers: BTreeMap<Epoch, ProtocolConfigurationForEpoch>) -> Self {
        Self { markers }
    }

    /// resolve configuration for given Epoch
    pub fn get_network_configuration(&self, epoch: Epoch) -> Option<ProtocolConfigurationForEpoch> {
        self.markers
            .range(..=epoch)
            .next_back()
            .map(|(_, marker)| marker.clone())
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

    mod configuration_resolver_from_markers {

        use super::*;

        fn fake_config_for_epoch(epoch: Epoch) -> ProtocolConfigurationForEpoch {
            ProtocolConfigurationForEpoch {
                protocol_parameters: ProtocolParameters::new(*epoch, *epoch, 0.1),
                enabled_signed_entity_types: SignedEntityTypeDiscriminants::all(),
                cardano_transactions: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig::dummy()),
            }
        }

        #[derive(Debug)]
        struct TestCase {
            requested_epoch: Epoch,
            expected_conf_epoch: Epoch,
        }

        macro_rules! test_case {
            (
                requested: $requested_epoch:expr,
                expected: $expected_conf_epoch:expr
            ) => {
                TestCase {
                    requested_epoch: Epoch($requested_epoch),
                    expected_conf_epoch: Epoch($expected_conf_epoch),
                }
            };
        }

        #[test]
        fn get_network_configuration_falls_back_to_last_known_configuration_when_epoch_has_no_marker()
         {
            let markers = BTreeMap::from([
                (Epoch(2), fake_config_for_epoch(Epoch(2))),
                (Epoch(6), fake_config_for_epoch(Epoch(6))),
                (Epoch(10), fake_config_for_epoch(Epoch(10))),
            ]);

            fn test_cases() -> Vec<TestCase> {
                vec![
                    test_case!(requested: 3, expected: 2 ),
                    test_case!(requested: 5, expected: 2 ),
                    test_case!(requested: 6, expected: 6 ),
                    test_case!(requested: 7, expected: 6 ),
                    test_case!(requested: 9, expected: 6 ),
                    test_case!(requested: 10, expected: 10),
                    test_case!(requested: 11, expected: 10),
                    test_case!(requested: 12, expected: 10),
                ]
            }

            let configurations = ConfigurationResolverFromMarkers::new(markers);

            for test_case in test_cases() {
                assert_eq!(
                    configurations.get_network_configuration(test_case.requested_epoch),
                    Some(fake_config_for_epoch(test_case.expected_conf_epoch))
                );
            }
        }

        #[test]
        fn test_get_network_configuration_return_none_if_no_fallback_conf_is_available() {
            let markers = BTreeMap::from([
                (Epoch(6), fake_config_for_epoch(Epoch(6))),
                (Epoch(10), fake_config_for_epoch(Epoch(10))),
            ]);

            let configurations = ConfigurationResolverFromMarkers::new(markers);

            assert_eq!(configurations.get_network_configuration(Epoch(4)), None);
        }
    }
}
