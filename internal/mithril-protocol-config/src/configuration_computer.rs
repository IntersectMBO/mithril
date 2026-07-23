//! //! Model definitions for ProtocolConfigurationReader.

use std::collections::BTreeMap;

use mithril_common::entities::Epoch;

use crate::ProtocolConfigurationForEpoch;

/// [ConfigurationComputerFromMarkers] containing markers by epoch
#[derive(PartialEq, Clone, Debug)]
pub struct ConfigurationComputerFromMarkers {
    /// BTreeMap assotiation of ProtocolConfigurationForEpoch to a coresponding Epoch
    pub markers: BTreeMap<Epoch, ProtocolConfigurationForEpoch>,
}

impl ConfigurationComputerFromMarkers {
    /// Create a new [ConfigurationComputerFromMarkers] with the given markers.
    pub fn new(markers: BTreeMap<Epoch, ProtocolConfigurationForEpoch>) -> Self {
        Self { markers }
    }

    /// retrieve configuration for given Epoch or fallback to last known configuration
    pub fn get_network_configuration(&self, epoch: Epoch) -> Option<ProtocolConfigurationForEpoch> {
        self.markers
            .range(..=epoch)
            .next_back()
            .map(|(_, marker)| marker.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mithril_common::{
        entities::{
            CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
            ProtocolParameters, SignedEntityTypeDiscriminants,
        },
        test::double::Dummy,
    };

    use crate::ProtocolConfigurationForEpoch;

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
    fn test_get_network_configuration_must_fallback_to_last_known_configuration_if_epoch_not_found()
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

        let configurations = ConfigurationComputerFromMarkers::new(markers);

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

        let configurations = ConfigurationComputerFromMarkers::new(markers);

        assert_eq!(configurations.get_network_configuration(Epoch(4)), None);
    }
}
