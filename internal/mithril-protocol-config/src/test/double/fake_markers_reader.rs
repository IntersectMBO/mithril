use std::{
    collections::{BTreeMap, BTreeSet},
    sync::RwLock,
};

use async_trait::async_trait;
use mithril_common::{
    StdResult,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
    },
};

use crate::{
    interface::ProtocolConfigurationMarkersReader,
    model::{ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch},
};

/// Dummy reader is intended to be used in a test environment (end to end test)
/// to simulate retrieving protocol configurations
pub struct FakeProtocolConfigurationMarkersReader {
    markers: RwLock<ConfigurationResolverFromMarkers>,
}

impl FakeProtocolConfigurationMarkersReader {
    /// Create a new instance directly from markers
    pub fn from_markers(markers: ConfigurationResolverFromMarkers) -> Self {
        let myself = Self::default();
        myself.set_markers(markers);

        myself
    }

    /// Tells what markers should be sent back by the reader.
    pub fn set_markers(&self, markers: ConfigurationResolverFromMarkers) {
        let mut my_markers = self.markers.write().unwrap();
        *my_markers = markers;
    }

    /// Instantiate a default ProtocolConfigurationMarkersReader with given ProtocolParameters and default values
    pub fn default_with_protocol_parameters(protocol_parameters: ProtocolParameters) -> Self {
        let markers = BTreeMap::from([(
            Epoch(0),
            ProtocolConfigurationForEpoch {
                protocol_parameters,
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoDatabase,
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ]),
                cardano_transactions: Some(CardanoTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(120),
                    step: BlockNumber(15),
                }),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(120),
                    step: BlockNumber(15),
                }),
            },
        )]);

        FakeProtocolConfigurationMarkersReader {
            markers: RwLock::new(ConfigurationResolverFromMarkers::new(markers)),
        }
    }
}

impl Default for FakeProtocolConfigurationMarkersReader {
    fn default() -> Self {
        let markers = BTreeMap::from([(
            Epoch(0),
            ProtocolConfigurationForEpoch {
                protocol_parameters: ProtocolParameters {
                    k: 5,
                    m: 100,
                    phi_f: 0.95,
                },
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoDatabase,
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ]),
                cardano_transactions: Some(CardanoTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(120),
                    step: BlockNumber(15),
                }),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(120),
                    step: BlockNumber(15),
                }),
            },
        )]);

        FakeProtocolConfigurationMarkersReader {
            markers: RwLock::new(ConfigurationResolverFromMarkers::new(markers)),
        }
    }
}

#[async_trait]
impl ProtocolConfigurationMarkersReader for FakeProtocolConfigurationMarkersReader {
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers> {
        let markers = self.markers.read().unwrap();

        Ok(markers.clone())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::Dummy;

    use super::*;

    #[tokio::test]
    async fn empty_dummy_reader() {
        let reader = FakeProtocolConfigurationMarkersReader::default();
        let markers = ConfigurationResolverFromMarkers::new_empty();
        reader.set_markers(markers);

        let result = reader
            .read_configuration_markers()
            .await
            .expect("dummy reader shall not fail reading");

        assert!(result.markers.is_empty());
    }

    #[tokio::test]
    async fn dummy_reader_output() {
        let markers = ConfigurationResolverFromMarkers::dummy();
        let reader = FakeProtocolConfigurationMarkersReader::default();
        reader.set_markers(markers.clone());

        assert_eq!(
            markers,
            reader
                .read_configuration_markers()
                .await
                .expect("dummy reader shall not fail reading")
        );
    }
}
