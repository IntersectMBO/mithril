use std::{
    collections::{BTreeMap, BTreeSet},
    sync::RwLock,
};

use anyhow::Context;
use async_trait::async_trait;
use mithril_common::{
    StdResult,
    crypto_helper::key_decode_hex,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
    },
};

use crate::{
    cardano_chain::message::ProtocolConfigurationForEpochMessage,
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

    /// Create a new instance with a single marker at epoch 0, from a JSON hex encoded [ProtocolConfigurationForEpochMessage]
    pub fn from_json_hex_marker_configuration(configuration: &str) -> StdResult<Self> {
        let configuration: ProtocolConfigurationForEpochMessage = key_decode_hex(configuration)
            .with_context(|| "Fake protocol configuration could not be decoded from JSON hex")?;
        let markers = BTreeMap::from([(Epoch(0), configuration.into())]);

        Ok(Self::from_markers(ConfigurationResolverFromMarkers::new(
            markers,
        )))
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
    use mithril_common::{crypto_helper::key_encode_hex, test::double::Dummy};

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

    mod from_json_hex_marker_configuration {
        use super::*;

        #[tokio::test]
        async fn reads_a_single_marker_at_epoch_zero_with_the_decoded_configuration() {
            let configuration = ProtocolConfigurationForEpochMessage::dummy();
            let reader =
                FakeProtocolConfigurationMarkersReader::from_json_hex_marker_configuration(
                    &key_encode_hex(&configuration).unwrap(),
                )
                .unwrap();

            let markers = reader.read_configuration_markers().await.unwrap();

            assert_eq!(
                ConfigurationResolverFromMarkers::new(BTreeMap::from([(
                    Epoch(0),
                    ProtocolConfigurationForEpoch::from(configuration)
                )])),
                markers
            );
        }

        #[test]
        fn fails_when_the_configuration_is_not_hex_encoded() {
            let result = FakeProtocolConfigurationMarkersReader::from_json_hex_marker_configuration(
                "not_hex",
            );

            assert!(result.is_err());
        }

        #[test]
        fn fails_when_the_decoded_json_is_not_a_single_configuration() {
            let configurations = vec![ProtocolConfigurationForEpochMessage::dummy()];

            let result = FakeProtocolConfigurationMarkersReader::from_json_hex_marker_configuration(
                &key_encode_hex(&configurations).unwrap(),
            );

            assert!(result.is_err());
        }
    }
}
