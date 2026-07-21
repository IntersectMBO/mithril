use mithril_cardano_node_chain::entities::{TxDatumBuilder, TxDatumFieldValue};
use mithril_common::{StdResult, crypto_helper::ProtocolConfigurationMarkersSigner};
use mithril_protocol_config::{
    ProtocolConfigurationForEpoch, ProtocolConfigurationMarker,
    adapters::ProtocolConfigurationMarkersPayloadCardanoChain,
};

use crate::commands::HumanReadableProtocolConfiguration;

type ProtocolConfigurationToolsResult<R> = StdResult<R>;
pub struct ProtocolConfigurationTools {}

impl ProtocolConfigurationTools {
    pub fn new() -> Self {
        Self {}
    }

    /// Generate TxDatum for Protocol Configuration
    pub fn generate_tx_datum(
        &self,
        configurations: Vec<HumanReadableProtocolConfiguration>, // TODO Add a type VerifiedProtocolConfiguration ?
        protocol_configuration_markers_signer: &ProtocolConfigurationMarkersSigner,
    ) -> ProtocolConfigurationToolsResult<String> {
        let mut markers: Vec<ProtocolConfigurationMarker> = Vec::new();
        for configuration in configurations {
            let protocol_configuration_for_epoch: ProtocolConfigurationForEpoch =
                configuration.clone().into();
            let marker: ProtocolConfigurationMarker = ProtocolConfigurationMarker::new(
                configuration.epoch,
                protocol_configuration_for_epoch.to_cbor()?,
            );
            markers.push(marker);
        }
        let signed_markers_payload = ProtocolConfigurationMarkersPayloadCardanoChain::new(markers)
            .sign(protocol_configuration_markers_signer)?;

        //TODO add a type signedPayload to ensure both marker and signature is here

        let tx_datum = TxDatumBuilder::new()
            .add_field(TxDatumFieldValue::Bytes(
                signed_markers_payload.to_json_hex()?,
            ))
            .build()?;
        Ok(tx_datum.0)
    }
}

impl From<HumanReadableProtocolConfiguration> for ProtocolConfigurationForEpoch {
    fn from(config: HumanReadableProtocolConfiguration) -> Self {
        ProtocolConfigurationForEpoch {
            protocol_parameters: config.protocol_parameters,
            enabled_signed_entity_types: config.enabled_signed_entity_types,
            cardano_transactions: config.cardano_transaction_signing_config,
            cardano_blocks_transactions: config.cardano_blocks_transactions_signing_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
    };
    use std::collections::BTreeSet;

    use super::*;

    fn build_tools() -> ProtocolConfigurationTools {
        ProtocolConfigurationTools::new()
    }

    #[test]
    fn from_human_readable_protocol_configuration_converts_to_protocol_configuration_for_epoch() {
        let human_readable_conf = HumanReadableProtocolConfiguration {
            epoch: Epoch(42),
            protocol_parameters: ProtocolParameters {
                k: 9,
                m: 77,
                phi_f: 0.5,
            },
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(150),
                    step: BlockNumber(20),
                },
            ),
        };

        let expected_protocol_configuration_for_epoch = ProtocolConfigurationForEpoch {
            protocol_parameters: ProtocolParameters {
                k: 9,
                m: 77,
                phi_f: 0.5,
            },
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_transactions: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(150),
                step: BlockNumber(20),
            }),
        };

        assert_eq!(
            ProtocolConfigurationForEpoch::from(human_readable_conf),
            expected_protocol_configuration_for_epoch
        );
    }

    #[test]
    fn generate_tx_datum_ok() {
        let configurations = vec![HumanReadableProtocolConfiguration {
            epoch: Epoch(42),
            protocol_parameters: ProtocolParameters {
                k: 9,
                m: 77,
                phi_f: 0.5,
            },
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions_signing_config: None,
        }];
        let signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let tools = build_tools();
        tools
            .generate_tx_datum(configurations, &signer)
            .expect("generate_tx_datum should not fail");
    }
}
