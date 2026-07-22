use std::collections::HashMap;

use anyhow::Context;
use mithril_cardano_node_chain::entities::{TxDatumBuilder, TxDatumFieldValue};
use mithril_common::{
    CardanoNetwork, StdResult, crypto_helper::ProtocolConfigurationMarkersSigner, entities::Epoch,
};
use mithril_protocol_config::{
    ProtocolConfigurationForEpoch, ProtocolConfigurationMarker,
    adapters::ProtocolConfigurationMarkersPayloadCardanoChain,
};
use slog::Logger;

use crate::{
    commands::HumanReadableProtocolConfiguration,
    dependency_injection::ProtocolConfigurationCommandDependenciesContainer,
};

type ProtocolConfigurationToolsResult<R> = StdResult<R>;

/// Configuration for the protocol configuration tools.
pub struct ProtocolConfigurationToolsConfiguration {
    /// Cardano network.
    pub network: CardanoNetwork,

    /// Current epoch.
    pub epoch: Epoch,

    /// On chain configurations by Epoch.
    pub on_chain_configurations: HashMap<Epoch, ProtocolConfigurationForEpoch>,
}

pub struct ProtocolConfigurationTools {
    configuration: ProtocolConfigurationToolsConfiguration,
    logger: Logger,
}

impl ProtocolConfigurationTools {
    pub fn new(configuration: ProtocolConfigurationToolsConfiguration, logger: Logger) -> Self {
        Self {
            configuration,
            logger,
        }
    }

    pub async fn from_dependencies(
        dependencies: ProtocolConfigurationCommandDependenciesContainer,
    ) -> StdResult<Self> {
        let epoch = dependencies
            .chain_observer
            .get_current_epoch()
            .await?
            .with_context(|| "Chain observer can not retrieve current epoch")?;

        let on_chain_configurations = dependencies
            .protocol_configuration_reader
            .read_mithril_protocol_configurations()
            .await?;

        let configuration = ProtocolConfigurationToolsConfiguration {
            network: dependencies.network,
            epoch,
            on_chain_configurations,
        };

        Ok(Self::new(configuration, dependencies.logger))
    }

    // /// Verify if configuration have greater Epoch (with a offset) than configuration on chain
    // pub async fn verify_configuration_against_production(
    //     &self,
    //     configurations: Vec<HumanReadableProtocolConfiguration>,
    // ) -> StdResult<()> {
    //     let production_configurations = self.adapter.read_mithril_protocol_configurations().await?;
    //     production_configurations
    //         .keys()
    //         .collect::<Vec<Epoch>>()
    //         .contains(&Epoch(1));

    //     Ok(())
    // }

    /// Generate TxDatum for Protocol Configuration
    pub fn generate_tx_datum(
        &self,
        configurations: Vec<HumanReadableProtocolConfiguration>,
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

    use crate::test::TestLogger;

    use super::*;

    fn build_tools() -> ProtocolConfigurationTools {
        let configuration = ProtocolConfigurationToolsConfiguration {
            network: CardanoNetwork::TestNet(42),
            epoch: Epoch(30),
            on_chain_configurations: HashMap::new(),
        };
        ProtocolConfigurationTools::new(configuration, TestLogger::stdout())
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
