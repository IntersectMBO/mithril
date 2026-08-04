use std::collections::BTreeMap;

use anyhow::Context;
use mithril_cardano_node_chain::entities::{TxDatumBuilder, TxDatumFieldValue};
use mithril_common::{
    StdResult, crypto_helper::ProtocolConfigurationMarkersSigner, entities::Epoch,
    messages::SignedEntityTypeDiscriminantsMessage,
};

use mithril_protocol_config::{
    cardano_chain::{
        ProtocolConfigurationMarkersPayloadCardanoChain,
        message::{ProtocolConfigurationForEpochMessage, ProtocolConfigurationMarker},
    },
    model::{ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch},
};
use slog::{Logger, info, warn};
use thiserror::Error;

use crate::{
    commands::HumanReadableProtocolConfiguration,
    dependency_injection::ProtocolConfigurationCommandDependenciesContainer,
};

const EPOCH_OFFSET: u64 = 3;
const DATUM_MAX_SIZE_KB: usize = 10;

#[derive(Debug, Error)]
pub enum ProtocolConfigurationVerifierError {
    #[error("Configuration to import for {0:?} is not the same has configuration on chain")]
    NotSameConfigurationForEpoch(Epoch),

    #[error("Size of datum is {0:?} KB (Maximum authorized size is {DATUM_MAX_SIZE_KB} KB)")]
    DatumMaxSizeExceeded(f64),
}

type ProtocolConfigurationToolsResult<R> = StdResult<R>;

/// Configuration for the protocol configuration tools.
pub struct ProtocolConfigurationToolsConfiguration {
    /// Current epoch.
    pub epoch: Epoch,

    /// On chain configurations by Epoch.
    pub on_chain_configurations: ConfigurationResolverFromMarkers,
}

/// Tools configuration
pub struct ProtocolConfigurationTools {
    configuration: ProtocolConfigurationToolsConfiguration,
    logger: Logger,
}

impl ProtocolConfigurationTools {
    /// Create a new instance of the ProtocolConfigurationTools.
    pub fn new(configuration: ProtocolConfigurationToolsConfiguration, logger: Logger) -> Self {
        Self {
            configuration,
            logger,
        }
    }

    /// Create an instance of the ProtocolConfigurationTools from the dependencies.
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
            .read_configuration_markers()
            .await?;

        let configuration = ProtocolConfigurationToolsConfiguration {
            epoch,
            on_chain_configurations,
        };

        Ok(Self::new(configuration, dependencies.logger))
    }

    /// Get the on-chain configurations.
    pub fn get_on_chain_configurations(self) -> ConfigurationResolverFromMarkers {
        self.configuration.on_chain_configurations
    }

    /// Verify if configurations to import are compatible with what's on-chain.
    pub fn verify_configurations_against_chain(
        &self,
        configurations_to_import: Vec<HumanReadableProtocolConfiguration>,
    ) -> Result<(), ProtocolConfigurationVerifierError> {
        let current_epoch = self.configuration.epoch;
        info!(&self.logger, "Current epoch is {}", current_epoch);

        let markers_from_chain = self.configuration.on_chain_configurations.clone();
        let markers_to_import = to_configuration_resolver_from_markers(configurations_to_import);

        let epoch_start = Epoch(current_epoch.0.saturating_sub(EPOCH_OFFSET));

        info!(
            &self.logger,
            "Verifying configurations for epoch range [{}..={}]", epoch_start, current_epoch
        );

        for epoch in epoch_start.iter_inclusive_up_to_epoch(current_epoch) {
            let marker_to_import = markers_to_import.get_network_configuration(epoch);
            let marker_on_chain = markers_from_chain.get_network_configuration(epoch);
            if marker_on_chain.is_some() {
                if marker_to_import != marker_on_chain {
                    return Err(
                        ProtocolConfigurationVerifierError::NotSameConfigurationForEpoch(epoch),
                    );
                }
            } else {
                warn!(
                    &self.logger,
                    "No previous configuration was found on chain for epoch {}. This is expected when this is the first time that a configuration is published on-chain.",
                    epoch
                );
            }
        }
        Ok(())
    }

    /// Generate TxDatum from HumanReadableProtocolConfiguration Vec
    pub fn generate_tx_datum(
        &self,
        configurations: Vec<HumanReadableProtocolConfiguration>,
        protocol_configuration_markers_signer: &ProtocolConfigurationMarkersSigner,
    ) -> ProtocolConfigurationToolsResult<String> {
        let mut markers: Vec<ProtocolConfigurationMarker> = Vec::new();
        for configuration in configurations {
            let epoch = configuration.epoch;
            let protocol_configuration_for_epoch: ProtocolConfigurationForEpochMessage =
                configuration.into();
            let marker: ProtocolConfigurationMarker = ProtocolConfigurationMarker::new(
                epoch,
                protocol_configuration_for_epoch.to_cbor_hex()?,
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

    /// Verify if the size of the TxDatum is under the maximum authorized size.
    pub fn verify_tx_datum_size(
        &self,
        datum: String,
    ) -> Result<(), ProtocolConfigurationVerifierError> {
        let size_bytes = datum.len();
        let size_kb = size_bytes as f64 / 1024.0;

        println!("Datum size: {:.2} KB", size_kb);

        if size_bytes > DATUM_MAX_SIZE_KB * 1024 {
            return Err(ProtocolConfigurationVerifierError::DatumMaxSizeExceeded(
                size_kb,
            ));
        }

        Ok(())
    }
}

impl From<HumanReadableProtocolConfiguration> for ProtocolConfigurationForEpochMessage {
    fn from(config: HumanReadableProtocolConfiguration) -> Self {
        ProtocolConfigurationForEpochMessage {
            protocol_parameters: config.protocol_parameters.into(),
            enabled_signed_entity_types: config
                .enabled_signed_entity_types
                .iter()
                .filter(|discriminant| {
                    matches!(discriminant, SignedEntityTypeDiscriminantsMessage::Known(_))
                })
                .cloned()
                .collect(),
            cardano_transactions: config.cardano_transaction_signing_config.map(Into::into),
            cardano_blocks_transactions: config
                .cardano_blocks_transactions_signing_config
                .map(Into::into),
        }
    }
}

impl From<HumanReadableProtocolConfiguration> for ProtocolConfigurationForEpoch {
    fn from(config: HumanReadableProtocolConfiguration) -> Self {
        ProtocolConfigurationForEpoch {
            protocol_parameters: config.protocol_parameters,
            enabled_signed_entity_types:
                SignedEntityTypeDiscriminantsMessage::into_known_discriminants(
                    config.enabled_signed_entity_types,
                ),
            cardano_transactions: config.cardano_transaction_signing_config,
            cardano_blocks_transactions: config.cardano_blocks_transactions_signing_config,
        }
    }
}

fn to_configuration_resolver_from_markers(
    configs: Vec<HumanReadableProtocolConfiguration>,
) -> ConfigurationResolverFromMarkers {
    let mut markers = BTreeMap::new();

    for config in configs {
        markers.insert(config.epoch, ProtocolConfigurationForEpoch::from(config));
    }
    ConfigurationResolverFromMarkers::new(markers)
}

#[cfg(test)]
mod tests {
    use mithril_common::{
        entities::{
            BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
            CardanoTransactionsSigningConfig, Epoch, ProtocolParameters,
            SignedEntityTypeDiscriminants::{
                self, CardanoDatabase, CardanoTransactions, MithrilStakeDistribution,
            },
        },
        messages::SignedEntityTypeDiscriminantsMessage,
        test::double::Dummy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    use crate::test::TestLogger;

    use super::*;

    fn build_tools_dummy() -> ProtocolConfigurationTools {
        let configuration = ProtocolConfigurationToolsConfiguration {
            epoch: Epoch(30),
            on_chain_configurations: ConfigurationResolverFromMarkers::new(BTreeMap::new()),
        };
        ProtocolConfigurationTools::new(configuration, TestLogger::stdout())
    }

    fn build_tools(
        current_epoch: Epoch,
        on_chain_configurations: ConfigurationResolverFromMarkers,
        logger: Logger,
    ) -> ProtocolConfigurationTools {
        let configuration = ProtocolConfigurationToolsConfiguration {
            epoch: current_epoch,
            on_chain_configurations,
        };
        ProtocolConfigurationTools::new(configuration, logger)
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
                SignedEntityTypeDiscriminantsMessage::Known(MithrilStakeDistribution),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
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
    fn from_human_readable_protocol_configuration_to_protocol_configuration_for_epoch_message_keep_only_known_discriminants()
     {
        let human_readable_conf = HumanReadableProtocolConfiguration {
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminantsMessage::Known(MithrilStakeDistribution),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                SignedEntityTypeDiscriminantsMessage::Unknown,
            ]),
            ..Dummy::dummy()
        };

        let expected_enabled_signed_entity_types = BTreeSet::from_iter(vec![
            SignedEntityTypeDiscriminantsMessage::Known(MithrilStakeDistribution),
            SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
            SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
        ]);

        assert_eq!(
            ProtocolConfigurationForEpochMessage::from(human_readable_conf)
                .enabled_signed_entity_types,
            expected_enabled_signed_entity_types
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
                SignedEntityTypeDiscriminantsMessage::Known(MithrilStakeDistribution),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
            ]),
            cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions_signing_config: None,
        }];
        let signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let tools = build_tools_dummy();
        assert!(tools.generate_tx_datum(configurations, &signer).is_ok());
    }

    #[test]
    fn verify_tx_datum_size_is_ok_with_datum_under_10_kb() {
        let tools = build_tools_dummy();
        assert!(tools.verify_tx_datum_size("tx datum under 10 kb".to_string()).is_ok());
    }

    #[test]
    fn verify_tx_datum_size_is_ok_with_datum_from_dummy_configuration() {
        let configurations = vec![
            HumanReadableProtocolConfiguration {
                epoch: Epoch(42),
                ..Dummy::dummy()
            },
            HumanReadableProtocolConfiguration {
                epoch: Epoch(53),
                ..Dummy::dummy()
            },
        ];
        let signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let tools = build_tools_dummy();
        let datum = tools
            .generate_tx_datum(configurations, &signer)
            .expect("generate_tx_datum should not fail");

        assert!(tools.verify_tx_datum_size(datum).is_ok());
    }

    mod verify_configurations_against_chain {
        use mithril_common::entities::SignedEntityTypeDiscriminants::{
            CardanoBlocksTransactions, CardanoStakeDistribution,
        };

        use super::*;

        /// Instantiate a unique ProtocolConfigurationForEpoch based on char
        fn fake_configuration(conf: char) -> ProtocolConfigurationForEpoch {
            ProtocolConfigurationForEpoch {
                protocol_parameters: ProtocolParameters {
                    k: conf as u64,
                    m: conf as u64,
                    phi_f: 1.2,
                },
                cardano_transactions: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig::dummy()),
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                    SignedEntityTypeDiscriminants::CardanoDatabase,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ]),
            }
        }

        /// Instantiate a HumanReadableProtocolConfiguration at epoch with a unique char configuration
        fn fake_configuration_to_import(
            epoch: Epoch,
            conf: char,
        ) -> HumanReadableProtocolConfiguration {
            HumanReadableProtocolConfiguration {
                epoch,
                protocol_parameters: ProtocolParameters {
                    k: conf as u64,
                    m: conf as u64,
                    phi_f: 1.2,
                },
                cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
                cardano_blocks_transactions_signing_config: Some(
                    CardanoBlocksTransactionsSigningConfig::dummy(),
                ),
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoBlocksTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                ]),
            }
        }

        fn build_on_chain_markers(
            configurations: Vec<(Epoch, char)>,
        ) -> ConfigurationResolverFromMarkers {
            let mut on_chain_markers = BTreeMap::new();
            for conf in configurations {
                on_chain_markers.insert(conf.0, fake_configuration(conf.1));
            }
            ConfigurationResolverFromMarkers::new(on_chain_markers)
        }

        fn build_configurations_to_import(
            configurations: Vec<(Epoch, char)>,
        ) -> Vec<HumanReadableProtocolConfiguration> {
            configurations
                .iter()
                .map(|conf| fake_configuration_to_import(conf.0, conf.1))
                .collect()
        }

        #[test]
        fn ok_with_only_one_same_epoch_conf_in_offset_window() {
            let (logger, log_inspector) = TestLogger::memory();

            let current_epoch = Epoch(47);
            let on_chain_markers = BTreeMap::from([
                (Epoch(38), fake_configuration('A')),
                (Epoch(44), fake_configuration('B')),
            ]);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(on_chain_markers);

            let configurations_to_import =
                build_configurations_to_import(vec![(Epoch(44), 'B'), (Epoch(56), 'Z')]);

            let tools = build_tools(current_epoch, on_chain_configurations, logger);
            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );

            assert!(
                log_inspector.contains_log("Verifying configurations for epoch range [44..=47]")
            )
        }

        #[test]
        fn ok_with_only_one_same_epoch_conf_outside_offset_window_with_fallback() {
            let current_epoch = Epoch(47);
            let on_chain_markers = BTreeMap::from([
                (Epoch(31), fake_configuration('A')),
                (Epoch(38), fake_configuration('B')),
            ]);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(on_chain_markers);

            let configurations_to_import = vec![
                fake_configuration_to_import(Epoch(38), 'B'),
                fake_configuration_to_import(Epoch(56), 'Z'),
            ];

            let tools = build_tools(current_epoch, on_chain_configurations, TestLogger::stdout());

            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );
        }

        #[test]
        fn ok_with_only_one_same_conf_at_different_epoch() {
            let current_epoch = Epoch(47);
            let on_chain_markers = BTreeMap::from([
                (Epoch(31), fake_configuration('A')),
                (Epoch(38), fake_configuration('B')),
            ]);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(on_chain_markers);

            let configurations_to_import = vec![
                fake_configuration_to_import(Epoch(40), 'B'),
                fake_configuration_to_import(Epoch(56), 'Z'),
            ];

            let tools = build_tools(current_epoch, on_chain_configurations, TestLogger::stdout());

            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );
        }

        #[test]
        fn ko_because_last_known_on_chain_configuration_b_for_offset_window_is_not_repeated() {
            let current_epoch = Epoch(47);
            let on_chain_markers = BTreeMap::from([
                (Epoch(31), fake_configuration('A')),
                (Epoch(38), fake_configuration('B')),
            ]);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(on_chain_markers);

            let configurations_to_import = vec![
                fake_configuration_to_import(Epoch(40), 'C'),
                fake_configuration_to_import(Epoch(56), 'Z'),
            ];

            let tools = build_tools(current_epoch, on_chain_configurations, TestLogger::stdout());
            let result = tools.verify_configurations_against_chain(configurations_to_import);

            assert!(matches!(
                result.unwrap_err(),
                ProtocolConfigurationVerifierError::NotSameConfigurationForEpoch(Epoch(44))
            ));
        }

        #[test]
        fn full_offset_window_have_to_be_repeated_if_it_have_different_configuration() {
            let current_epoch = Epoch(47);
            let on_chain_markers = BTreeMap::from([
                (Epoch(43), fake_configuration('A')),
                (Epoch(44), fake_configuration('B')),
                (Epoch(45), fake_configuration('C')),
                (Epoch(46), fake_configuration('D')),
                (Epoch(47), fake_configuration('E')),
            ]);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(on_chain_markers);

            let configurations_to_import = vec![
                fake_configuration_to_import(Epoch(44), 'B'),
                fake_configuration_to_import(Epoch(45), 'C'),
                fake_configuration_to_import(Epoch(46), 'D'),
                fake_configuration_to_import(Epoch(47), 'E'),
                fake_configuration_to_import(Epoch(53), 'Z'),
            ];

            let tools = build_tools(
                current_epoch,
                on_chain_configurations.clone(),
                TestLogger::stdout(),
            );
            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );

            //It fail if one of epoch/conf from offset window is not repeated
            let bad_configurations_to_import = vec![
                fake_configuration_to_import(Epoch(44), 'B'),
                fake_configuration_to_import(Epoch(45), 'X'),
                fake_configuration_to_import(Epoch(46), 'D'),
                fake_configuration_to_import(Epoch(47), 'E'),
                fake_configuration_to_import(Epoch(53), 'Z'),
            ];

            let tools = build_tools(current_epoch, on_chain_configurations, TestLogger::stdout());
            let result = tools.verify_configurations_against_chain(bad_configurations_to_import);

            assert!(matches!(
                result.unwrap_err(),
                ProtocolConfigurationVerifierError::NotSameConfigurationForEpoch(Epoch(45))
            ));
        }

        #[test]
        fn window_to_repeat_dont_have_to_be_exactly_at_same_epoch_as_long_as_it_can_fallback_to_same_configuration()
         {
            let current_epoch = Epoch(47);
            let on_chain_configurations =
                build_on_chain_markers(vec![(Epoch(30), 'A'), (Epoch(44), 'B'), (Epoch(47), 'B')]);

            let configurations_to_import = vec![
                fake_configuration_to_import(Epoch(32), 'A'),
                fake_configuration_to_import(Epoch(40), 'B'),
                fake_configuration_to_import(Epoch(53), 'Z'),
            ];

            let tools = build_tools(
                current_epoch,
                on_chain_configurations.clone(),
                TestLogger::stdout(),
            );
            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );
        }

        #[test]
        fn verification_with_no_markers_on_chain_should_be_ok() {
            let current_epoch = Epoch(47);
            let on_chain_configurations = ConfigurationResolverFromMarkers::new(BTreeMap::new());

            let configurations_to_import = vec![fake_configuration_to_import(Epoch(53), 'Z')];

            let tools = build_tools(
                current_epoch,
                on_chain_configurations.clone(),
                TestLogger::stdout(),
            );
            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );
        }

        #[test]
        fn verification_with_no_markers_to_import_should_be_ko() {
            let current_epoch = Epoch(47);
            let on_chain_configurations =
                build_on_chain_markers(vec![(Epoch(30), 'A'), (Epoch(44), 'B')]);

            let tools = build_tools(
                current_epoch,
                on_chain_configurations.clone(),
                TestLogger::stdout(),
            );
            let result = tools.verify_configurations_against_chain(vec![]);

            assert!(matches!(
                result.unwrap_err(),
                ProtocolConfigurationVerifierError::NotSameConfigurationForEpoch(Epoch(44))
            ));
        }

        #[test]
        fn verification_should_handle_offset_with_current_epoch_1() {
            let current_epoch = Epoch(1);
            let on_chain_configurations = build_on_chain_markers(vec![(Epoch(1), 'A')]);
            let configurations_to_import = vec![fake_configuration_to_import(Epoch(1), 'A')];

            let tools = build_tools(
                current_epoch,
                on_chain_configurations.clone(),
                TestLogger::stdout(),
            );

            assert!(
                tools
                    .verify_configurations_against_chain(configurations_to_import)
                    .is_ok()
            );
        }
    }
}
