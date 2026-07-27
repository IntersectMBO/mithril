use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use slog::{Logger, warn};

use mithril_common::StdResult;
use mithril_common::entities::{Epoch, SignedEntityConfigValidator, SignedEntityTypeDiscriminants};
use mithril_common::logging::LoggerExtensions;
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_protocol_config::model::{
    MithrilNetworkConfiguration, MithrilNetworkConfigurationForEpoch, SignedEntityTypeConfiguration,
};

use crate::EpochSettingsStorer;
use crate::entities::AggregatorEpochSettings;

/// Read network configuration from the database epoch_settings or, if no records is available for
/// an epoch, fallback to the provided configuration value
pub struct LocalMithrilNetworkConfigurationProvider {
    local_configuration_epoch_settings: AggregatorEpochSettings,
    allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
    epoch_settings_store: Arc<dyn EpochSettingsStorer>,
    logger: Logger,
}

impl LocalMithrilNetworkConfigurationProvider {
    /// Instantiate a new `LocalMithrilNetworkConfigurationProvider`
    pub fn new(
        local_configuration_epoch_settings: AggregatorEpochSettings,
        allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
        epoch_settings_store: Arc<dyn EpochSettingsStorer>,
        logger: Logger,
    ) -> Self {
        Self {
            local_configuration_epoch_settings,
            allowed_discriminants,
            epoch_settings_store,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Get epoch configuration from store or fallback to local configuration if it does not exists
    async fn get_stored_configuration_or_fallback(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfigurationForEpoch> {
        let epoch_settings = self.epoch_settings_store.get_epoch_settings(epoch).await?.unwrap_or(
            AggregatorEpochSettings {
                protocol_parameters: self
                    .local_configuration_epoch_settings
                    .protocol_parameters
                    .clone(),
                cardano_transactions_signing_config: self
                    .local_configuration_epoch_settings
                    .cardano_transactions_signing_config
                    .clone(),
                cardano_blocks_transactions_signing_config: self
                    .local_configuration_epoch_settings
                    .cardano_blocks_transactions_signing_config
                    .clone(),
            },
        );

        let enabled_signed_entity_types = match SignedEntityConfigValidator::check_consistency(
            &self.allowed_discriminants,
            &epoch_settings.cardano_transactions_signing_config,
            &epoch_settings.cardano_blocks_transactions_signing_config,
        ) {
            Ok(()) => self.allowed_discriminants.clone(),
            Err(err) => {
                warn!(
                    self.logger, "Some allowed signed entity could not be enabled for epoch {epoch}; using only the usable subset";
                    "error" => %err
                );
                err.usable_discriminants
            }
        };

        Ok(MithrilNetworkConfigurationForEpoch {
            enabled_signed_entity_types,
            protocol_parameters: epoch_settings.protocol_parameters,
            signed_entity_types_config: SignedEntityTypeConfiguration {
                cardano_transactions: epoch_settings.cardano_transactions_signing_config,
                cardano_blocks_transactions: epoch_settings
                    .cardano_blocks_transactions_signing_config,
            },
        })
    }
}

#[async_trait]
impl MithrilNetworkConfigurationProvider for LocalMithrilNetworkConfigurationProvider {
    async fn get_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration> {
        let aggregation_epoch = epoch.offset_to_signer_retrieval_epoch_saturating();
        let next_aggregation_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let registration_epoch = epoch.offset_to_next_signer_retrieval_epoch().next();

        let configuration_for_aggregation =
            self.get_stored_configuration_or_fallback(aggregation_epoch).await?;
        let configuration_for_next_aggregation = self
            .get_stored_configuration_or_fallback(next_aggregation_epoch)
            .await?;
        let configuration_for_registration =
            self.get_stored_configuration_or_fallback(registration_epoch).await?;

        let config = MithrilNetworkConfiguration {
            epoch,
            configuration_for_aggregation,
            configuration_for_next_aggregation,
            configuration_for_registration,
        };
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{
        entities::{
            BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
            CardanoTransactionsSigningConfig, ProtocolParameters,
        },
        test::double::Dummy,
    };

    use crate::store::FakeEpochSettingsStorer;
    use crate::test::TestLogger;

    use super::*;

    #[tokio::test]
    async fn get_stored_configuration_with_stored_value_returns_them() {
        let local_configuration_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: ProtocolParameters::new(2000, 200, 0.2),
            ..Dummy::dummy()
        };
        let stored_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: ProtocolParameters::new(1000, 100, 0.1),
            ..Dummy::dummy()
        };

        let local_provider = LocalMithrilNetworkConfigurationProvider::new(
            local_configuration_epoch_settings,
            SignedEntityTypeDiscriminants::all(),
            Arc::new(FakeEpochSettingsStorer::new(vec![(
                Epoch(42),
                stored_epoch_settings.clone(),
            )])),
            TestLogger::stdout(),
        );

        let network_configuration = local_provider
            .get_stored_configuration_or_fallback(Epoch(42))
            .await
            .unwrap();

        assert_eq!(
            stored_epoch_settings.protocol_parameters,
            network_configuration.protocol_parameters
        )
    }

    #[tokio::test]
    async fn get_stored_configuration_without_stored_value_fallback_to_configuration_value() {
        let local_configuration_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: ProtocolParameters::new(2000, 200, 0.2),
            ..Dummy::dummy()
        };

        let local_provider = LocalMithrilNetworkConfigurationProvider::new(
            local_configuration_epoch_settings.clone(),
            SignedEntityTypeDiscriminants::all(),
            Arc::new(FakeEpochSettingsStorer::new(vec![])),
            TestLogger::stdout(),
        );

        let network_configuration = local_provider
            .get_stored_configuration_or_fallback(Epoch(42))
            .await
            .unwrap();

        assert_eq!(
            local_configuration_epoch_settings.protocol_parameters,
            network_configuration.protocol_parameters
        )
    }

    #[tokio::test]
    async fn get_stored_configuration_disable_inconsistent_discriminants_without_fallback() {
        let local_configuration_epoch_settings = AggregatorEpochSettings::dummy();
        let stored_epoch_settings = AggregatorEpochSettings {
            cardano_transactions_signing_config: None,
            cardano_blocks_transactions_signing_config: None,
            ..Dummy::dummy()
        };

        let local_provider = LocalMithrilNetworkConfigurationProvider::new(
            local_configuration_epoch_settings,
            // enable all signed entity types even if we don't have a configuration for them
            SignedEntityTypeDiscriminants::all(),
            Arc::new(FakeEpochSettingsStorer::new(vec![(
                Epoch(42),
                stored_epoch_settings.clone(),
            )])),
            TestLogger::stdout(),
        );

        let network_configuration = local_provider
            .get_stored_configuration_or_fallback(Epoch(42))
            .await
            .unwrap();

        assert_eq!(
            SignedEntityTypeDiscriminants::all()
                // Discriminants without associated configuration should have been removed
                .difference(&BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ]))
                .cloned()
                .collect::<BTreeSet<_>>(),
            network_configuration.enabled_signed_entity_types
        )
    }

    #[tokio::test]
    async fn get_stored_configuration_disable_inconsistent_discriminants_when_fallback() {
        let local_configuration_epoch_settings = AggregatorEpochSettings {
            cardano_transactions_signing_config: None,
            cardano_blocks_transactions_signing_config: None,
            ..Dummy::dummy()
        };

        let local_provider = LocalMithrilNetworkConfigurationProvider::new(
            local_configuration_epoch_settings.clone(),
            SignedEntityTypeDiscriminants::all(),
            Arc::new(FakeEpochSettingsStorer::new(vec![])),
            TestLogger::stdout(),
        );

        let network_configuration = local_provider
            .get_stored_configuration_or_fallback(Epoch(42))
            .await
            .unwrap();

        assert_eq!(
            SignedEntityTypeDiscriminants::all()
                // Discriminants without associated configuration should have been removed
                .difference(&BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ]))
                .cloned()
                .collect::<BTreeSet<_>>(),
            network_configuration.enabled_signed_entity_types
        )
    }

    #[tokio::test]
    async fn test_get_network_configuration_retrieve_configurations_for_aggregation_next_aggregation_and_registration()
     {
        let local_configuration_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: ProtocolParameters::new(3000, 300, 0.3),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(3),
                step: BlockNumber(30),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(33),
                    step: BlockNumber(330),
                },
            ),
        };

        // Nothing stored at 44, should fallback to configuration
        let local_provider = LocalMithrilNetworkConfigurationProvider::new(
            local_configuration_epoch_settings,
            SignedEntityTypeDiscriminants::all(),
            Arc::new(FakeEpochSettingsStorer::new(vec![
                (
                    Epoch(42),
                    AggregatorEpochSettings {
                        protocol_parameters: ProtocolParameters::new(1000, 100, 0.1),
                        cardano_transactions_signing_config: Some(
                            CardanoTransactionsSigningConfig {
                                security_parameter: BlockNumberOffset(1),
                                step: BlockNumber(10),
                            },
                        ),
                        cardano_blocks_transactions_signing_config: Some(
                            CardanoBlocksTransactionsSigningConfig {
                                security_parameter: BlockNumberOffset(11),
                                step: BlockNumber(110),
                            },
                        ),
                    },
                ),
                (
                    Epoch(43),
                    AggregatorEpochSettings {
                        protocol_parameters: ProtocolParameters::new(2000, 200, 0.2),
                        cardano_transactions_signing_config: Some(
                            CardanoTransactionsSigningConfig {
                                security_parameter: BlockNumberOffset(2),
                                step: BlockNumber(20),
                            },
                        ),
                        cardano_blocks_transactions_signing_config: Some(
                            CardanoBlocksTransactionsSigningConfig {
                                security_parameter: BlockNumberOffset(22),
                                step: BlockNumber(220),
                            },
                        ),
                    },
                ),
            ])),
            TestLogger::stdout(),
        );

        let configuration = local_provider.get_network_configuration(Epoch(43)).await.unwrap();

        assert_eq!(Epoch(43), configuration.epoch);

        assert_eq!(
            MithrilNetworkConfigurationForEpoch {
                protocol_parameters: ProtocolParameters::new(1000, 100, 0.1),
                enabled_signed_entity_types: SignedEntityTypeDiscriminants::all(),
                signed_entity_types_config: SignedEntityTypeConfiguration {
                    cardano_transactions: Some(CardanoTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(1),
                        step: BlockNumber(10),
                    }),
                    cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(11),
                        step: BlockNumber(110),
                    },),
                },
            },
            configuration.configuration_for_aggregation
        );

        assert_eq!(
            MithrilNetworkConfigurationForEpoch {
                protocol_parameters: ProtocolParameters::new(2000, 200, 0.2),
                enabled_signed_entity_types: SignedEntityTypeDiscriminants::all(),
                signed_entity_types_config: SignedEntityTypeConfiguration {
                    cardano_transactions: Some(CardanoTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(2),
                        step: BlockNumber(20),
                    }),
                    cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(22),
                        step: BlockNumber(220),
                    },),
                },
            },
            configuration.configuration_for_next_aggregation
        );

        assert_eq!(
            MithrilNetworkConfigurationForEpoch {
                protocol_parameters: ProtocolParameters::new(3000, 300, 0.3),
                enabled_signed_entity_types: SignedEntityTypeDiscriminants::all(),
                signed_entity_types_config: SignedEntityTypeConfiguration {
                    cardano_transactions: Some(CardanoTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(3),
                        step: BlockNumber(30),
                    }),
                    cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(33),
                        step: BlockNumber(330),
                    },),
                },
            },
            configuration.configuration_for_registration
        );
    }
}
