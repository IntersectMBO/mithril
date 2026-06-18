//! HTTP implementation of MithrilNetworkConfigurationProvider.

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, warn};
use std::sync::Arc;

use mithril_aggregator_client::AggregatorHttpClient;
use mithril_aggregator_client::query::GetProtocolConfigurationQuery;
use mithril_common::StdResult;
use mithril_common::entities::{Epoch, SignedEntityConfigValidator};
use mithril_common::logging::LoggerExtensions;

use crate::interface::MithrilNetworkConfigurationProvider;
use crate::model::{MithrilNetworkConfiguration, MithrilNetworkConfigurationForEpoch};

/// Structure implementing MithrilNetworkConfigurationProvider using HTTP.
pub struct HttpMithrilNetworkConfigurationProvider {
    aggregator_http_client: Arc<AggregatorHttpClient>,
    logger: Logger,
}

impl HttpMithrilNetworkConfigurationProvider {
    /// HttpMithrilNetworkConfigurationProvider factory
    pub fn new(aggregator_http_client: Arc<AggregatorHttpClient>, logger: Logger) -> Self {
        Self {
            aggregator_http_client,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn get_valid_configuration_for_epoch(
        &self,
        epoch: Epoch,
    ) -> StdResult<Option<MithrilNetworkConfigurationForEpoch>> {
        if let Some(mut configuration) = self
            .aggregator_http_client
            .send(GetProtocolConfigurationQuery::epoch(epoch))
            .await?
            .map(Into::<MithrilNetworkConfigurationForEpoch>::into)
        {
            if let Err(err) = SignedEntityConfigValidator::check_consistency(
                &configuration.enabled_signed_entity_types,
                &configuration.signed_entity_types_config.cardano_transactions,
                &configuration.signed_entity_types_config.cardano_blocks_transactions,
            ) {
                warn!(
                    self.logger, "Some allowed signed entity could not be enabled for epoch {epoch}; using only the usable subset";
                    "error" => %err
                );
                configuration.enabled_signed_entity_types = err.usable_discriminants;
            };

            Ok(Some(configuration))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl MithrilNetworkConfigurationProvider for HttpMithrilNetworkConfigurationProvider {
    async fn get_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration> {
        let aggregation_epoch = epoch.offset_to_signer_retrieval_epoch_saturating();
        let next_aggregation_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let registration_epoch = epoch.offset_to_next_signer_retrieval_epoch().next();

        let configuration_for_aggregation: MithrilNetworkConfigurationForEpoch = self
            .get_valid_configuration_for_epoch(aggregation_epoch)
            .await?
            .with_context(|| {
                format!("Missing network configuration for aggregation epoch {aggregation_epoch}")
            })?;

        let configuration_for_next_aggregation = self
            .get_valid_configuration_for_epoch(next_aggregation_epoch)
            .await?
            .with_context(|| {
                format!("Missing network configuration for next aggregation epoch {next_aggregation_epoch}")
            })?;

        let configuration_for_registration = self
            .get_valid_configuration_for_epoch(registration_epoch)
            .await?
            .with_context(|| {
                format!(
                    "Missing network configuration for registration epoch {next_aggregation_epoch}"
                )
            })?;

        Ok(MithrilNetworkConfiguration {
            epoch,
            configuration_for_aggregation,
            configuration_for_next_aggregation,
            configuration_for_registration,
        })
    }
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use mithril_common::entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, ProtocolParameters, SignedEntityTypeDiscriminants,
    };
    use mithril_common::messages::{DiscontinuedSignedEntityType, ProtocolConfigurationMessage};
    use mithril_common::test::double::Dummy;
    use mithril_common::test::entities_extensions::SignedEntityTypeDiscriminantsTestExtension;

    use crate::test::test_tools::TestLogger;

    use super::*;

    fn build_http_network_provider(
        server_url: &str,
        logger: Logger,
    ) -> HttpMithrilNetworkConfigurationProvider {
        HttpMithrilNetworkConfigurationProvider::new(
            Arc::new(
                AggregatorHttpClient::builder(server_url)
                    .with_logger(logger.clone())
                    .build()
                    .unwrap(),
            ),
            logger,
        )
    }

    #[tokio::test]
    async fn test_get_network_configuration_retrieve_configurations_for_aggregation_next_aggregation_and_registration()
     {
        let configuration_epoch_41 = ProtocolConfigurationMessage {
            protocol_parameters: ProtocolParameters::new(1000, 100, 0.1),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(1),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(11),
                    step: BlockNumber(110),
                },
            ),
            ..Dummy::dummy()
        };
        let configuration_epoch_42 = ProtocolConfigurationMessage {
            protocol_parameters: ProtocolParameters::new(2000, 200, 0.2),
            ..Dummy::dummy()
        };
        let configuration_epoch_43 = ProtocolConfigurationMessage {
            protocol_parameters: ProtocolParameters::new(3000, 300, 0.3),
            ..Dummy::dummy()
        };

        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/protocol-configuration/41");
            then.status(200)
                .body(serde_json::to_string(&configuration_epoch_41).unwrap());
        });
        server.mock(|when, then| {
            when.path("/protocol-configuration/42");
            then.status(200)
                .body(serde_json::to_string(&configuration_epoch_42).unwrap());
        });
        server.mock(|when, then| {
            when.path("/protocol-configuration/43");
            then.status(200)
                .body(serde_json::to_string(&configuration_epoch_43).unwrap());
        });

        let mithril_configuration_provider =
            build_http_network_provider(&server.base_url(), TestLogger::stdout());

        let configuration = mithril_configuration_provider
            .get_network_configuration(Epoch(42))
            .await
            .expect("should have configuration");

        assert_eq!(
            configuration.configuration_for_aggregation.protocol_parameters,
            ProtocolParameters::new(1000, 100, 0.1)
        );
        assert_eq!(
            configuration
                .configuration_for_aggregation
                .signed_entity_types_config
                .cardano_transactions,
            Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(1),
                step: BlockNumber(10),
            })
        );

        assert_eq!(
            configuration
                .configuration_for_aggregation
                .signed_entity_types_config
                .cardano_blocks_transactions,
            Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(11),
                step: BlockNumber(110),
            })
        );

        assert_eq!(
            configuration.configuration_for_next_aggregation.protocol_parameters,
            ProtocolParameters::new(2000, 200, 0.2)
        );

        assert_eq!(
            configuration.configuration_for_registration.protocol_parameters,
            ProtocolParameters::new(3000, 300, 0.3)
        );
    }

    #[tokio::test]
    async fn eventual_eventual_inconsistent_discriminants_are_removed_from_enabled_list() {
        let configuration_epoch_56 = ProtocolConfigurationMessage {
            available_signed_entity_types: SignedEntityTypeDiscriminants::all_with_unstable()
                .into_iter()
                .map(Into::into)
                .collect(),
            cardano_transactions_signing_config: None,
            cardano_blocks_transactions_signing_config: None,
            ..Dummy::dummy()
        };

        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/protocol-configuration/56");
            then.status(200)
                .body(serde_json::to_string(&configuration_epoch_56).unwrap());
        });

        let mithril_configuration_provider =
            build_http_network_provider(&server.base_url(), TestLogger::stdout());

        let configuration = mithril_configuration_provider
            .get_valid_configuration_for_epoch(Epoch(56))
            .await
            .unwrap()
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
            configuration.enabled_signed_entity_types
        )
    }

    #[tokio::test]
    async fn all_known_discriminants_including_unstable_can_be_read() {
        let configuration_epoch_56 = ProtocolConfigurationMessage {
            available_signed_entity_types: SignedEntityTypeDiscriminants::all_with_unstable()
                .into_iter()
                .map(Into::into)
                .collect(),
            ..Dummy::dummy()
        };

        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/protocol-configuration/56");
            then.status(200)
                .body(serde_json::to_string(&configuration_epoch_56).unwrap());
        });

        let mithril_configuration_provider =
            build_http_network_provider(&server.base_url(), TestLogger::stdout());

        mithril_configuration_provider
            .get_valid_configuration_for_epoch(Epoch(56))
            .await
            .expect("Including unstable discriminants should not fail")
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_and_discontinued_discriminants_are_removed_from_enabled_list() {
        let server = MockServer::start();
        server.mock(|when, then| {
            let mut message = serde_json::to_value(&ProtocolConfigurationMessage {
                available_signed_entity_types: BTreeSet::new(),
                ..Dummy::dummy()
            })
            .unwrap();
            message["available_signed_entity_types"] = serde_json::to_value(vec![
                SignedEntityTypeDiscriminants::MithrilStakeDistribution.as_ref(),
                DiscontinuedSignedEntityType::CardanoImmutableFilesFull.as_ref(),
                "signed_entity_type_which_does_not_exist",
            ])
            .unwrap();

            when.path("/protocol-configuration/56");
            then.status(200).body(message.to_string());
        });

        let mithril_configuration_provider =
            build_http_network_provider(&server.base_url(), TestLogger::stdout());

        let configuration = mithril_configuration_provider
            .get_valid_configuration_for_epoch(Epoch(56))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            BTreeSet::from([SignedEntityTypeDiscriminants::MithrilStakeDistribution]),
            configuration.enabled_signed_entity_types
        )
    }
}
