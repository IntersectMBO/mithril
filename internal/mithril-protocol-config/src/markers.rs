//! Markers implementation of MithrilNetworkConfigurationProvider.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use mithril_common::{
    StdResult,
    entities::{Epoch, InconsistentSignedEntityConfigError},
    logging::LoggerExtensions,
};
use slog::{Logger, warn};

use crate::{
    interface::{MithrilNetworkConfigurationProvider, ProtocolConfigurationMarkersReader},
    model::{MithrilNetworkConfiguration, MithrilNetworkConfigurationForEpoch},
};

/// Structure implementing MithrilNetworkConfigurationProvider using Cardano Chain.
pub struct MarkersMithrilNetworkConfigurationProvider {
    logger: Logger,
    markers_reader: Arc<dyn ProtocolConfigurationMarkersReader>,
}

impl MarkersMithrilNetworkConfigurationProvider {
    /// MarkersMithrilNetworkConfigurationProvider  factory
    pub fn new(
        logger: Logger,
        markers_reader: Arc<dyn ProtocolConfigurationMarkersReader>,
    ) -> Self {
        Self {
            logger: logger.new_with_component_name::<Self>(),
            markers_reader,
        }
    }

    fn log_inconsistency_error(&self, epoch: Epoch, err: &InconsistentSignedEntityConfigError) {
        warn!(
            &self.logger, "Some allowed signed entity could not be enabled for epoch {epoch}; using only the usable subset";
            "error" => %err
        );
    }
}

#[async_trait]
impl MithrilNetworkConfigurationProvider for MarkersMithrilNetworkConfigurationProvider {
    async fn get_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration> {
        let aggregation_epoch = epoch.offset_to_signer_retrieval_epoch_saturating();
        let next_aggregation_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let registration_epoch = epoch.offset_to_next_signer_retrieval_epoch().next();

        let configurations = self.markers_reader.read_configuration_markers().await?;

        let configuration_for_aggregation = configurations
            .get_network_configuration(aggregation_epoch)
            .map(MithrilNetworkConfigurationForEpoch::from)
            .with_context(|| {
                format!("Missing network configuration for aggregation epoch {aggregation_epoch}")
            })?
            .ensure_consistency(|err| self.log_inconsistency_error(aggregation_epoch, err));

        let configuration_for_next_aggregation = configurations
            .get_network_configuration(next_aggregation_epoch)
            .map(MithrilNetworkConfigurationForEpoch::from)
            .with_context(|| {
                format!("Missing network configuration for next aggregation epoch {next_aggregation_epoch}")
            })?
            .ensure_consistency(|err| self.log_inconsistency_error(next_aggregation_epoch, err));

        let configuration_for_registration = configurations
            .get_network_configuration(registration_epoch)
            .map(MithrilNetworkConfigurationForEpoch::from)
            .with_context(|| {
                format!("Missing network configuration for registration epoch {registration_epoch}")
            })?
            .ensure_consistency(|err| self.log_inconsistency_error(registration_epoch, err));

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
    use std::collections::{BTreeMap, BTreeSet};

    use mithril_common::entities::SignedEntityTypeDiscriminants;
    use mithril_common::test::double::Dummy;
    use mithril_common::test::entities_extensions::SignedEntityTypeDiscriminantsTestExtension;

    use crate::model::ProtocolConfigurationForEpoch;
    use crate::{model::ConfigurationResolverFromMarkers, test::test_tools::TestLogger};

    use crate::test::helper::generate_configuration;

    use super::*;

    fn build_markers_cardano_chain_network_provider(
        logger: Logger,
        configurations: ConfigurationResolverFromMarkers,
    ) -> MarkersMithrilNetworkConfigurationProvider {
        MarkersMithrilNetworkConfigurationProvider {
            logger,
            markers_reader: Arc::new(
                crate::test::double::FakeProtocolConfigurationMarkersReader::from_markers(
                    configurations,
                ),
            ),
        }
    }

    #[tokio::test]
    async fn test_get_network_configuration_retrieve_configurations_for_aggregation_next_aggregation_and_registration()
     {
        let markers = BTreeMap::from([
            (Epoch(31), generate_configuration('A')),
            (Epoch(38), generate_configuration('B')),
        ]);

        let configurations: ConfigurationResolverFromMarkers =
            ConfigurationResolverFromMarkers::new(markers);

        let markers_mithril_configuration_provider =
            build_markers_cardano_chain_network_provider(TestLogger::stdout(), configurations);

        let mithril_network_configuration = markers_mithril_configuration_provider
            .get_network_configuration(Epoch(42))
            .await
            .expect("should have configuration");

        assert_eq!(mithril_network_configuration.epoch, Epoch(42));
        assert_eq!(
            mithril_network_configuration.configuration_for_aggregation,
            generate_configuration('B').into()
        );
        assert_eq!(
            mithril_network_configuration.configuration_for_next_aggregation,
            generate_configuration('B').into()
        );
        assert_eq!(
            mithril_network_configuration.configuration_for_registration,
            generate_configuration('B').into()
        );
    }

    #[tokio::test]
    async fn test_get_network_configuration_removes_unavailable_discriminants_when_config_missing()
    {
        let configuration = ProtocolConfigurationForEpoch {
            enabled_signed_entity_types: SignedEntityTypeDiscriminants::all_with_unstable()
                .into_iter()
                .collect(),
            cardano_transactions: None,
            cardano_blocks_transactions: None,
            ..Dummy::dummy()
        };

        let markers = BTreeMap::from([(Epoch(31), configuration)]);

        let configurations: ConfigurationResolverFromMarkers =
            ConfigurationResolverFromMarkers::new(markers);

        let markers_mithril_configuration_provider =
            build_markers_cardano_chain_network_provider(TestLogger::stdout(), configurations);

        let mithril_network_configuration = markers_mithril_configuration_provider
            .get_network_configuration(Epoch(42))
            .await
            .expect("should have configuration");

        let expected_discriminants = SignedEntityTypeDiscriminants::all()
            // Discriminants without associated configuration should have been removed
            .difference(&BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            ]))
            .cloned()
            .collect::<BTreeSet<_>>();

        assert_eq!(
            expected_discriminants,
            mithril_network_configuration
                .configuration_for_aggregation
                .enabled_signed_entity_types
        );

        assert_eq!(
            expected_discriminants,
            mithril_network_configuration
                .configuration_for_next_aggregation
                .enabled_signed_entity_types
        );

        assert_eq!(
            expected_discriminants,
            mithril_network_configuration
                .configuration_for_registration
                .enabled_signed_entity_types
        );
    }
}
