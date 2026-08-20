use std::sync::Arc;
use tokio::sync::RwLock;

use mithril_protocol_config::{
    builder::build_protocol_configuration_adapter, http::HttpMithrilNetworkConfigurationProvider,
    interface::MithrilNetworkConfigurationProvider, interface::ProtocolConfigurationMarkersReader,
    markers::MarkersMithrilNetworkConfigurationProvider,
    test::double::FakeProtocolConfigurationMarkersReader,
};

use crate::dependency_injection::{DependenciesBuilder, EpochServiceWrapper, Result};
use crate::services::{EpochServiceDependencies, MithrilEpochService};
use crate::{ExecutionEnvironment, get_dependency};

impl DependenciesBuilder {
    async fn build_epoch_service(&mut self) -> Result<EpochServiceWrapper> {
        let verification_key_store = self.get_verification_key_store().await?;
        let epoch_settings_storer = self.get_epoch_settings_store().await?;
        let chain_observer = self.get_chain_observer().await?;
        let era_checker = self.get_era_checker().await?;
        let stake_store = self.get_stake_store().await?;
        let allowed_discriminants = self
            .configuration
            .compute_allowed_signed_entity_types_discriminants()?;

        let epoch_service = Arc::new(RwLock::new(MithrilEpochService::new(
            EpochServiceDependencies::new(
                self.get_mithril_network_configuration_provider().await?,
                epoch_settings_storer,
                verification_key_store,
                chain_observer,
                era_checker,
                stake_store,
            ),
            allowed_discriminants,
            self.root_logger(),
        )));

        Ok(epoch_service)
    }

    /// [EpochService][crate::services::EpochService] service
    pub async fn get_epoch_service(&mut self) -> Result<EpochServiceWrapper> {
        get_dependency!(self.epoch_service)
    }

    async fn build_mithril_network_configuration_provider(
        &mut self,
    ) -> Result<Arc<dyn MithrilNetworkConfigurationProvider>> {
        let network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider> =
            if self.configuration.is_follower_aggregator() {
                Arc::new(HttpMithrilNetworkConfigurationProvider::new(
                    self.get_leader_aggregator_client().await?,
                    self.root_logger(),
                ))
            } else {
                let protocol_configuration_adapter =
                    self.get_protocol_configuration_reader().await?;
                Arc::new(MarkersMithrilNetworkConfigurationProvider::new(
                    self.root_logger(),
                    protocol_configuration_adapter,
                ))
            };

        Ok(network_configuration_provider)
    }

    /// [MithrilNetworkConfigurationProvider][mithril_protocol_config::interface::MithrilNetworkConfigurationProvider] service
    pub async fn get_mithril_network_configuration_provider(
        &mut self,
    ) -> Result<Arc<dyn MithrilNetworkConfigurationProvider>> {
        get_dependency!(self.mithril_network_configuration_provider)
    }

    async fn build_protocol_configuration_reader(
        &mut self,
    ) -> Result<Arc<dyn ProtocolConfigurationMarkersReader>> {
        let protocol_configuration_markers_reader: Arc<dyn ProtocolConfigurationMarkersReader> =
            match self.configuration.environment() {
                ExecutionEnvironment::Production => {
                    let adapter_config =
                        self.configuration.protocol_configuration_reader_adapter_config();

                    build_protocol_configuration_adapter(
                        adapter_config,
                        self.get_chain_observer().await?,
                    )
                }
                _ => Arc::new(FakeProtocolConfigurationMarkersReader::default()),
            };

        Ok(protocol_configuration_markers_reader)
    }

    /// [ProtocolConfigurationMarkersReader] service
    pub async fn get_protocol_configuration_reader(
        &mut self,
    ) -> Result<Arc<dyn ProtocolConfigurationMarkersReader>> {
        get_dependency!(self.protocol_configuration_reader)
    }
}
