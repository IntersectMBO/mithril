use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use mithril_cardano_node_chain::{
    chain_observer::{CardanoCliRunner, ChainObserver, ChainObserverBuilder, ChainObserverType},
    chain_reader::{ChainBlockReader, PallasChainReader},
    chain_scanner::{BlockScanner, CardanoBlockScanner},
    test::double::FakeChainObserver,
};
use mithril_cardano_node_internal_database::digesters::{
    CardanoImmutableDigester, ImmutableDigester,
};
use mithril_common::entities::SignedEntityTypeDiscriminants;
use mithril_signed_entity_preloader::{
    CardanoTransactionsPreloader, CardanoTransactionsPreloaderActivation, PreloadTaskRunner,
};

use crate::ExecutionEnvironment;
use crate::dependency_injection::{DependenciesBuilder, Result};
use crate::get_dependency;
use crate::services::{MithrilStakeDistributionService, StakeDistributionService};
impl DependenciesBuilder {
    async fn build_chain_observer(&mut self) -> Result<Arc<dyn ChainObserver>> {
        let chain_observer: Arc<dyn ChainObserver> = match self.configuration.environment() {
            ExecutionEnvironment::Production => {
                let chain_observer_type = &self.configuration.chain_observer_type();
                let cardano_cli_runner = match chain_observer_type {
                    ChainObserverType::CardanoCli => Some(self.get_cardano_cli_runner().await?),
                    _ => None,
                };
                let cardano_node_socket_path = &self.configuration.cardano_node_socket_path();
                let cardano_network = &self
                    .configuration
                    .get_network()
                    .with_context(|| "Dependencies Builder can not get Cardano network while building the chain observer")?;
                let chain_observer_builder = ChainObserverBuilder::new(
                    chain_observer_type,
                    cardano_node_socket_path,
                    cardano_network,
                    cardano_cli_runner.as_deref(),
                );

                chain_observer_builder
                    .build()
                    .with_context(|| "Dependencies Builder can not build chain observer")?
            }
            _ => Arc::new(FakeChainObserver::default()),
        };

        Ok(chain_observer)
    }

    /// Return a [ChainObserver]
    pub async fn get_chain_observer(&mut self) -> Result<Arc<dyn ChainObserver>> {
        get_dependency!(self.chain_observer)
    }

    async fn build_cardano_cli_runner(&mut self) -> Result<Box<CardanoCliRunner>> {
        let cli_runner = CardanoCliRunner::new(
            self.configuration.cardano_cli_path(),
            self.configuration.cardano_node_socket_path(),
            self.configuration.get_network().with_context(|| {
                "Dependencies Builder can not get Cardano network while building cardano cli runner"
            })?,
        );

        Ok(Box::new(cli_runner))
    }

    /// Return a [CardanoCliRunner]
    pub async fn get_cardano_cli_runner(&mut self) -> Result<Box<CardanoCliRunner>> {
        get_dependency!(self.cardano_cli_runner)
    }

    async fn build_chain_block_reader(&mut self) -> Result<Arc<Mutex<dyn ChainBlockReader>>> {
        let chain_block_reader = PallasChainReader::new(
            &self.configuration.cardano_node_socket_path(),
            self.configuration.get_network()?,
            self.root_logger(),
        );

        Ok(Arc::new(Mutex::new(chain_block_reader)))
    }

    /// Chain reader
    pub async fn get_chain_block_reader(&mut self) -> Result<Arc<Mutex<dyn ChainBlockReader>>> {
        get_dependency!(self.chain_block_reader)
    }

    async fn build_block_scanner(&mut self) -> Result<Arc<dyn BlockScanner>> {
        let block_scanner = CardanoBlockScanner::new(
            self.get_chain_block_reader().await?,
            self.get_chain_data_repository().await?,
            self.configuration
                .cardano_transactions_block_streamer_max_roll_forwards_per_poll(),
            self.root_logger(),
        )
        .set_throttling_interval(
            self.configuration
                .cardano_transactions_block_streamer_throttling_interval()
                .map(Duration::from_millis),
        );

        Ok(Arc::new(block_scanner))
    }

    /// Block scanner
    pub async fn get_block_scanner(&mut self) -> Result<Arc<dyn BlockScanner>> {
        get_dependency!(self.block_scanner)
    }

    async fn build_immutable_digester(&mut self) -> Result<Arc<dyn ImmutableDigester>> {
        let immutable_digester_cache = match self.configuration.environment() {
            ExecutionEnvironment::Production => Some(self.get_immutable_cache_provider().await?),
            _ => None,
        };
        let digester = CardanoImmutableDigester::new(immutable_digester_cache, self.root_logger());

        Ok(Arc::new(digester))
    }

    /// Immutable digester.
    pub async fn get_immutable_digester(&mut self) -> Result<Arc<dyn ImmutableDigester>> {
        get_dependency!(self.immutable_digester)
    }

    /// Create a [PreloadTaskRunner] running a [CardanoTransactionsPreloader].
    pub async fn create_cardano_transactions_preloader(
        &mut self,
    ) -> Result<Arc<PreloadTaskRunner<CardanoTransactionsPreloader>>> {
        let activation = self
            .configuration
            .compute_allowed_signed_entity_types_discriminants()?
            .contains(&SignedEntityTypeDiscriminants::CardanoTransactions);
        let cardano_transactions_preloader = PreloadTaskRunner::new(
            CardanoTransactionsPreloader::new(
                self.get_chain_data_importer().await?,
                self.configuration.preload_security_parameter(),
                self.get_chain_observer().await?,
                Arc::new(CardanoTransactionsPreloaderActivation::new(activation)),
            ),
            self.get_signed_entity_type_lock().await?,
            self.root_logger(),
        );

        Ok(Arc::new(cardano_transactions_preloader))
    }

    async fn build_stake_distribution_service(
        &mut self,
    ) -> Result<Arc<dyn StakeDistributionService>> {
        let stake_distribution_service = Arc::new(MithrilStakeDistributionService::new(
            self.get_stake_store().await?,
            self.get_chain_observer().await?,
        ));

        Ok(stake_distribution_service)
    }

    /// [StakeDistributionService] service
    pub async fn get_stake_distribution_service(
        &mut self,
    ) -> Result<Arc<dyn StakeDistributionService>> {
        get_dependency!(self.stake_distribution_service)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{entities::SignedEntityTypeDiscriminants, temp_dir};

    use crate::ServeCommandConfiguration;

    use super::*;

    #[tokio::test]
    async fn cardano_transactions_preloader_activated_with_cardano_transactions_signed_entity_type_in_configuration()
     {
        assert_cardano_transactions_preloader_activation(
            SignedEntityTypeDiscriminants::CardanoTransactions.to_string(),
            true,
        )
        .await;
        assert_cardano_transactions_preloader_activation(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution.to_string(),
            false,
        )
        .await;
    }

    async fn assert_cardano_transactions_preloader_activation(
        signed_entity_types: String,
        expected_activation: bool,
    ) {
        let configuration = ServeCommandConfiguration {
            signed_entity_types: Some(signed_entity_types),
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };
        let mut dep_builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(configuration));

        let cardano_transactions_preloader =
            dep_builder.create_cardano_transactions_preloader().await.unwrap();

        let is_activated = cardano_transactions_preloader.is_activated().await.unwrap();
        assert_eq!(
            expected_activation, is_activated,
            "'is_activated' expected {expected_activation}, but was {is_activated}"
        );
    }
}
