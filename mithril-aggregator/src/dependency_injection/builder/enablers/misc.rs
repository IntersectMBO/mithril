//! Miscellaneous enablers
//!
//! This naming is not ideal, we should either:
//! - group these enablers into more logical categories
//! - redefine the actual categories so those miscellaneous enablers fit into them

use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;

use mithril_aggregator_client::AggregatorHttpClient;
use mithril_common::logging::LoggerExtensions;
use mithril_common::messages::RegisterSignatureMessageDmq;
use mithril_dmq::{
    DmqConsumerClientDeduplicator, DmqConsumerClientPallas, SystemUnixTimestampProvider,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

use crate::database::repository::CertificateRepository;
use crate::dependency_injection::{DependenciesBuilder, Result};
use crate::get_dependency;
use crate::services::SignatureConsumerDmq;
use crate::services::{
    MessageService, MithrilMessageService, SequentialSignatureProcessor, SignatureConsumer,
    SignatureConsumerNoop, SignatureProcessor,
};

impl DependenciesBuilder {
    async fn build_signed_entity_type_lock(&mut self) -> Result<Arc<SignedEntityTypeLock>> {
        let signed_entity_lock = Arc::new(SignedEntityTypeLock::default());
        Ok(signed_entity_lock)
    }

    /// Get the [SignedEntityTypeLock] instance
    pub async fn get_signed_entity_type_lock(&mut self) -> Result<Arc<SignedEntityTypeLock>> {
        get_dependency!(self.signed_entity_type_lock)
    }

    /// Builds HTTP message service
    pub async fn build_message_service(&mut self) -> Result<Arc<dyn MessageService>> {
        let certificate_repository = Arc::new(CertificateRepository::new(
            self.get_sqlite_connection().await?,
        ));
        let signed_entity_storer = self.get_signed_entity_storer().await?;
        let epoch_settings_storer = self.get_epoch_settings_store().await?;
        let immutable_file_digest_mapper = self.get_immutable_file_digest_mapper().await?;
        let epoch_service = self.get_epoch_service().await?;
        let service = MithrilMessageService::new(
            certificate_repository,
            signed_entity_storer,
            epoch_settings_storer,
            immutable_file_digest_mapper,
            epoch_service,
        );

        Ok(Arc::new(service))
    }

    /// [MessageService] service
    pub async fn get_message_service(&mut self) -> Result<Arc<dyn MessageService>> {
        get_dependency!(self.message_service)
    }

    async fn build_aggregator_client(
        &mut self,
        endpoint: &str,
        client_name: &str,
    ) -> Result<Arc<AggregatorHttpClient>> {
        let aggregator_client = AggregatorHttpClient::builder(endpoint)
            .with_api_version_provider(self.get_api_version_provider().await?)
            .with_timeout(Duration::from_secs(30))
            .with_logger(self.root_logger.new_with_name(client_name))
            .build()?;

        Ok(Arc::new(aggregator_client))
    }

    /// Builds an [AggregatorHttpClient]
    pub async fn build_leader_aggregator_client(&mut self) -> Result<Arc<AggregatorHttpClient>> {
        let leader_aggregator_endpoint = self
            .configuration
            .leader_aggregator_endpoint()
            .with_context(|| "Leader Aggregator endpoint is mandatory for follower Aggregator")?;

        self.build_aggregator_client(&leader_aggregator_endpoint, "LeaderAggregatorClient")
            .await
    }

    /// Returns a leader [AggregatorHttpClient]
    pub async fn get_leader_aggregator_client(&mut self) -> Result<Arc<AggregatorHttpClient>> {
        get_dependency!(self.leader_aggregator_client)
    }

    /// Builds an [AggregatorHttpClient] for the certificate chain, which is the leader one when
    /// no dedicated endpoint is configured
    pub async fn build_certificate_chain_aggregator_client(
        &mut self,
    ) -> Result<Arc<AggregatorHttpClient>> {
        match self.configuration.certificate_chain_aggregator_endpoint() {
            Some(endpoint) => {
                self.build_aggregator_client(&endpoint, "CertificateChainAggregatorClient")
                    .await
            }
            None => self.get_leader_aggregator_client().await,
        }
    }

    /// Returns a certificate chain [AggregatorHttpClient]
    pub async fn get_certificate_chain_aggregator_client(
        &mut self,
    ) -> Result<Arc<AggregatorHttpClient>> {
        get_dependency!(self.certificate_chain_aggregator_client)
    }

    /// Builds a [SignatureConsumer]
    pub async fn build_signature_consumer(&mut self) -> Result<Arc<dyn SignatureConsumer>> {
        let signature_consumer = match self.configuration.dmq_node_socket_path() {
            Some(dmq_node_socket_path) => {
                let dmq_consumer =
                    Arc::new(DmqConsumerClientPallas::<RegisterSignatureMessageDmq>::new(
                        dmq_node_socket_path,
                        self.configuration.get_dmq_network()?,
                        self.root_logger(),
                    ));
                let dmq_consumer_deduplicator =
                    Arc::new(DmqConsumerClientDeduplicator::new_with_default_ttl(
                        dmq_consumer,
                        Arc::new(SystemUnixTimestampProvider),
                    ));
                Arc::new(SignatureConsumerDmq::new(dmq_consumer_deduplicator))
                    as Arc<dyn SignatureConsumer>
            }
            _ => Arc::new(SignatureConsumerNoop) as Arc<dyn SignatureConsumer>,
        };

        Ok(signature_consumer)
    }

    /// Builds a [SignatureProcessor]
    pub async fn create_signature_processor(&mut self) -> Result<Arc<dyn SignatureProcessor>> {
        let (_stop_tx, stop_rx) = self.get_stop_signal_channel().await?;
        let signature_processor = SequentialSignatureProcessor::new(
            self.build_signature_consumer().await?,
            self.get_certifier_service().await?,
            stop_rx,
            self.get_metrics_service().await?,
            Duration::from_millis(self.configuration.signature_processor_wait_delay_on_error_ms()),
            self.root_logger(),
        );

        Ok(Arc::new(signature_processor))
    }
}
