//! Warm-up of the aggregate signature prover ahead of the first signing round.

use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, info, warn};

use mithril_common::crypto_helper::{
    ProtocolParameters, SnarkProverSetupWarmer, TrustedSetupDownloader, TrustedSetupProvider,
};
use mithril_common::logging::LoggerExtensions;
use mithril_common::{AggregateSignatureType, StdResult};
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_ticker::TickerService;

/// Warms up the aggregate signature prover, so the first signing round does not materialize the
/// prover setup inside its aggregation.
#[async_trait]
pub trait AggregateSignatureProverWarmer: Send + Sync {
    /// Warms up the prover of the current epoch.
    async fn warm_up(&self) -> StdResult<()>;
}

/// Warms up the SNARK prover setups on a thread of their own, into the process-wide cache the
/// provers read, so a shutdown never waits for them. The SRS of the trusted setup is downloaded
/// on that thread when it is missing, the provers never downloading it themselves.
pub struct SnarkAggregateSignatureProverWarmer {
    aggregate_signature_type: AggregateSignatureType,
    ticker_service: Arc<dyn TickerService>,
    network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
    trusted_setup_downloader: Arc<dyn TrustedSetupDownloader>,
    logger: Logger,
}

impl SnarkAggregateSignatureProverWarmer {
    /// Factory
    pub fn new(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
        network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        trusted_setup_downloader: Arc<dyn TrustedSetupDownloader>,
        logger: Logger,
    ) -> Self {
        Self {
            aggregate_signature_type,
            ticker_service,
            network_configuration_provider,
            trusted_setup_downloader,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Protocol parameters the current epoch aggregates with.
    async fn protocol_parameters_for_aggregation(&self) -> StdResult<ProtocolParameters> {
        let epoch = self
            .ticker_service
            .get_current_epoch()
            .await
            .with_context(|| "Prover warmer could not get the current epoch")?;
        let network_configuration = self
            .network_configuration_provider
            .get_network_configuration(epoch)
            .await
            .with_context(|| {
                format!("Prover warmer could not get the network configuration of epoch {epoch}")
            })?;

        Ok(ProtocolParameters::from(
            network_configuration
                .configuration_for_aggregation
                .protocol_parameters,
        ))
    }
}

#[async_trait]
impl AggregateSignatureProverWarmer for SnarkAggregateSignatureProverWarmer {
    async fn warm_up(&self) -> StdResult<()> {
        if self.aggregate_signature_type == AggregateSignatureType::Concatenation {
            return Ok(());
        }

        let protocol_parameters = self.protocol_parameters_for_aggregation().await?;
        info!(
            self.logger,
            "Warming up the aggregate signature prover, which takes a few minutes; the first \
             signing round waits for it if it is not finished by then";
            "aggregate_signature_type" => %self.aggregate_signature_type
        );
        let aggregate_signature_type = self.aggregate_signature_type;
        let trusted_setup_provider =
            TrustedSetupProvider::with_downloader(self.trusted_setup_downloader.clone());
        let logger = self.logger.clone();

        thread::spawn(move || {
            let started_at = Instant::now();
            match SnarkProverSetupWarmer::warm(
                &protocol_parameters,
                aggregate_signature_type,
                &trusted_setup_provider,
            ) {
                Ok(()) => info!(
                    logger, "Aggregate signature prover warmed up";
                    "elapsed_seconds" => started_at.elapsed().as_secs()
                ),
                Err(error) => warn!(
                    logger, "Failed to warm up the aggregate signature prover";
                    "error" => ?error
                ),
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::crypto_helper::NoTrustedSetupDownload;
    use mithril_common::entities::{self, Epoch, TimePoint};
    use mithril_common::test::double::{Dummy, fake_data};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;
    use mithril_protocol_config::test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider;
    use mithril_ticker::MithrilTickerService;

    use crate::test::TestLogger;

    use super::*;

    fn ticker_service_with_current_epoch(current_epoch: Option<Epoch>) -> Arc<dyn TickerService> {
        let time_point = current_epoch.map(|epoch| TimePoint {
            epoch,
            ..TimePoint::dummy()
        });

        Arc::new(MithrilTickerService::new(
            Arc::new(FakeChainObserver::new(time_point)),
            Arc::new(DumbImmutableFileObserver::default()),
        ))
    }

    fn provider_aggregating_with(
        protocol_parameters: entities::ProtocolParameters,
    ) -> Arc<FakeMithrilNetworkConfigurationProvider> {
        Arc::new(FakeMithrilNetworkConfigurationProvider::new(
            MithrilNetworkConfigurationForEpoch {
                protocol_parameters,
                ..Dummy::dummy()
            },
            MithrilNetworkConfigurationForEpoch::dummy(),
            MithrilNetworkConfigurationForEpoch::dummy(),
        ))
    }

    #[tokio::test]
    async fn resolves_the_parameters_the_current_epoch_aggregates_with() {
        let protocol_parameters = entities::ProtocolParameters::new(7, 42, 0.5);
        let warmer = SnarkAggregateSignatureProverWarmer::new(
            AggregateSignatureType::Snark,
            ticker_service_with_current_epoch(Some(Epoch(3))),
            provider_aggregating_with(protocol_parameters.clone()),
            Arc::new(NoTrustedSetupDownload),
            TestLogger::stdout(),
        );

        let resolved = warmer.protocol_parameters_for_aggregation().await.unwrap();

        assert_eq!(
            protocol_parameters,
            entities::ProtocolParameters::from(resolved)
        );
    }

    #[tokio::test]
    async fn fails_when_the_current_epoch_cannot_be_read() {
        let warmer = SnarkAggregateSignatureProverWarmer::new(
            AggregateSignatureType::Snark,
            ticker_service_with_current_epoch(None),
            provider_aggregating_with(fake_data::protocol_parameters()),
            Arc::new(NoTrustedSetupDownload),
            TestLogger::stdout(),
        );

        warmer
            .warm_up()
            .await
            .expect_err("the warm-up must surface an unreadable epoch");
    }
}
