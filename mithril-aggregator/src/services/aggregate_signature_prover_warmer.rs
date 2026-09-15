//! Warm-up of the aggregate signature prover ahead of the first signing round.

use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, info, warn};

use mithril_common::crypto_helper::{ProtocolParameters, SnarkProverSetupWarmer};
use mithril_common::logging::LoggerExtensions;
use mithril_common::{AggregateSignatureType, StdResult};
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_ticker::TickerService;

/// Warms up the aggregate signature prover, so the first signing round does not materialize the
/// prover setup inside its aggregation.
#[async_trait]
pub trait AggregateSignatureProverWarmer: Send + Sync {
    /// Warms up the prover of the current epoch.
    ///
    /// Fails when the protocol parameters of the current epoch cannot be read, in which case the
    /// setup is materialized on first use.
    async fn warm_up(&self) -> StdResult<()>;
}

/// Warms up the SNARK prover setups on a thread of their own, into the process-wide cache the
/// provers read, so a shutdown never waits for them.
pub struct SnarkAggregateSignatureProverWarmer {
    aggregate_signature_type: AggregateSignatureType,
    ticker_service: Arc<dyn TickerService>,
    network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
    logger: Logger,
}

impl SnarkAggregateSignatureProverWarmer {
    /// Factory
    pub fn new(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
        network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        logger: Logger,
    ) -> Self {
        Self {
            aggregate_signature_type,
            ticker_service,
            network_configuration_provider,
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
        let logger = self.logger.clone();

        thread::spawn(move || {
            let started_at = Instant::now();
            match SnarkProverSetupWarmer::warm(&protocol_parameters, aggregate_signature_type) {
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
    use anyhow::anyhow;

    use mithril_common::entities::{self, Epoch, TimePoint};
    use mithril_common::test::double::{Dummy, fake_data};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;
    use mithril_protocol_config::test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider;

    use crate::test::TestLogger;

    use super::*;

    struct TickerAtEpoch(Epoch);

    #[async_trait]
    impl TickerService for TickerAtEpoch {
        async fn get_current_time_point(&self) -> StdResult<TimePoint> {
            Ok(TimePoint {
                epoch: self.0,
                ..TimePoint::dummy()
            })
        }
    }

    struct FailingTicker;

    #[async_trait]
    impl TickerService for FailingTicker {
        async fn get_current_time_point(&self) -> StdResult<TimePoint> {
            Err(anyhow!("ticker failure"))
        }
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
            Arc::new(TickerAtEpoch(Epoch(3))),
            provider_aggregating_with(protocol_parameters.clone()),
            TestLogger::stdout(),
        );

        let resolved = warmer.protocol_parameters_for_aggregation().await.unwrap();

        assert_eq!(
            protocol_parameters,
            entities::ProtocolParameters::from(resolved)
        );
    }

    #[tokio::test]
    async fn concatenation_has_nothing_to_warm_up() {
        let warmer = SnarkAggregateSignatureProverWarmer::new(
            AggregateSignatureType::Concatenation,
            Arc::new(FailingTicker),
            provider_aggregating_with(fake_data::protocol_parameters()),
            TestLogger::stdout(),
        );

        warmer
            .warm_up()
            .await
            .expect("a concatenation aggregate signature must not read the epoch");
    }

    #[tokio::test]
    async fn fails_when_the_current_epoch_cannot_be_read() {
        let warmer = SnarkAggregateSignatureProverWarmer::new(
            AggregateSignatureType::Snark,
            Arc::new(FailingTicker),
            provider_aggregating_with(fake_data::protocol_parameters()),
            TestLogger::stdout(),
        );

        warmer
            .warm_up()
            .await
            .expect_err("the warm-up must surface an unreadable epoch");
    }
}
