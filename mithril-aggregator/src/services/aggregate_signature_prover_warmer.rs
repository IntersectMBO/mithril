//! Warm-up of the aggregate signature prover ahead of the first signing round.

use std::future::Future;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use rand_core::{OsRng, RngCore};
use slog::{Logger, error, info, warn};
use tokio::sync::oneshot;
use tokio::time::sleep;

use mithril_common::crypto_helper::{
    ProtocolParameters, SnarkProverSetupWarmer, TrustedSetupDownloader, TrustedSetupError,
    TrustedSetupProvider,
};
use mithril_common::logging::LoggerExtensions;
use mithril_common::{AggregateSignatureType, StdResult};
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_ticker::TickerService;

use crate::services::TrustedSetupDownloadError;

/// Warms up the aggregate signature prover, so the first signing round does not materialize the
/// prover setup inside its aggregation.
#[async_trait]
pub trait AggregateSignatureProverWarmer: Send + Sync {
    /// Warms up the prover of the current epoch.
    async fn warm_up(&self) -> StdResult<()>;
}

/// Warms up the SNARK prover setups in the background, into the process-wide cache the provers
/// read, so a shutdown never waits for them. This is also the only place the SRS of the trusted
/// setup is downloaded when it is missing, since the provers only read the local cache.
///
/// A failure that a further attempt can resolve is retried with a delay that doubles up to a
/// ceiling, since a node whose setups are not materialized cannot aggregate. A failure that no
/// further attempt resolves, such as an SRS whose hash does not match, stops the warm-up instead
/// of repeating the same download forever.
pub struct SnarkAggregateSignatureProverWarmer {
    aggregate_signature_type: AggregateSignatureType,
    ticker_service: Arc<dyn TickerService>,
    network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
    trusted_setup_downloader: Arc<dyn TrustedSetupDownloader>,
    retry_delay: Duration,
    max_retry_delay: Duration,
    logger: Logger,
}

impl SnarkAggregateSignatureProverWarmer {
    /// Delay before the first warm-up retry, doubled before each further attempt.
    pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(60);

    /// Ceiling the doubled retry delay is capped at.
    pub const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(900);

    /// Largest power the retry delay is doubled by, which keeps the computation in range.
    const MAX_RETRY_DELAY_EXPONENT: u32 = 16;

    /// Fraction of a retry delay the random extra wait is drawn from.
    const RETRY_DELAY_JITTER_RATIO: u128 = 4;

    /// Factory
    pub fn new(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
        network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        trusted_setup_downloader: Arc<dyn TrustedSetupDownloader>,
        retry_delay: Duration,
        max_retry_delay: Duration,
        logger: Logger,
    ) -> Self {
        Self {
            aggregate_signature_type,
            ticker_service,
            network_configuration_provider,
            trusted_setup_downloader,
            retry_delay,
            max_retry_delay,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Whether attempting the failed work again can succeed where `error` did not.
    ///
    /// An epoch the node cannot read yet, a connection that drops and a server error all resolve
    /// on their own. An SRS whose hash does not match the one pinned in the library, a provider
    /// with no downloader, a download issued from a runtime thread and a request the server
    /// answers with a client error each describe a state no further attempt changes.
    fn is_retryable(error: &anyhow::Error) -> bool {
        if matches!(
            error.downcast_ref::<TrustedSetupError>(),
            Some(TrustedSetupError::VerifyHashFail { .. } | TrustedSetupError::DownloadUnavailable)
        ) {
            return false;
        }

        match error.downcast_ref::<TrustedSetupDownloadError>() {
            Some(TrustedSetupDownloadError::CalledFromRuntimeThread) => false,
            Some(TrustedSetupDownloadError::AttemptsExhausted { source, .. }) => {
                !source.status().is_some_and(|status| status.is_client_error())
            }
            None => true,
        }
    }

    /// Delay before `attempt`, doubling from `base_delay` up to `max_delay`, plus a random extra
    /// wait so the nodes of a fleet restarted together do not retry in lockstep.
    fn retry_delay_for(attempt: u32, base_delay: Duration, max_delay: Duration) -> Duration {
        let exponent = attempt.saturating_sub(1).min(Self::MAX_RETRY_DELAY_EXPONENT);
        let delay = base_delay
            .saturating_mul(2u32.saturating_pow(exponent))
            .min(max_delay);
        let jitter_span =
            u64::try_from(delay.as_nanos() / Self::RETRY_DELAY_JITTER_RATIO).unwrap_or(u64::MAX);

        match jitter_span {
            0 => delay,
            span => delay + Duration::from_nanos(OsRng.next_u64() % span),
        }
    }

    /// Protocol parameters the current epoch aggregates with.
    async fn protocol_parameters_for_aggregation(
        ticker_service: &Arc<dyn TickerService>,
        network_configuration_provider: &Arc<dyn MithrilNetworkConfigurationProvider>,
    ) -> StdResult<ProtocolParameters> {
        let epoch = ticker_service
            .get_current_epoch()
            .await
            .with_context(|| "Prover warmer could not get the current epoch")?;
        let network_configuration = network_configuration_provider
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

    /// One warm-up attempt: resolves the parameters of the current epoch, then materializes the
    /// setups on a thread of its own, which the SRS download blocks for the whole transfer.
    async fn warm_once(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
        network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        trusted_setup_provider: Arc<TrustedSetupProvider>,
    ) -> StdResult<()> {
        let protocol_parameters = Self::protocol_parameters_for_aggregation(
            &ticker_service,
            &network_configuration_provider,
        )
        .await?;
        let (sender, receiver) = oneshot::channel();

        thread::spawn(move || {
            let _ = sender.send(SnarkProverSetupWarmer::warm(
                &protocol_parameters,
                aggregate_signature_type,
                &trusted_setup_provider,
            ));
        });

        receiver
            .await
            .with_context(|| "The prover setup warm-up stopped before reporting its result")?
    }

    /// Runs `warm` until it succeeds or fails with an error that cannot heal, waiting longer
    /// before each further attempt.
    async fn warm_until_done<F, W>(
        mut warm: F,
        retry_delay: Duration,
        max_retry_delay: Duration,
        logger: &Logger,
    ) -> StdResult<()>
    where
        F: FnMut() -> W,
        W: Future<Output = StdResult<()>>,
    {
        let mut attempt = 1;
        loop {
            match warm().await {
                Ok(()) => return Ok(()),
                Err(error) if !Self::is_retryable(&error) => return Err(error),
                Err(error) => {
                    let delay = Self::retry_delay_for(attempt, retry_delay, max_retry_delay);
                    warn!(
                        logger, "Failed to warm up the aggregate signature prover, retrying";
                        "attempt" => attempt, "retry_delay_seconds" => delay.as_secs(), "error" => ?error
                    );
                    sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[async_trait]
impl AggregateSignatureProverWarmer for SnarkAggregateSignatureProverWarmer {
    async fn warm_up(&self) -> StdResult<()> {
        if self.aggregate_signature_type == AggregateSignatureType::Concatenation {
            return Ok(());
        }

        info!(
            self.logger,
            "Warming up the aggregate signature prover, which takes a few minutes; the first \
             signing round waits for it if it is not finished by then";
            "aggregate_signature_type" => %self.aggregate_signature_type
        );
        let aggregate_signature_type = self.aggregate_signature_type;
        let ticker_service = self.ticker_service.clone();
        let network_configuration_provider = self.network_configuration_provider.clone();
        let trusted_setup_provider = Arc::new(TrustedSetupProvider::with_downloader(
            self.trusted_setup_downloader.clone(),
        ));
        let retry_delay = self.retry_delay;
        let max_retry_delay = self.max_retry_delay;
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let started_at = Instant::now();
            let warmed_up = Self::warm_until_done(
                || {
                    Self::warm_once(
                        aggregate_signature_type,
                        ticker_service.clone(),
                        network_configuration_provider.clone(),
                        trusted_setup_provider.clone(),
                    )
                },
                retry_delay,
                max_retry_delay,
                &logger,
            )
            .await;

            match warmed_up {
                Ok(()) => info!(
                    logger, "Aggregate signature prover warmed up";
                    "elapsed_seconds" => started_at.elapsed().as_secs()
                ),
                Err(error) => error!(
                    logger, "Gave up warming up the aggregate signature prover, which cannot \
                             produce an aggregate signature until it is restarted";
                    "elapsed_seconds" => started_at.elapsed().as_secs(), "error" => ?error
                ),
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use httpmock::{Method::GET, MockServer};
    use tokio::runtime::Runtime;

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::crypto_helper::NoTrustedSetupDownload;
    use mithril_common::entities::{self, Epoch, TimePoint};
    use mithril_common::test::double::{Dummy, fake_data};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;
    use mithril_protocol_config::test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider;
    use mithril_ticker::MithrilTickerService;

    use crate::services::{ReqwestTrustedSetupDownloader, TrustedSetupDownloadRetryPolicy};
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
    ) -> Arc<dyn MithrilNetworkConfigurationProvider> {
        Arc::new(FakeMithrilNetworkConfigurationProvider::new(
            MithrilNetworkConfigurationForEpoch {
                protocol_parameters,
                ..Dummy::dummy()
            },
            MithrilNetworkConfigurationForEpoch::dummy(),
            MithrilNetworkConfigurationForEpoch::dummy(),
        ))
    }

    fn warmer(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
    ) -> SnarkAggregateSignatureProverWarmer {
        SnarkAggregateSignatureProverWarmer::new(
            aggregate_signature_type,
            ticker_service,
            provider_aggregating_with(fake_data::protocol_parameters()),
            Arc::new(NoTrustedSetupDownload),
            Duration::ZERO,
            Duration::ZERO,
            TestLogger::stdout(),
        )
    }

    #[tokio::test]
    async fn resolves_the_parameters_the_current_epoch_aggregates_with() {
        let protocol_parameters = entities::ProtocolParameters::new(7, 42, 0.5);

        let resolved = SnarkAggregateSignatureProverWarmer::protocol_parameters_for_aggregation(
            &ticker_service_with_current_epoch(Some(Epoch(3))),
            &provider_aggregating_with(protocol_parameters.clone()),
        )
        .await
        .unwrap();

        assert_eq!(
            protocol_parameters,
            entities::ProtocolParameters::from(resolved)
        );
    }

    #[tokio::test]
    async fn fails_to_resolve_the_parameters_when_the_current_epoch_cannot_be_read() {
        SnarkAggregateSignatureProverWarmer::protocol_parameters_for_aggregation(
            &ticker_service_with_current_epoch(None),
            &provider_aggregating_with(fake_data::protocol_parameters()),
        )
        .await
        .expect_err("the resolution must surface an unreadable epoch");
    }

    #[tokio::test]
    async fn concatenation_skips_the_warm_up_entirely() {
        warmer(
            AggregateSignatureType::Concatenation,
            ticker_service_with_current_epoch(None),
        )
        .warm_up()
        .await
        .expect("a concatenation node must not read the epoch nor warm up any setup");
    }

    #[tokio::test]
    async fn retries_the_warm_up_until_it_succeeds() {
        let mut attempts = 0;

        SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts += 1;
                let outcome = if attempts < 3 {
                    Err(anyhow!("warm-up attempt {attempts} failed"))
                } else {
                    Ok(())
                };

                async move { outcome }
            },
            Duration::ZERO,
            Duration::ZERO,
            &TestLogger::stdout(),
        )
        .await
        .unwrap();

        assert_eq!(3, attempts, "the warm-up must be retried until it succeeds");
    }

    #[tokio::test]
    async fn does_not_retry_a_successful_warm_up() {
        let mut attempts = 0;

        SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts += 1;

                async move { Ok(()) }
            },
            Duration::ZERO,
            Duration::ZERO,
            &TestLogger::stdout(),
        )
        .await
        .unwrap();

        assert_eq!(1, attempts, "a successful warm-up must not be retried");
    }

    #[tokio::test]
    async fn stops_retrying_an_srs_whose_hash_does_not_match() {
        let mut attempts = 0;

        let result = SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts += 1;
                let outcome = Err(TrustedSetupError::VerifyHashFail {
                    expected: "expected".to_string(),
                    computed: "computed".to_string(),
                }
                .into());

                async move { outcome }
            },
            Duration::ZERO,
            Duration::ZERO,
            &TestLogger::stdout(),
        )
        .await;

        result.expect_err("an SRS whose hash does not match must stop the warm-up");
        assert_eq!(
            1, attempts,
            "a failure no attempt resolves must be tried once"
        );
    }

    fn download_error_for_status(status: u16) -> anyhow::Error {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(status);
        });
        let runtime = Runtime::new().unwrap();
        let downloader = ReqwestTrustedSetupDownloader::new(
            server.url("/srs"),
            runtime.handle().clone(),
            Duration::from_secs(5),
            TrustedSetupDownloadRetryPolicy::never(),
            TestLogger::stdout(),
        )
        .unwrap();

        downloader.download().unwrap_err()
    }

    #[test]
    fn a_download_rejected_with_a_client_error_is_not_retryable() {
        assert!(!SnarkAggregateSignatureProverWarmer::is_retryable(
            &download_error_for_status(404)
        ));
    }

    #[test]
    fn a_download_failing_with_a_server_error_is_retryable() {
        assert!(SnarkAggregateSignatureProverWarmer::is_retryable(
            &download_error_for_status(500)
        ));
    }

    #[test]
    fn a_download_called_from_a_runtime_thread_is_not_retryable() {
        let error = TrustedSetupDownloadError::CalledFromRuntimeThread.into();

        assert!(!SnarkAggregateSignatureProverWarmer::is_retryable(&error));
    }

    #[test]
    fn retry_delay_doubles_from_the_base_delay_up_to_the_ceiling() {
        let base_delay = Duration::from_secs(60);
        let max_delay = Duration::from_secs(900);

        for (attempt, expected_seconds) in
            [(1, 60), (2, 120), (3, 240), (4, 480), (5, 900), (99, 900)]
        {
            let delay = SnarkAggregateSignatureProverWarmer::retry_delay_for(
                attempt, base_delay, max_delay,
            );
            let backoff = Duration::from_secs(expected_seconds);

            assert!(
                (backoff..backoff + backoff / 4).contains(&delay),
                "attempt {attempt} must wait {backoff:?} plus jitter, got {delay:?}"
            );
        }
    }

    #[test]
    fn retry_delay_of_a_zero_base_delay_stays_zero() {
        let delay =
            SnarkAggregateSignatureProverWarmer::retry_delay_for(9, Duration::ZERO, Duration::ZERO);

        assert_eq!(Duration::ZERO, delay);
    }
}
