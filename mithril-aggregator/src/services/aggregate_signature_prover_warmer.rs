//! Warm-up of the aggregate signature prover ahead of the first signing round.

use std::future::Future;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use rand_core::{OsRng, RngCore};
use slog::{Logger, error, info, warn};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::sleep;

use mithril_common::crypto_helper::{
    ProtocolParameters, SnarkProverSetupWarmer, TrustedSetupError, TrustedSetupProvider,
};
use mithril_common::logging::LoggerExtensions;
use mithril_common::{AggregateSignatureType, StdResult};
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_ticker::TickerService;

use crate::services::TrustedSetupDownloadError;

/// Errors of the prover warm-up that no further attempt resolves.
#[derive(Debug, Error)]
pub enum ProverWarmUpError {
    /// The thread materializing the setups stopped without reporting its outcome, which only a
    /// panic causes, so attempting the same materialization again would panic the same way.
    #[error("The prover setup warm-up thread panicked before reporting its outcome")]
    SetupThreadPanicked,
}

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
    trusted_setup_provider: Arc<TrustedSetupProvider>,
    retry_delay: Duration,
    max_retry_delay: Duration,
    logger: Logger,
}

impl SnarkAggregateSignatureProverWarmer {
    /// Delay before the first warm-up retry, doubled before each further attempt.
    pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(60);

    /// Ceiling the doubled retry delay is capped at.
    pub const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(900);

    /// Fraction of a retry delay the random extra wait is drawn from.
    const RETRY_DELAY_JITTER_RATIO: u128 = 4;

    /// Factory
    pub fn new(
        aggregate_signature_type: AggregateSignatureType,
        ticker_service: Arc<dyn TickerService>,
        network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        trusted_setup_provider: Arc<TrustedSetupProvider>,
        retry_delay: Duration,
        max_retry_delay: Duration,
        logger: Logger,
    ) -> Self {
        Self {
            aggregate_signature_type,
            ticker_service,
            network_configuration_provider,
            trusted_setup_provider,
            retry_delay,
            max_retry_delay,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Whether attempting the failed work again can succeed where `error` did not.
    ///
    /// An epoch the node cannot read yet, a connection that drops and a server error all resolve
    /// on their own. An SRS whose hash does not match the one pinned in the library, a provider
    /// with no downloader, a download issued from a runtime thread, a request the server answers
    /// with a client error, a node shutting down and a setup thread that panicked each describe
    /// a state no further attempt changes.
    fn is_retryable(error: &anyhow::Error) -> bool {
        let setup_retryable = match error.downcast_ref::<TrustedSetupError>() {
            Some(
                TrustedSetupError::VerifyHashFail { .. } | TrustedSetupError::DownloadUnavailable,
            ) => false,
            None => true,
        };
        let download_retryable = match error.downcast_ref::<TrustedSetupDownloadError>() {
            Some(
                TrustedSetupDownloadError::CalledFromRuntimeThread
                | TrustedSetupDownloadError::Stopped { .. }
                | TrustedSetupDownloadError::Rejected { .. },
            ) => false,
            Some(TrustedSetupDownloadError::AttemptsExhausted { .. }) | None => true,
        };
        let warm_up_retryable = match error.downcast_ref::<ProverWarmUpError>() {
            Some(ProverWarmUpError::SetupThreadPanicked) => false,
            None => true,
        };

        setup_retryable && download_retryable && warm_up_retryable
    }

    /// Whether `error` reports the node shutting down while the warm-up was running, which is no
    /// failure of the warm-up itself.
    fn is_shutdown(error: &anyhow::Error) -> bool {
        matches!(
            error.downcast_ref::<TrustedSetupDownloadError>(),
            Some(TrustedSetupDownloadError::Stopped { .. })
        )
    }

    /// Delay before the attempt following `failed_attempts` failures, doubling from `base_delay`
    /// up to `max_delay`, plus a random extra wait so the nodes of a fleet restarted together do
    /// not retry in lockstep.
    fn retry_delay_for(
        failed_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
    ) -> Duration {
        let delay = base_delay
            .saturating_mul(2u32.saturating_pow(failed_attempts.saturating_sub(1)))
            .min(max_delay);
        let jitter_span =
            u64::try_from(delay.as_nanos() / Self::RETRY_DELAY_JITTER_RATIO).unwrap_or(u64::MAX);

        match jitter_span {
            0 => delay,
            span => delay.saturating_add(Duration::from_nanos(OsRng.next_u64() % span)),
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

    /// Runs `materialize` on a thread of its own, which the SRS download blocks for the whole
    /// transfer, and reports its outcome without blocking the runtime.
    async fn materialize_on_own_thread<M>(materialize: M) -> StdResult<()>
    where
        M: FnOnce() -> StdResult<()> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        thread::spawn(move || {
            let _ = sender.send(materialize());
        });

        receiver.await.map_err(|_| ProverWarmUpError::SetupThreadPanicked)?
    }

    /// One warm-up attempt: resolves the parameters of the current epoch, then materializes the
    /// setups on a thread of its own.
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

        Self::materialize_on_own_thread(move || {
            SnarkProverSetupWarmer::warm(
                &protocol_parameters,
                aggregate_signature_type,
                &trusted_setup_provider,
            )
        })
        .await
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
        let trusted_setup_provider = self.trusted_setup_provider.clone();
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
                Err(error) if Self::is_shutdown(&error) => info!(
                    logger, "Aggregate signature prover warm-up abandoned, the node is shutting down";
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
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;
    use httpmock::{Method::GET, MockServer};
    use tokio::runtime::Runtime;
    use tokio::sync::watch;
    use tokio::task::yield_now;
    use tokio::time::{Instant, timeout};

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::crypto_helper::{NoTrustedSetupDownload, TrustedSetupDownloader};
    use mithril_common::entities::{self, Epoch, TimePoint};
    use mithril_common::temp_dir_create;
    use mithril_common::test::double::{Dummy, fake_data};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;
    use mithril_protocol_config::test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider;
    use mithril_ticker::MithrilTickerService;

    use crate::services::{
        ReqwestTrustedSetupDownloader, TrustedSetupDownloadRetryPolicy,
        TrustedSetupDownloadTimeouts,
    };
    use crate::test::TestLogger;

    use super::*;

    struct RecordingTickerService {
        epoch_reads: AtomicUsize,
        epoch_readable: bool,
    }

    impl RecordingTickerService {
        fn readable() -> Self {
            Self {
                epoch_reads: AtomicUsize::new(0),
                epoch_readable: true,
            }
        }

        fn unreadable() -> Self {
            Self {
                epoch_reads: AtomicUsize::new(0),
                epoch_readable: false,
            }
        }

        fn epoch_reads(&self) -> usize {
            self.epoch_reads.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl TickerService for RecordingTickerService {
        async fn get_current_time_point(&self) -> StdResult<TimePoint> {
            self.epoch_reads.fetch_add(1, Ordering::SeqCst);

            if self.epoch_readable {
                Ok(TimePoint::dummy())
            } else {
                Err(anyhow!("the epoch cannot be read"))
            }
        }
    }

    struct StoppingTrustedSetupDownloader;

    impl TrustedSetupDownloader for StoppingTrustedSetupDownloader {
        fn download(&self) -> StdResult<Vec<u8>> {
            Err(TrustedSetupDownloadError::Stopped {
                url: "https://srs.example/srs".to_string(),
            }
            .into())
        }
    }

    fn provider_without_download_in(cache_folder: PathBuf) -> Arc<TrustedSetupProvider> {
        Arc::new(TrustedSetupProvider::new(
            cache_folder,
            "expected srs hash",
            Arc::new(NoTrustedSetupDownload),
        ))
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        timeout(Duration::from_secs(10), async {
            while !condition() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the condition must be met within ten seconds");
    }

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
        trusted_setup_provider: Arc<TrustedSetupProvider>,
        logger: Logger,
    ) -> SnarkAggregateSignatureProverWarmer {
        SnarkAggregateSignatureProverWarmer::new(
            aggregate_signature_type,
            ticker_service,
            provider_aggregating_with(fake_data::protocol_parameters()),
            trusted_setup_provider,
            SnarkAggregateSignatureProverWarmer::DEFAULT_RETRY_DELAY,
            SnarkAggregateSignatureProverWarmer::DEFAULT_MAX_RETRY_DELAY,
            logger,
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
        let ticker_service = Arc::new(RecordingTickerService::unreadable());

        warmer(
            AggregateSignatureType::Concatenation,
            ticker_service.clone(),
            provider_without_download_in(temp_dir_create!()),
            TestLogger::stdout(),
        )
        .warm_up()
        .await
        .unwrap();
        yield_now().await;

        assert_eq!(
            0,
            ticker_service.epoch_reads(),
            "a concatenation node must not read the epoch its warm-up would start from"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn snark_warm_up_retries_reading_the_epoch_it_starts_from() {
        let ticker_service = Arc::new(RecordingTickerService::unreadable());

        warmer(
            AggregateSignatureType::Snark,
            ticker_service.clone(),
            provider_without_download_in(temp_dir_create!()),
            TestLogger::stdout(),
        )
        .warm_up()
        .await
        .unwrap();
        yield_now().await;
        let epoch_reads_before_the_retry_delay = ticker_service.epoch_reads();
        sleep(SnarkAggregateSignatureProverWarmer::DEFAULT_RETRY_DELAY * 2).await;

        assert_eq!(
            1, epoch_reads_before_the_retry_delay,
            "the warm-up must read the epoch once before waiting for a retry"
        );
        assert_eq!(
            2,
            ticker_service.epoch_reads(),
            "the warm-up must read the epoch again after the retry delay"
        );
    }

    #[tokio::test]
    async fn snark_warm_up_gives_up_on_a_failure_no_attempt_resolves() {
        let (logger, log_inspector) = TestLogger::memory();
        let ticker_service = Arc::new(RecordingTickerService::readable());

        warmer(
            AggregateSignatureType::Snark,
            ticker_service.clone(),
            provider_without_download_in(temp_dir_create!()),
            logger,
        )
        .warm_up()
        .await
        .unwrap();
        wait_until(|| {
            log_inspector.contains_log("Gave up warming up the aggregate signature prover")
        })
        .await;

        assert_eq!(
            1,
            ticker_service.epoch_reads(),
            "a warm-up failing with a missing SRS download must not be attempted again"
        );
    }

    #[tokio::test]
    async fn snark_warm_up_abandoned_by_a_shutdown_is_not_reported_as_a_failure() {
        let (logger, log_inspector) = TestLogger::memory();
        let trusted_setup_provider = Arc::new(TrustedSetupProvider::new(
            temp_dir_create!(),
            "expected srs hash",
            Arc::new(StoppingTrustedSetupDownloader),
        ));

        warmer(
            AggregateSignatureType::Snark,
            Arc::new(RecordingTickerService::readable()),
            trusted_setup_provider,
            logger,
        )
        .warm_up()
        .await
        .unwrap();
        wait_until(|| log_inspector.contains_log("warm-up abandoned")).await;

        assert!(
            !log_inspector.contains_log("Gave up warming up"),
            "a shutdown must not be reported as a warm-up failure"
        );
    }

    #[tokio::test]
    async fn warm_once_reports_the_failure_of_the_setup_materialization() {
        let error = SnarkAggregateSignatureProverWarmer::warm_once(
            AggregateSignatureType::Snark,
            Arc::new(RecordingTickerService::readable()),
            provider_aggregating_with(fake_data::protocol_parameters()),
            provider_without_download_in(temp_dir_create!()),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupError>(),
                Some(TrustedSetupError::DownloadUnavailable)
            ),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test(start_paused = true)]
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
            SnarkAggregateSignatureProverWarmer::DEFAULT_RETRY_DELAY,
            SnarkAggregateSignatureProverWarmer::DEFAULT_MAX_RETRY_DELAY,
            &TestLogger::stdout(),
        )
        .await
        .unwrap();

        assert_eq!(3, attempts, "the warm-up must be retried until it succeeds");
    }

    #[tokio::test(start_paused = true)]
    async fn waits_a_doubling_delay_capped_at_the_ceiling_before_each_further_attempt() {
        let base_delay = Duration::from_secs(60);
        let max_delay = Duration::from_secs(150);
        let mut attempts_at = Vec::new();

        SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts_at.push(Instant::now());
                let outcome = if attempts_at.len() < 4 {
                    Err(anyhow!("warm-up attempt {} failed", attempts_at.len()))
                } else {
                    Ok(())
                };

                async move { outcome }
            },
            base_delay,
            max_delay,
            &TestLogger::stdout(),
        )
        .await
        .unwrap();

        let waits = attempts_at.windows(2).map(|attempts| attempts[1] - attempts[0]);
        for (wait, backoff) in waits.zip([60, 120, 150].map(Duration::from_secs)) {
            assert!(
                (backoff..backoff + backoff / 4).contains(&wait),
                "the loop must wait {backoff:?} plus jitter, waited {wait:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_a_successful_warm_up() {
        let mut attempts = 0;

        SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts += 1;

                async move { Ok(()) }
            },
            SnarkAggregateSignatureProverWarmer::DEFAULT_RETRY_DELAY,
            SnarkAggregateSignatureProverWarmer::DEFAULT_MAX_RETRY_DELAY,
            &TestLogger::stdout(),
        )
        .await
        .unwrap();

        assert_eq!(1, attempts, "a successful warm-up must not be retried");
    }

    #[tokio::test(start_paused = true)]
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
            SnarkAggregateSignatureProverWarmer::DEFAULT_RETRY_DELAY,
            SnarkAggregateSignatureProverWarmer::DEFAULT_MAX_RETRY_DELAY,
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
        let (_stop_tx, stop_rx) = watch::channel(());
        let downloader = ReqwestTrustedSetupDownloader::new(
            server.url("/srs"),
            runtime.handle().clone(),
            stop_rx,
            TrustedSetupDownloadTimeouts::default(),
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

    #[tokio::test]
    async fn materializing_on_its_own_thread_reports_a_successful_materialization() {
        SnarkAggregateSignatureProverWarmer::materialize_on_own_thread(|| Ok(()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn materializing_on_its_own_thread_reports_the_outcome_of_the_materialization() {
        let error = SnarkAggregateSignatureProverWarmer::materialize_on_own_thread(|| {
            Err(anyhow!("materialization failed"))
        })
        .await
        .unwrap_err();

        assert_eq!("materialization failed", error.to_string());
    }

    #[tokio::test]
    async fn a_setup_thread_that_panics_stops_the_warm_up() {
        let mut attempts = 0;

        let error = SnarkAggregateSignatureProverWarmer::warm_until_done(
            || {
                attempts += 1;

                SnarkAggregateSignatureProverWarmer::materialize_on_own_thread(|| {
                    panic!("the setup materialization panicked")
                })
            },
            Duration::ZERO,
            Duration::ZERO,
            &TestLogger::stdout(),
        )
        .await
        .expect_err("a setup thread that panicked must stop the warm-up");

        assert_eq!(
            1, attempts,
            "a panicking materialization must not be retried"
        );
        assert!(
            matches!(
                error.downcast_ref::<ProverWarmUpError>(),
                Some(ProverWarmUpError::SetupThreadPanicked)
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn a_provider_without_download_is_not_retryable() {
        let error = TrustedSetupError::DownloadUnavailable.into();

        assert!(!SnarkAggregateSignatureProverWarmer::is_retryable(&error));
    }

    #[test]
    fn a_download_abandoned_by_a_stopping_node_is_not_retryable() {
        let error = TrustedSetupDownloadError::Stopped {
            url: "https://srs.example/srs".to_string(),
        }
        .into();

        assert!(!SnarkAggregateSignatureProverWarmer::is_retryable(&error));
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
    fn retry_delay_adds_a_random_extra_wait_below_a_quarter_of_the_backoff() {
        let backoff = Duration::from_secs(60);

        let delays: HashSet<Duration> = (0..100)
            .map(|_| {
                SnarkAggregateSignatureProverWarmer::retry_delay_for(
                    1,
                    backoff,
                    Duration::from_secs(900),
                )
            })
            .collect();

        assert!(
            delays.len() > 1,
            "the extra wait must be random, every delay was {delays:?}"
        );
        assert!(
            delays
                .iter()
                .all(|delay| (backoff..backoff + backoff / 4).contains(delay)),
            "every delay must be the backoff plus less than a quarter of it, got {delays:?}"
        );
    }

    #[test]
    fn retry_delay_of_a_zero_base_delay_stays_zero() {
        let delay =
            SnarkAggregateSignatureProverWarmer::retry_delay_for(9, Duration::ZERO, Duration::ZERO);

        assert_eq!(Duration::ZERO, delay);
    }
}
