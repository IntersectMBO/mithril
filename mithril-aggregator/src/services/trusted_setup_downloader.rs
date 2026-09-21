//! Download of the trusted setup SRS with the aggregator HTTP client.

use std::thread;
use std::time::Duration;

use anyhow::Context;
use reqwest::header::USER_AGENT;
use reqwest::{Client, StatusCode, Url, redirect};
use slog::{Logger, info, warn};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::watch;

use mithril_common::StdResult;
use mithril_common::crypto_helper::TrustedSetupDownloader;
use mithril_common::logging::LoggerExtensions;

/// Errors of the SRS download.
#[derive(Debug, Error)]
pub enum TrustedSetupDownloadError {
    /// The download was called from a thread of the runtime it bridges onto, which it would block.
    #[error(
        "The SRS download blocks its thread for the whole transfer and must not run on a runtime thread"
    )]
    CalledFromRuntimeThread,
    /// The node started shutting down, so no further attempt was made.
    #[error("SRS download from '{url}' was abandoned because the node is shutting down")]
    Stopped {
        /// URL the SRS was requested from.
        url: String,
    },
    /// The server answered with a status that another attempt cannot change.
    #[error("SRS download from '{url}' was rejected by the server with status {status}")]
    Rejected {
        /// URL the SRS was requested from.
        url: String,
        /// Status the server answered with.
        status: StatusCode,
        /// Error carrying that status.
        #[source]
        source: reqwest::Error,
    },
    /// Every attempt allowed by the retry policy failed.
    #[error("SRS download from '{url}' failed after {attempts} attempts")]
    AttemptsExhausted {
        /// URL the SRS was requested from.
        url: String,
        /// Number of attempts made.
        attempts: usize,
        /// Error of the last attempt.
        #[source]
        source: reqwest::Error,
    },
}

/// Policy for retrying the download of the SRS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSetupDownloadRetryPolicy {
    /// Number of attempts to download the SRS.
    pub attempts: usize,
    /// Delay between two attempts.
    pub delay_between_attempts: Duration,
}

impl TrustedSetupDownloadRetryPolicy {
    /// Policy that never retries.
    pub fn never() -> Self {
        Self {
            attempts: 1,
            delay_between_attempts: Duration::ZERO,
        }
    }
}

impl Default for TrustedSetupDownloadRetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            delay_between_attempts: Duration::from_secs(5),
        }
    }
}

/// Timeouts of one download attempt of the SRS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSetupDownloadTimeouts {
    /// Longest the connection may take to be established.
    pub connect: Duration,
    /// Longest the transfer may stall before the attempt is abandoned.
    ///
    /// This is an idle timeout rather than a deadline for the whole download, so an SRS of several
    /// hundred megabytes keeps going on a slow link for as long as bytes keep arriving.
    pub read: Duration,
    /// Longest the attempt may last as a whole, so a host trickling bytes cannot hold the prover
    /// setup lock indefinitely.
    pub total: Duration,
}

impl Default for TrustedSetupDownloadTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(60),
            total: Duration::from_secs(1800),
        }
    }
}

/// Downloads the SRS of the trusted setup with the aggregator HTTP client, from the thread the
/// prover warm-up runs on.
///
/// The library expects a synchronous download while the client is asynchronous, so each attempt is
/// bridged onto the runtime whose handle was captured at construction. The bridge blocks the calling
/// thread for the whole transfer, so a call from a thread of that runtime is refused rather than
/// stalling one of its workers.
pub struct ReqwestTrustedSetupDownloader {
    client: Client,
    runtime_handle: Handle,
    stop_rx: watch::Receiver<()>,
    url: String,
    retry_policy: TrustedSetupDownloadRetryPolicy,
    logger: Logger,
}

impl ReqwestTrustedSetupDownloader {
    /// Largest number of redirects an attempt follows.
    const MAX_REDIRECTS: usize = 5;

    /// Factory
    pub fn new(
        url: String,
        runtime_handle: Handle,
        stop_rx: watch::Receiver<()>,
        timeouts: TrustedSetupDownloadTimeouts,
        retry_policy: TrustedSetupDownloadRetryPolicy,
        logger: Logger,
    ) -> StdResult<Self> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(timeouts.connect)
                .read_timeout(timeouts.read)
                .timeout(timeouts.total)
                .redirect(Self::redirect_policy())
                .build()
                .with_context(|| "Trusted setup downloader HTTP client creation failed")?,
            runtime_handle,
            stop_rx,
            url,
            retry_policy,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    /// Follows a bounded number of redirects, and none that leaves HTTPS, so the transfer cannot be
    /// moved to cleartext by the server.
    fn redirect_policy() -> redirect::Policy {
        redirect::Policy::custom(|attempt| {
            let refusal = attempt.previous().first().and_then(|requested| {
                Self::redirect_refusal(requested, attempt.url(), attempt.previous().len())
            });

            match refusal {
                Some(reason) => attempt.error(reason),
                None => attempt.follow(),
            }
        })
    }

    /// Why the `hop`th redirect of a download requested at `requested` towards `next` is refused,
    /// if it is: it leaves HTTPS, or it follows too many redirects.
    fn redirect_refusal(requested: &Url, next: &Url, hop: usize) -> Option<&'static str> {
        if requested.scheme() == "https" && next.scheme() != "https" {
            Some("the SRS download refuses a redirect that leaves HTTPS")
        } else if hop > Self::MAX_REDIRECTS {
            Some("the SRS download followed too many redirects")
        } else {
            None
        }
    }

    /// Whether `status` is an answer no further attempt changes: a client error, except the two
    /// asking for a later attempt, a request timeout and a rate limit.
    fn is_rejection(status: &StatusCode) -> bool {
        status.is_client_error()
            && !matches!(
                *status,
                StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
            )
    }

    /// One download attempt, run on the runtime.
    async fn download_once(&self) -> Result<Vec<u8>, reqwest::Error> {
        let response = self
            .client
            .get(&self.url)
            .header(USER_AGENT, "mithril-aggregator")
            .send()
            .await?
            .error_for_status()?;

        Ok(response.bytes().await?.to_vec())
    }
}

impl TrustedSetupDownloader for ReqwestTrustedSetupDownloader {
    fn download(&self) -> StdResult<Vec<u8>> {
        if Handle::try_current().is_ok() {
            return Err(TrustedSetupDownloadError::CalledFromRuntimeThread.into());
        }

        let attempts = self.retry_policy.attempts.max(1);
        let mut attempt = 1;
        loop {
            if self.stop_rx.has_changed().unwrap_or(true) {
                return Err(TrustedSetupDownloadError::Stopped {
                    url: self.url.clone(),
                }
                .into());
            }

            info!(
                self.logger, "Downloading the SRS of the trusted setup";
                "url" => &self.url, "attempt" => attempt, "attempts" => attempts
            );
            let error = match self.runtime_handle.block_on(self.download_once()) {
                Ok(bytes) => return Ok(bytes),
                Err(error) => error,
            };

            if let Some(status) = error.status().filter(Self::is_rejection) {
                return Err(TrustedSetupDownloadError::Rejected {
                    url: self.url.clone(),
                    status,
                    source: error,
                }
                .into());
            }

            if attempt >= attempts {
                return Err(TrustedSetupDownloadError::AttemptsExhausted {
                    url: self.url.clone(),
                    attempts: attempt,
                    source: error,
                }
                .into());
            }

            warn!(
                self.logger, "SRS download attempt failed, retrying";
                "attempt" => attempt, "error" => ?error
            );
            thread::sleep(self.retry_policy.delay_between_attempts);
            attempt += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method::GET, MockServer};
    use tokio::runtime::Runtime;

    use crate::test::TestLogger;

    use super::*;

    fn timeouts(total: Duration) -> TrustedSetupDownloadTimeouts {
        TrustedSetupDownloadTimeouts {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(5),
            total,
        }
    }

    fn downloader_with_timeouts(
        url: String,
        runtime_handle: Handle,
        timeouts: TrustedSetupDownloadTimeouts,
        retry_policy: TrustedSetupDownloadRetryPolicy,
    ) -> (ReqwestTrustedSetupDownloader, watch::Sender<()>) {
        let (stop_tx, stop_rx) = watch::channel(());
        let downloader = ReqwestTrustedSetupDownloader::new(
            url,
            runtime_handle,
            stop_rx,
            timeouts,
            retry_policy,
            TestLogger::stdout(),
        )
        .unwrap();

        (downloader, stop_tx)
    }

    fn downloader(
        url: String,
        runtime_handle: Handle,
        retry_policy: TrustedSetupDownloadRetryPolicy,
    ) -> (ReqwestTrustedSetupDownloader, watch::Sender<()>) {
        downloader_with_timeouts(
            url,
            runtime_handle,
            timeouts(Duration::from_secs(5)),
            retry_policy,
        )
    }

    fn retry_policy(attempts: usize) -> TrustedSetupDownloadRetryPolicy {
        TrustedSetupDownloadRetryPolicy {
            attempts,
            delay_between_attempts: Duration::ZERO,
        }
    }

    #[test]
    fn downloads_the_bytes_served_at_the_url_on_the_first_successful_attempt() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );

        let bytes = downloader.download().unwrap();

        assert_eq!(b"srs bytes".to_vec(), bytes);
        mock.assert_calls(1);
    }

    #[test]
    fn refuses_to_download_from_a_runtime_thread() {
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader(
            "http://127.0.0.1:1/srs".to_string(),
            runtime.handle().clone(),
            retry_policy(1),
        );

        let error = runtime.block_on(async { downloader.download() }).unwrap_err();

        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::CalledFromRuntimeThread)
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retries_a_failing_download_up_to_the_policy_attempts() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(500);
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(3);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::AttemptsExhausted { attempts: 3, .. })
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn does_not_retry_a_download_the_server_rejects_with_a_client_error() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(404);
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(1);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::Rejected {
                    status: StatusCode::NOT_FOUND,
                    ..
                })
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retries_a_download_the_server_asks_to_attempt_later() {
        for status in [
            StatusCode::REQUEST_TIMEOUT.as_u16(),
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
        ] {
            let server = MockServer::start();
            let mock = server.mock(|when, then| {
                when.method(GET).path("/srs");
                then.status(status);
            });
            let runtime = Runtime::new().unwrap();
            let (downloader, _stop_tx) = downloader(
                server.url("/srs"),
                runtime.handle().clone(),
                retry_policy(3),
            );

            let error = downloader.download().unwrap_err();

            mock.assert_calls(3);
            assert!(
                matches!(
                    error.downcast_ref::<TrustedSetupDownloadError>(),
                    Some(TrustedSetupDownloadError::AttemptsExhausted { attempts: 3, .. })
                ),
                "status {status} must be retried, got: {error:?}"
            );
        }
    }

    #[test]
    fn abandons_an_attempt_that_exceeds_the_whole_transfer_deadline() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).delay(Duration::from_secs(2)).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader_with_timeouts(
            server.url("/srs"),
            runtime.handle().clone(),
            timeouts(Duration::from_millis(200)),
            TrustedSetupDownloadRetryPolicy::never(),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(1);
        match error.downcast_ref::<TrustedSetupDownloadError>() {
            Some(TrustedSetupDownloadError::AttemptsExhausted { source, .. }) => {
                assert!(source.is_timeout(), "unexpected error: {source:?}")
            }
            _ => panic!("unexpected error: {error:?}"),
        }
    }

    #[test]
    fn abandons_an_attempt_whose_transfer_stalls_longer_than_the_read_timeout() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).delay(Duration::from_secs(2)).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader_with_timeouts(
            server.url("/srs"),
            runtime.handle().clone(),
            TrustedSetupDownloadTimeouts {
                connect: Duration::from_secs(5),
                read: Duration::from_millis(200),
                total: Duration::from_secs(5),
            },
            TrustedSetupDownloadRetryPolicy::never(),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(1);
        match error.downcast_ref::<TrustedSetupDownloadError>() {
            Some(TrustedSetupDownloadError::AttemptsExhausted { source, .. }) => {
                assert!(source.is_timeout(), "unexpected error: {source:?}")
            }
            _ => panic!("unexpected error: {error:?}"),
        }
    }

    #[test]
    fn abandons_the_download_when_the_stop_signal_sender_is_gone() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );
        drop(stop_tx);

        let error = downloader.download().unwrap_err();

        mock.assert_calls(0);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::Stopped { .. })
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn abandons_the_download_when_the_node_is_stopping() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );
        stop_tx.send(()).unwrap();

        let error = downloader.download().unwrap_err();

        mock.assert_calls(0);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::Stopped { .. })
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn refuses_a_redirect_that_leaves_https() {
        let requested = Url::parse("https://srs.example/srs").unwrap();
        let next = Url::parse("http://srs.example/srs").unwrap();

        let refusal = ReqwestTrustedSetupDownloader::redirect_refusal(&requested, &next, 1);

        assert!(
            refusal.is_some_and(|reason| reason.contains("leaves HTTPS")),
            "unexpected verdict: {refusal:?}"
        );
    }

    #[test]
    fn follows_a_redirect_that_keeps_its_scheme_within_the_limit() {
        let https = Url::parse("https://srs.example/srs").unwrap();
        let http = Url::parse("http://srs.example/srs").unwrap();
        let last_allowed_hop = ReqwestTrustedSetupDownloader::MAX_REDIRECTS;

        for (requested, next) in [(&https, &https), (&http, &http), (&http, &https)] {
            let refusal =
                ReqwestTrustedSetupDownloader::redirect_refusal(requested, next, last_allowed_hop);

            assert_eq!(None, refusal, "{requested} to {next} must be followed");
        }
    }

    #[test]
    fn refuses_a_redirect_beyond_the_limit() {
        let https = Url::parse("https://srs.example/srs").unwrap();
        let first_refused_hop = ReqwestTrustedSetupDownloader::MAX_REDIRECTS + 1;

        let refusal =
            ReqwestTrustedSetupDownloader::redirect_refusal(&https, &https, first_refused_hop);

        assert!(
            refusal.is_some_and(|reason| reason.contains("too many redirects")),
            "unexpected verdict: {refusal:?}"
        );
    }

    #[test]
    fn stops_following_an_endless_redirect_chain() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(302).header("Location", server.url("/srs"));
        });
        let runtime = Runtime::new().unwrap();
        let (downloader, _stop_tx) = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            TrustedSetupDownloadRetryPolicy::never(),
        );

        downloader.download().unwrap_err();

        assert_eq!(
            ReqwestTrustedSetupDownloader::MAX_REDIRECTS + 1,
            mock.calls(),
            "the chain must stop after the redirect limit"
        );
    }
}
