use anyhow::anyhow;
use std::future::{Future, pending};

use mithril_client::MithrilResult;

/// Wait until the process receives a shutdown signal: `Ctrl-C` (`SIGINT` on unix), or `SIGTERM`
/// and `SIGHUP` (e.g. when the terminal is closed) on unix.
///
/// Once called, the default behavior of those signals (terminating the process) is replaced for
/// the rest of the process lifetime.
///
/// If the signals can not be listened to, it never completes.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let (terminate, hangup) = {
        use tokio::signal::unix::SignalKind;
        (
            unix_signal(SignalKind::terminate()),
            unix_signal(SignalKind::hangup()),
        )
    };
    #[cfg(not(unix))]
    let (terminate, hangup) = (pending::<()>(), pending::<()>());

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = hangup => {},
    }
}

/// Wait until the process receives the given unix signal, never completes if it can not be
/// listened to.
#[cfg(unix)]
async fn unix_signal(kind: tokio::signal::unix::SignalKind) {
    match tokio::signal::unix::signal(kind) {
        Ok(mut signal) => {
            signal.recv().await;
        }
        Err(_) => pending::<()>().await,
    }
}

/// Run the given future until it completes, or until the given signal is received, in which case
/// the future is dropped and an error is returned.
pub async fn run_until_signal<T>(
    future: impl Future<Output = MithrilResult<T>>,
    signal: impl Future<Output = ()>,
) -> MithrilResult<T> {
    tokio::select! {
        result = future => result,
        _ = signal => Err(anyhow!("Interrupted by a shutdown signal")),
    }
}

#[cfg(test)]
mod tests {
    use std::future::ready;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn returns_the_future_result_when_it_completes_before_the_signal() {
        let result = run_until_signal(ready(Ok(42)), pending()).await;

        assert_eq!(42, result.unwrap());
    }

    #[tokio::test]
    async fn returns_the_future_error_when_it_fails_before_the_signal() {
        let result: MithrilResult<()> =
            run_until_signal(ready(Err(anyhow::anyhow!("future error"))), pending()).await;

        assert_eq!("future error", result.unwrap_err().to_string());
    }

    #[tokio::test]
    async fn returns_an_error_when_the_signal_is_received_before_the_future_completes() {
        let result: MithrilResult<()> = tokio::time::timeout(
            Duration::from_secs(1),
            run_until_signal(pending(), ready(())),
        )
        .await
        .expect("should not wait for the future when the signal is received");

        assert!(
            result.unwrap_err().to_string().contains("Interrupted"),
            "should be an interruption error"
        );
    }
}
