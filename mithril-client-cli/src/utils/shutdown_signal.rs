use anyhow::anyhow;
use std::future::{Future, pending};

use mithril_client::MithrilResult;

/// Wait until the process receives a shutdown signal: `Ctrl-C` (`SIGINT` on unix), or `SIGTERM`
/// on unix.
///
/// Once called, the default behavior of those signals (terminating the process) is replaced for
/// the rest of the process lifetime.
///
/// Those signals are listened to even if they were ignored when the process started, e.g. `SIGINT`
/// for the background jobs of a non-interactive shell (`mithril-client … &` in a script), which are
/// then interrupted by it instead of ignoring it.
///
/// If the signals can not be listened to, it never completes.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Run the given future until it completes, or until the given signal is received, in which case
/// the future is dropped and an error is returned.
///
/// The signal is polled first, so that it is listened to (e.g. its handler installed) before the
/// future runs.
pub async fn run_until_signal<T>(
    future: impl Future<Output = MithrilResult<T>>,
    signal: impl Future<Output = ()>,
) -> MithrilResult<T> {
    tokio::select! {
        biased;
        _ = signal => Err(anyhow!("Interrupted by a shutdown signal")),
        result = future => result,
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
    async fn listens_to_the_signal_before_running_the_future() {
        // Repeated as the polling order could be randomly right
        for _ in 0..20 {
            let polls = std::sync::Mutex::new(Vec::new());
            let signal = async {
                polls.lock().unwrap().push("signal");
                pending::<()>().await
            };
            let future = async {
                polls.lock().unwrap().push("future");
                Ok(())
            };

            run_until_signal(future, signal).await.unwrap();

            assert_eq!(vec!["signal", "future"], *polls.lock().unwrap());
        }
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
