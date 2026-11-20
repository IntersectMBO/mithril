//! Capture of the logs emitted by a test, to assert on them

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing::level_filters::LevelFilter;
use tracing::subscriber::DefaultGuard;

/// Writer appending the formatted logs to a shared buffer
#[derive(Clone, Default)]
struct MemoryWriter(Arc<Mutex<Vec<u8>>>);

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Logs captured during a test, the capture stops when the inspector is dropped
pub struct LogsInspector {
    logs: MemoryWriter,
    _guard: DefaultGuard,
}

impl LogsInspector {
    /// Check if any log line contains the given text (case-sensitive)
    pub fn contains_log(&self, text: &str) -> bool {
        self.lines().iter().any(|line| line.contains(text))
    }

    /// Returns the log lines containing the given text (case-sensitive)
    pub fn search_logs(&self, text: &str) -> Vec<String> {
        self.lines().into_iter().filter(|line| line.contains(text)).collect()
    }

    fn lines(&self) -> Vec<String> {
        let bytes = self.logs.0.lock().unwrap();
        String::from_utf8_lossy(&bytes).lines().map(str::to_string).collect()
    }
}

/// Capture the logs emitted by the current thread, at every level, until the returned inspector
/// is dropped
///
/// The capture is scoped to the current thread: tests running in parallel don't mix their logs,
/// and `#[tokio::test]` runs on the current thread by default. The events of tasks spawned on a
/// `multi_thread` runtime are not captured.
pub fn capture_logs() -> LogsInspector {
    let logs = MemoryWriter::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    LogsInspector {
        logs,
        _guard: tracing::subscriber::set_default(subscriber),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_the_logs_with_their_fields() {
        let logs = capture_logs();

        tracing::debug!(pid = 42, "Could not read the topology file");
        tracing::trace!("another log");

        assert!(logs.contains_log("Could not read the topology file"));
        assert_eq!(
            1,
            logs.search_logs("pid=42").len(),
            "{:?}",
            logs.search_logs("")
        );
        assert_eq!(2, logs.search_logs("").len());
    }

    #[test]
    fn does_not_capture_the_logs_emitted_after_the_inspector_is_dropped() {
        let logs = capture_logs();
        let lines = logs.logs.clone();
        drop(logs);

        tracing::info!("not captured");

        assert!(lines.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn captures_the_logs_of_an_async_test() {
        let logs = capture_logs();

        async { tracing::warn!("from an async block") }.await;

        assert!(logs.contains_log("from an async block"));
    }
}
