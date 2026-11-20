//! Utilities module
//! This module contains tools needed for the commands layer.

mod archive_unpacker;
mod block_helper;
mod cardano_db;
mod cardano_db_download_checker;
mod expander;
mod feedback_receiver;
mod forced_era_fetcher;
mod fs;
mod github_release_retriever;
mod http_client;
mod http_downloader;
mod kubo_node;
mod multi_download_progress_reporter;
mod progress_reporter;
mod shutdown_signal;
mod version;

pub use archive_unpacker::*;
pub use block_helper::*;
pub use cardano_db::*;
pub use cardano_db_download_checker::*;
pub use expander::*;
pub use feedback_receiver::*;
pub use forced_era_fetcher::*;
pub use fs::*;
pub use github_release_retriever::*;
pub use http_client::*;
pub use http_downloader::*;
pub use kubo_node::*;
pub use multi_download_progress_reporter::*;
pub use progress_reporter::*;
pub use shutdown_signal::*;
pub use version::*;

use anyhow::Context;
use mithril_client::MithrilResult;
use std::path::Path;

/// The key used to store the caution message when printing a JSON directly to stderr
pub(crate) const JSON_CAUTION_KEY: &str = "caution";

/// Prints a simple warning message to stderr
///
/// The message should be no more than one or two lines, else the json output would be too large,
/// and it would be best to break it down in a structured object. (See `warn_fast_bootstrap_not_available`
/// in cardano db download command for an example.)
pub(crate) fn print_simple_warning(message: &str, is_json_output_enabled: bool) {
    eprintln!("{}", format_simple_warning(message, is_json_output_enabled));
}

fn format_simple_warning(message: &str, is_json_output_enabled: bool) -> String {
    if is_json_output_enabled {
        serde_json::json!({ JSON_CAUTION_KEY: message }).to_string()
    } else {
        format!("Warning: {message}")
    }
}

/// Converts a [Path] to a [String], returning an error if the path is not valid UTF-8.
pub(crate) fn path_to_string(path: &Path) -> MithrilResult<String> {
    let path = path
        .to_str()
        .with_context(|| {
            format!(
                "Path '{}' contains invalid UTF-8 characters.",
                path.display()
            )
        })?
        .to_string();

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_simple_warning_escapes_the_quotes_and_backslashes_of_the_message() {
        let warning = format_simple_warning(r#"Failed to remove "C:\Temp\kubo""#, true);

        assert_eq!(
            r#"{"caution":"Failed to remove \"C:\\Temp\\kubo\""}"#,
            warning
        );
    }

    #[test]
    fn text_simple_warning_is_prefixed_message() {
        assert_eq!(
            "Warning: something happened",
            format_simple_warning("something happened", false)
        );
    }
}
