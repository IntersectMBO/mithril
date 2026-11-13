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
mod http_downloader;
mod kubo_node;
mod multi_download_progress_reporter;
mod progress_reporter;
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
pub use http_downloader::*;
pub use kubo_node::*;
pub use multi_download_progress_reporter::*;
pub use progress_reporter::*;
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
    if is_json_output_enabled {
        eprintln!(r#"{{"{JSON_CAUTION_KEY}":"{message}"}}"#);
    } else {
        eprintln!("Warning: {message}");
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
