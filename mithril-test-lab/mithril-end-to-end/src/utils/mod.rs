mod mithril_command;
#[macro_use]
mod spec_utils;
mod child_logger;
mod compatibility_checker;
pub(crate) mod file_utils;
mod formatting;
mod immutable_files_utils;
mod version_req;

pub use child_logger::*;
pub use compatibility_checker::*;
pub use formatting::*;
pub use immutable_files_utils::*;
pub use mithril_command::{EnvVars, MithrilCommand};
pub use spec_utils::{AttemptResult, Backoff, TimeoutReason};
pub use version_req::NodeVersion;

pub fn is_running_in_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok()
}
