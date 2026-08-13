use std::io::Write;
use tar::Builder;

use mithril_common::StdResult;

use crate::appender::TarAppender;

/// A test double appender that always fails.
///
/// Used in tests to verify error handling behavior when appending operations fail.
pub struct FailAppender;

impl TarAppender for FailAppender {
    fn append<T: Write>(&self, _tar: &mut Builder<T>) -> StdResult<()> {
        anyhow::bail!("FailAppender always fails (append)")
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        anyhow::bail!("FailAppender always fails (compute_uncompressed_data_size)")
    }
}
