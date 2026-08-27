//! Test utilities.
//!
//! ⚠ Do not use in production code ⚠
//!
//! This module provides in particular test doubles for the traits defined in this crate.

pub mod double;
pub mod helper;

#[cfg(test)]
pub(crate) mod test_tools {
    mithril_common::define_test_logger!();
}
