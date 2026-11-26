#![warn(missing_docs)]

//! # Mithril-era
//!
//! Mechanisms to read and check Mithril Era markers, for more information on Mithril Era please read
//! [Mithril Network Upgrade Strategy](https://mithril.network/doc/adr/4).

pub mod adapters;
mod era_checker;
mod era_reader;

pub use era_checker::EraChecker;
pub use era_reader::*;

#[cfg(test)]
pub(crate) mod test_tools {
    mithril_common::define_test_logger!();
}
