#![warn(missing_docs)]

//! This module provides a preload mechanism for Cardano Transaction signed entity, allowing
//! to compute in advance the Transactions & Block Range Root to be signed.

mod cardano_transactions_preloader;
mod preload_task;

pub use cardano_transactions_preloader::*;
pub use preload_task::*;

#[cfg(test)]
pub(crate) mod test_tools {
    mithril_common::define_test_logger!();
}
