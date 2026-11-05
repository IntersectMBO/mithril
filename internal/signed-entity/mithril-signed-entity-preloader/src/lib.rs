#![warn(missing_docs)]

//! This module provides a preload mechanism for signed entities, allowing to compute in advance
//! the data needed to sign or build their artifacts, locking their signed entity types meanwhile.
//!
//! It also provides the preload task for the Cardano Transactions signed entities, computing in
//! advance the Transactions & Block Range Root to be signed.

mod cardano_transactions_preloader;
mod preload_task;

pub use cardano_transactions_preloader::*;
pub use preload_task::*;

#[cfg(test)]
pub(crate) mod test_tools {
    mithril_common::define_test_logger!();
}
