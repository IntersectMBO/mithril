#![warn(missing_docs)]

//! A command line interface that uses the [Mithril Client Library](https://mithril.network/doc/manual/developer-docs/nodes/mithril-client-library)
//! to manipulate Mithril certified types from a Mithril Aggregator:
//! - Cardano Database: list, show, download archive
//! - Cardano transactions: list & show snapshot, certify a list of transactions
//! - Cardano stake distribution: list and download
//! - Mithril stake distribution: list and download
//!
//!   You can find more information on how it works reading the [documentation website](https://mithril.network/doc/mithril/mithril-network/client).

mod certificate_chain_cache;
mod command_context;
pub mod commands;
mod configuration;
mod utils;

pub use certificate_chain_cache::*;
pub use command_context::*;
pub use configuration::*;
/// Error Clap
pub type ClapError = clap::error::Error;

// Memory allocator (to handle properly memory fragmentation)
#[cfg(all(
    not(target_os = "windows"),
    not(all(target_os = "linux", target_arch = "aarch64"))
))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(
    not(target_os = "windows"),
    not(all(target_os = "linux", target_arch = "aarch64"))
))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use mimalloc::MiMalloc;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
