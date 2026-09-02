#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// TODO: Remove this allow once migration from deprecated AggregatorClient types is complete
#![allow(deprecated)]

//! Define all the tooling necessary to manipulate Mithril certified types from a
//! [Mithril Aggregator](https://mithril.network/rust-doc/mithril_aggregator/index.html).
//!
//! It handles the different types that can be queried to a Mithril aggregator:
//!
//! - [Cardano Database v2][cardano_database_client] list, get, download archive and record statistics.
//! - [Cardano transactions][cardano_transaction_client] list & get snapshot, get proofs.
//! - [Cardano stake distribution][cardano_stake_distribution_client] list, get and get by epoch.
//! - [Mithril stake distribution][mithril_stake_distribution_client] list and get.
//! - [Certificates][certificate_client] list, get, and chain validation.
//! - [MithrilEraClient][era]: retrieve the current Mithril era.
//!
//! The [Client] aggregates the queries of all of those types.
//!
//! **NOTE:** Snapshot download and Certificate chain validation can take quite some time even with a fast
//! computer and network.
//! For those a feedback mechanism is available, more details on it in the [feedback] submodule.
//!
//! # Example
//!
//! Below is an example describing the usage of most of the library's functions together:
//!
//! **Note:** _Snapshot download and the compute snapshot message functions are available using crate feature_ **fs**.
//!
//! ```no_run
//! # #[cfg(feature = "fs")]
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{ClientBuilder, MessageBuilder};
//! use mithril_client::cardano_database_client::{DownloadUnpackOptions, ImmutableFileRange};
//! use std::path::Path;
//!
//! let client =
//!     ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY")
//!         .build()?;
//! let cardano_database_snapshot = client
//!     .cardano_database_v2()
//!     .get("CARDANO_DATABASE_HASH")
//!     .await?
//!     .unwrap();
//!
//! let certificate = client
//!     .certificate()
//!     .verify_chain(&cardano_database_snapshot.certificate_hash)
//!     .await?;
//!
//! // Note: the directory must already exist, and the user running the binary must have read/write access to it.
//! let target_directory = Path::new("/home/user/download/");
//! let immutable_file_range = ImmutableFileRange::Range(3, 6);
//! let download_unpack_options = DownloadUnpackOptions {
//!     allow_override: true,
//!     include_ancillary: true,
//!     ..DownloadUnpackOptions::default()
//! };
//! client
//!     .cardano_database_v2()
//!     .download_unpack(
//!         &cardano_database_snapshot,
//!         &immutable_file_range,
//!         &target_directory,
//!         download_unpack_options,
//!     )
//!     .await?;
//!
//! let verified_digests = client
//!     .cardano_database_v2()
//!     .download_and_verify_digests(&certificate, &cardano_database_snapshot)
//!     .await?;
//!
//! let full_restoration = immutable_file_range == ImmutableFileRange::Full;
//! let include_ancillary = download_unpack_options.include_ancillary;
//! let number_of_immutable_files_restored =
//!     immutable_file_range.length(cardano_database_snapshot.beacon.immutable_file_number);
//! if let Err(error) = client
//!     .cardano_database_v2()
//!     .add_statistics(
//!         full_restoration,
//!         include_ancillary,
//!         number_of_immutable_files_restored,
//!     )
//!     .await
//! {
//!     println!("Could not increment snapshot download statistics: {error:?}");
//! }
//!
//! let allow_missing_immutables_files = false;
//! let merkle_proof = client
//!     .cardano_database_v2()
//!     .verify_cardano_database(
//!         &certificate,
//!         &cardano_database_snapshot,
//!         &immutable_file_range,
//!         allow_missing_immutables_files,
//!         &target_directory,
//!         &verified_digests,
//!     )
//!     .await?;
//!
//! let message = MessageBuilder::new()
//!     .compute_cardano_database_message(&certificate, &merkle_proof)
//!     .await?;
//!
//! assert!(certificate.match_message(&message));
//! #    Ok(())
//! # }
//! ```
//!
//! ## Optional Features
//!
//! The following is a list of [Cargo features](https://doc.rust-lang.org/stable/cargo/reference/manifest.html#the-features-section) that can be
//! enabled or disabled:
//!
//! - **fs**: Enables file system-related functionalities.
//! - **unstable**: Enables experimental or in-development `mithril-client` features that may change.
//! - **rug-backend**: Enables usage of `rug` numerical backend in `mithril-stm` (dependency of `mithril-common`).
//! - **num-integer-backend**: Enables usage of `num-integer` numerical backend in `mithril-stm` (dependency of `mithril-common`).
//!
//! To allow fine-tuning of the http queries, the following [Reqwest](https://docs.rs/reqwest/latest/reqwest/#optional-features) features are re-exported.
//! No TLS backend is enabled by default: you must enable at least one of the TLS-related
//! features below, otherwise the crate will fail to compile.
//! - **native-tls**: Enables TLS functionality provided by `native-tls`.
//! - **native-tls-vendored**: Enables the `vendored` feature of `native-tls`.
//! - **native-tls-no-alpn**: Enables `native-tls` without its `alpn` feature.
//! - **native-tls-vendored-no-alpn**: Enables the `vendored` feature of `native-tls` without its `alpn` feature.
//! - **rustls**: Enables TLS functionality provided by `rustls`.
//! - **rustls-no-provider**: Enables TLS functionality provided by `rustls` without setting `aws-lc-rs` as its TLS provider.

// Ensure at least one TLS backend is enabled
#[cfg(not(any(
    feature = "native-tls",
    feature = "native-tls-no-alpn",
    feature = "native-tls-vendored",
    feature = "native-tls-vendored-no-alpn",
    feature = "rustls",
    feature = "rustls-no-provider",
)))]
compile_error!(
    "At least one TLS backend feature must be enabled. Choose from: \
    'native-tls', 'native-tls-no-alpn', 'native-tls-vendored', 'native-tls-vendored-no-alpn', \
    'rustls', or 'rustls-no-provider'"
);

macro_rules! cfg_fs {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "fs")]
            #[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
            $item
        )*
    }
}

#[allow(unused_macros)]
macro_rules! cfg_unstable {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "unstable")]
            #[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
            $item
        )*
    }
}

#[allow(unused_macros)]
macro_rules! cfg_fs_unstable {
    ($($item:item)*) => {
        $(
            #[cfg(all(feature = "unstable", feature = "fs"))]
            #[cfg_attr(docsrs, doc(cfg(all(feature = "unstable", feature = "fs"))))]
            $item
        )*
    }
}

mod aggregator_client;
pub mod cardano_database_client;
pub mod cardano_stake_distribution_client;
pub mod cardano_transaction_client;
cfg_unstable! {
    pub mod cardano_block_client;
    pub mod cardano_transaction_v2_client;
}
pub mod certificate_client;
#[cfg(feature = "future_snark")]
pub mod circuit_key_registry;
mod client;
pub mod era;
pub mod feedback;
mod message;
pub mod mithril_stake_distribution_client;
cfg_fs! {
    pub mod file_downloader;
}

mod type_alias;
mod utils;

pub use client::*;
pub use message::*;
pub use type_alias::*;

#[cfg(test)]
pub(crate) mod test_utils {
    mithril_common::define_test_logger!();
}
