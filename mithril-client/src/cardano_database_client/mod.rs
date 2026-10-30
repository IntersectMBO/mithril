//! A client to retrieve Cardano databases data from an aggregator.
//!
//! In order to do so it defines a [CardanoDatabaseClient] which exposes the following features:
//!  - [get][CardanoDatabaseClient::get]: get a Cardano database data from its hash
//!  - [list][CardanoDatabaseClient::list]: get the list of available Cardano database
//!  - [download_unpack][CardanoDatabaseClient::download_unpack]: download and unpack a Cardano database snapshot for a given immutable files range
//!  - [download_and_verify_digests][CardanoDatabaseClient::download_and_verify_digests]: download and verify the digests of the immutable files in a Cardano database snapshot
//! # Get a Cardano database
//!
//! To get a Cardano database using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey};
//!
//! let client = ClientBuilder::new(AggregatorDiscoveryType::url("YOUR_AGGREGATOR_ENDPOINT"))
//!     .set_genesis_verification_key(GenesisVerificationKey::json_hex("YOUR_GENESIS_VERIFICATION_KEY"))
//!     .build()?;
//! let cardano_database = client.cardano_database_v2().get("CARDANO_DATABASE_HASH").await?.unwrap();
//!
//! println!(
//!     "Cardano database hash={}, merkle_root={}, immutable_file_number={:?}",
//!     cardano_database.hash,
//!     cardano_database.merkle_root,
//!     cardano_database.beacon.immutable_file_number
//! );
//! #    Ok(())
//! # }
//! ```
//!
//! # List available Cardano databases
//!
//! To list available Cardano databases using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey};
//!
//! let client = ClientBuilder::new(AggregatorDiscoveryType::url("YOUR_AGGREGATOR_ENDPOINT"))
//!     .set_genesis_verification_key(GenesisVerificationKey::json_hex("YOUR_GENESIS_VERIFICATION_KEY"))
//!     .build()?;
//! let cardano_databases = client.cardano_database_v2().list().await?;
//!
//! for cardano_database in cardano_databases {
//!     println!("Cardano database hash={}, immutable_file_number={}", cardano_database.hash, cardano_database.beacon.immutable_file_number);
//! }
//! #    Ok(())
//! # }
//! ```
//!
//! # List available Cardano databases filtered by an epoch
//!
//! To list available Cardano databases using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, common::Epoch};
//!
//! let client = ClientBuilder::new(AggregatorDiscoveryType::url("YOUR_AGGREGATOR_ENDPOINT"))
//!     .set_genesis_verification_key(GenesisVerificationKey::json_hex("YOUR_GENESIS_VERIFICATION_KEY"))
//!     .build()?;
//!
//! // For a specific epoch
//! let cardano_databases = client.cardano_database_v2().list_by_epoch(Epoch(8)).await?;
//! // For the latest epoch known by the Mithril aggregator
//! let cardano_databases = client.cardano_database_v2().list_for_latest_epoch().await?;
//! // For the latest epoch known by the Mithril aggregator with an offset
//! let cardano_databases = client.cardano_database_v2().list_for_latest_epoch_with_offset(4).await?;
//!
//! for cardano_database in cardano_databases {
//!     println!("Cardano database hash={}, immutable_file_number={}", cardano_database.hash, cardano_database.beacon.immutable_file_number);
//! }
//! #    Ok(())
//! # }
//! ```
//!
//! # Download a Cardano database snapshot
//! **Note:** _Available on crate feature_ **fs** _only._
//!
//! To download a partial or a full Cardano database folder the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # #[cfg(feature = "fs")]
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, cardano_database_client::{ImmutableFileRange, DownloadUnpackOptions}};
//! use std::path::Path;
//!
//! let client = ClientBuilder::new(AggregatorDiscoveryType::url("YOUR_AGGREGATOR_ENDPOINT"))
//!     .set_genesis_verification_key(GenesisVerificationKey::json_hex("YOUR_GENESIS_VERIFICATION_KEY"))
//!     .build()?;
//! let cardano_database_snapshot = client.cardano_database_v2().get("CARDANO_DATABASE_HASH").await?.unwrap();
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
//! #
//! #    Ok(())
//! # }
//! ```
//! # Compute a Merkle proof for a Cardano database snapshot
//! **Note:** _Available on crate feature_ **fs** _only._
//!
//! To compute proof of membership of downloaded immutable files in a Cardano database folder the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # #[cfg(feature = "fs")]
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MessageBuilder, cardano_database_client::{ImmutableFileRange, DownloadUnpackOptions}};
//! use std::path::Path;
//!
//! let client = ClientBuilder::new(AggregatorDiscoveryType::url("YOUR_AGGREGATOR_ENDPOINT"))
//!     .set_genesis_verification_key(GenesisVerificationKey::json_hex("YOUR_GENESIS_VERIFICATION_KEY"))
//!     .build()?;
//! let cardano_database_snapshot = client.cardano_database_v2().get("CARDANO_DATABASE_HASH").await?.unwrap();
//! let certificate = client.certificate().verify_chain(&cardano_database_snapshot.certificate_hash).await?;
//!
//! // Note: the directory must already exist, and the user running the binary must have read/write access to it.
//! let target_directory = Path::new("/home/user/download/");
//! let immutable_file_range = ImmutableFileRange::Full;
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
//!     .download_and_verify_digests(
//!         &certificate,
//!         &cardano_database_snapshot)
//!     .await?;
//!
//! let allow_missing_immutables_files = false;
//! let merkle_proof = client
//!    .cardano_database_v2()
//!    .verify_cardano_database(
//!        &certificate,
//!       &cardano_database_snapshot,
//!       &immutable_file_range,
//!      allow_missing_immutables_files,
//!      &target_directory,
//!      &verified_digests
//!  ).await?;
//!
//!
//! let message = MessageBuilder::new().compute_cardano_database_message(
//!         &certificate,
//!         &merkle_proof,
//!     ).await?;
//! #
//! #    Ok(())
//! # }
//! ```
mod api;
mod fetch;
mod statistics;

#[cfg(test)]
pub(crate) use api::test_dependency_injector::CardanoDatabaseClientDependencyInjector;
pub use api::{CardanoDatabaseAggregatorRequest, CardanoDatabaseClient};

cfg_fs! {
    mod immutable_file_range;
    mod download_unpack;
    mod proving;

    pub use download_unpack::DownloadUnpackOptions;
    pub use immutable_file_range::ImmutableFileRange;
    pub use proving::{CardanoDatabaseVerificationError, ImmutableVerificationResult};
    pub use proving::VerifiedDigests;
}

cfg_fs_unstable! {
    pub use download_unpack::IpfsShare;
}
