#![warn(missing_docs)]
//! Mithril aggregator
//! The Aggregator is responsible for:
//! * registering signers
//! * producing aggregate multi-signatures
//! * creating, storing & serving the certificate chain
//! * creating, storing & serving certified snapshots
//!
//! This crate is divided in two parts: a HTTP server that exposes an API to
//! communicate with signers and a Runtime that tracks the blockchain to provide
//! signed certificates.
//! You can find more information on how it works reading the [documentation website](https://mithril.network/doc/mithril/mithril-network/aggregator).

mod artifact_builder;
mod commands;
mod configuration;
pub mod database;
pub mod dependency_injection;
pub mod entities;
pub mod event_store;
mod file_uploaders;
mod http_server;
mod immutable_file_digest_mapper;
mod message_adapters;
pub mod metrics;
mod multi_signer;
mod runtime;
pub mod services;
mod store;
#[doc(hidden)]
pub mod test;
mod tools;

pub use crate::artifact_builder::ArtifactBuilder;
pub use crate::configuration::{
    ConfigurationSource, DefaultConfiguration, ExecutionEnvironment, ServeCommandConfiguration,
    SnapshotUploaderType,
};
pub use crate::multi_signer::{MultiSigner, MultiSignerImpl};
pub use commands::{CommandType, MainOpts};
pub use dependency_injection::ServeCommandDependenciesContainer;
pub use file_uploaders::{DumbUploader, FileUploader};
pub use message_adapters::FromRegisterSignerAdapter;
pub use metrics::*;
pub use runtime::{
    AggregatorConfig, AggregatorRunner, AggregatorRunnerTrait, AggregatorRuntime, RuntimeError,
};
pub use services::{
    MithrilSignerRegistrationFollower, MithrilSignerRegistrationLeader,
    MithrilSignerRegistrationVerifier, SignerRecorder, SignerRegisterer, SignerRegistrationError,
    SignerRegistrationRound, SignerRegistrationRoundOpener, SignerRegistrationVerifier,
    SignerSynchronizer,
};
pub use store::{EpochSettingsStorer, ProtocolParametersRetriever, VerificationKeyStorer};
pub use tools::SingleSignatureAuthenticator;

pub use immutable_file_digest_mapper::ImmutableFileDigestMapper;

#[cfg(test)]
pub(crate) use dependency_injection::tests::initialize_dependencies;

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

#[cfg(test)]
mod tests {
    mithril_aggregator_client::test_http_compression_is_enabled!();
}
