//! Module dedicated to EraReaderAdapter implementations.
mod bootstrap;
mod bootstrap_latest;
mod builder;
mod cardano_chain;
mod dummy;
mod file;

pub use bootstrap::BootstrapAdapter as EraReaderBootstrapAdapter;
pub use bootstrap_latest::BootstrapLatestAdapter as EraReaderBootstrapLatestAdapter;
pub use builder::{AdapterBuilder as EraReaderAdapterBuilder, AdapterType as EraReaderAdapterType};
#[allow(deprecated)]
pub use cardano_chain::LegacyEraMarkersPayload as LegacyEraMarkersPayloadCardanoChain;
pub use cardano_chain::{
    CardanoChainAdapter as EraReaderCardanoChainAdapter,
    CardanoChainAdapterError as EraReaderCardanoChainAdapterError,
    EraMarkersPayload as EraMarkersPayloadCardanoChain,
};
pub use dummy::DummyAdapter as EraReaderDummyAdapter;
pub use file::FileAdapter as EraReaderFileAdapter;
