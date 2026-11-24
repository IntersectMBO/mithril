//! Era markers stored on the Cardano chain: payloads, selection and reader adapter.
mod adapter;
mod legacy_payload;
mod payload;

#[cfg(test)]
mod test_fixtures;

pub use adapter::{CardanoChainAdapter, CardanoChainAdapterError};
#[allow(deprecated)]
pub use legacy_payload::LegacyEraMarkersPayload;
pub use payload::EraMarkersPayload;
