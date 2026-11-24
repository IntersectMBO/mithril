//! Era markers stored on the Cardano chain: payload and reader adapter.
mod adapter;
mod payload;

pub use adapter::CardanoChainAdapter;
pub use payload::EraMarkersPayload;
