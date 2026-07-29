//! Test doubles
//!
//! Enable unit testing on MithrilNetworkConfigurationProvider

pub mod configuration_provider;
mod configuration_provider_with_markers;
mod dummies;
mod fake_markers_reader;

pub use configuration_provider_with_markers::*;
pub use fake_markers_reader::*;
