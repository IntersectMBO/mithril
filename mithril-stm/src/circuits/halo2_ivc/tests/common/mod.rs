//! Shared test infrastructure for the recursive Halo2 IVC circuit.
//!
//! This module owns the asset readers, proof helpers, and generator building
//! blocks reused by both the `golden` and `encoding` test suites.

pub(crate) const ASSET_SEED: u64 = 42;
pub(crate) const CERTIFICATE_CIRCUIT_DEGREE: u32 = 13;

// The committed assets are derived from an SRS generated with `ASSET_SEED`, and the generators read
// that SRS from the cache written under `UNSAFE_SRS_SEED`. The two must stay equal, otherwise the
// assets would silently be rebuilt from a different SRS.
const _: () = assert!(ASSET_SEED == crate::circuits::trusted_setup::UNSAFE_SRS_SEED);

pub(crate) mod asset_readers;
pub(crate) mod field_encoding;
pub(crate) mod generators;
pub(crate) mod helpers;
