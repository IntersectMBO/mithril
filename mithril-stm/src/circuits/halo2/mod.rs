//! Halo2 STM circuit integration (feature-gated by `future_snark`).
//!
//! Module map:
//! - `circuit`: relation orchestration and top-level constraint flow
//! - `witness_assignments`: witness assignment into Halo2 layouter values
//! - `witness`: circuit-facing witness and instance contract
//! - `adapters`: STM-to-circuit conversions for boundary types
//! - `gadgets`: reusable constraint logic split by domain
//! - `errors`: typed circuit errors and backend error conversion
//! - `tests/golden`: end-to-end circuit scenarios
//! - inline `#[cfg(test)]` blocks in `gadgets/*` and `adapters`: focused regression checks
//! - `tests/test_helpers`: shared harness for focused gadget tests

pub mod adapters;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod witness_assignments;
// TODO(snark): remove `allow(dead_code)` once Halo2 modules are fully wired into STM.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod circuit;
pub mod errors;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod gadgets;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod key_serialization;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod keys;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod types;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod witness;

#[cfg(any(test, feature = "benchmark-internals"))]
pub mod bench;

#[cfg(test)]
pub(crate) mod tests;

/// Circuit verification key of the non-recursive circuit used for production.
/// This key is generated using the Midnight's secure SRS and the following
/// production parameters:
/// - m: 16948
/// - k: 1944
/// - phi_f: 0.2
/// - merkle_tree_depth: 13
///
pub const NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION: &[u8] =
    include_bytes!("non_recursive_circuit_verification_key_for_production.bin");
