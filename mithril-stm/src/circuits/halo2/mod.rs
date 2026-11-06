//! Halo2 STM circuit integration (feature-gated by `snark`).
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

use crate::Parameters;

pub mod adapters;
pub(crate) mod circuit;
pub mod errors;
pub(crate) mod gadgets;
pub(crate) mod key_serialization;
pub(crate) mod keys;
pub(crate) mod types;
pub(crate) mod witness;
pub(crate) mod witness_assignments;

#[cfg(any(test, feature = "benchmark-internals"))]
pub mod bench;

#[cfg(test)]
pub(crate) mod tests;

/// STM parameters the production circuit verification keys are derived from.
pub(crate) const STM_PARAMETERS_FOR_PRODUCTION: Parameters = Parameters {
    m: 16948,
    k: 1944,
    phi_f: 0.2,
};

/// Number of public inputs of the certificate circuit: the Merkle tree commitment and the message.
pub(crate) const CERTIFICATE_CIRCUIT_PUBLIC_INPUT_COUNT: usize = 2;

/// Circuit verification key of the non-recursive circuit used for production.
/// This key is generated using the Midnight's secure SRS and the following
/// production parameters:
/// - m: 16948
/// - k: 1944
/// - phi_f: 0.2
/// - merkle_tree_depth: 13
///
pub const NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION: &[u8] =
    include_bytes!("non_recursive_circuit_verification_key_for_production.vkey");
