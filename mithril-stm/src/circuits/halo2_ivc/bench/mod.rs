//! Benchmark-only façade and CLI for the IVC recursive circuit.
//!
//! Compiled under `test` or the `benchmark-internals` feature: `cli` (the argument parser and its unit
//! tests) is available in both, while `helpers` (the façade) is `benchmark-internals`-only because it needs
//! the full setup. Kept in the library rather than `benches/` because `helpers` delegates to
//! `pub(crate)`/private production code (prover input, prover/verifier setup, embedded assets); the thin
//! harness in `benches/halo2_ivc_snark.rs` consumes this module through the public API.

/// Fail-closed CLI parsing for the `halo2_ivc_snark` harness (also unit-tested under `cargo test`).
pub mod cli;
/// Façade over the production IVC proof-system code (feature-gated, needs the full setup).
#[cfg(feature = "benchmark-internals")]
pub mod helpers;
