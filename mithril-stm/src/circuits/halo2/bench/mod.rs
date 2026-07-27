//! Benchmark-only façade for the non-recursive certificate circuit.
//!
//! Compiled under `test` or the `benchmark-internals` feature. Kept in the library rather than `benches/`
//! because `helpers` delegates to `pub(crate)`/private production code; the harnesses in
//! `benches/halo2_snark.rs` and `benches/halo2_prover_modes.rs` consume this module through the public API.

/// Façade over the production non-recursive proof-system code.
pub mod helpers;
