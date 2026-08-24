//! Layer C1: in-circuit verification mechanics tests for the recursive Halo2 IVC circuit.
//!
//! These tests validate what the circuit enforces internally — proof verification
//! wiring, genesis gating bypass, and accumulator update constraints — as opposed
//! to the off-circuit state transition rules covered by Layer B.
//!
//! `public_inputs`      — tampered global fields and accumulator in public inputs.
//! `genesis_gating`     — garbage proof bytes are accepted at genesis (step 0).
//! `certificate_proof`  — tampered certificate proof is rejected in non-genesis steps.
//! `previous_ivc_proof` — tampered previous IVC proof is rejected in non-genesis steps.
//! `accumulator`        — tampered next_accumulator output is rejected.

mod accumulator;
mod certificate_proof;
mod genesis_gating;
mod previous_ivc_proof;
mod public_inputs;
