//! Layer B: state transition rule tests for the recursive Halo2 IVC circuit.
//!
//! The fast cases verify stored proofs against correct and tampered public inputs, per transition
//! context.
//!
//! The slow `MockProver` cases establish that the circuit binds each returned state cell to its
//! public row, and that a satisfiable stimulus is accepted. They mutate the instance vector only,
//! so they do not isolate the chain-link constraints; that needs witness-side mutation.

mod negative;
mod positive;
