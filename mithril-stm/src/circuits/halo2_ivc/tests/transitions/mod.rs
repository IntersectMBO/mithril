//! Layer B: state transition rule tests for the recursive Halo2 IVC circuit.
//!
//! The fast cases verify stored proofs against correct and tampered public inputs, for each of the
//! genesis, same-epoch and next-epoch contexts.
//!
//! The slow `MockProver` cases establish something narrower than the rules themselves: that the
//! circuit binds each returned state cell to its public row, and that a satisfiable stimulus is
//! accepted. They mutate the instance vector only, so they do not isolate the chain-link
//! constraints — `classify_epoch`, `assert_first_step_is_next_epoch`,
//! `assert_merkle_tree_commitment_link`, `assert_next_values_consistency`. Removing one of those
//! need not make a public-output tamper accept, and acceptance cannot show one is necessary.
//! Exercising them requires mutating the witness.

mod negative;
mod positive;
