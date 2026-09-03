//! Crate-internal facade for the recursive Halo2 IVC proof system.

mod errors;
mod interface;
mod proof;
mod prover_input;
mod prover_input_helpers;
mod prover_setup;
mod rolling_state;
mod verifier_setup;

pub(crate) use interface::IvcChainProver;
#[cfg(test)]
pub(crate) use interface::MockIvcChainProver;
pub(crate) use proof::{IvcChainStepBundle, IvcProof, IvcProver};
#[cfg(feature = "benchmark-internals")]
pub(crate) use prover_input::IvcProverInput;
#[cfg(all(test, feature = "future_snark"))]
pub(crate) use prover_input_helpers::tests::build_standard_rolling_state;
#[cfg(feature = "benchmark-internals")]
pub(crate) use prover_setup::IvcProverSetup;
pub(crate) use rolling_state::IvcRollingState;
pub(crate) use verifier_setup::{IvcVerifierData, IvcVerifierSetup};
