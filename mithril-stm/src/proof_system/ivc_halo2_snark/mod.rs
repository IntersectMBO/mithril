pub(crate) mod errors;
pub(crate) mod proof;
mod prover_input;
mod prover_input_helpers;
mod prover_setup;
pub(crate) mod rolling_state;
pub(crate) mod verifier_setup;

#[cfg(feature = "benchmark-internals")]
pub(crate) use prover_input::IvcProverInput;
#[cfg(feature = "benchmark-internals")]
pub(crate) use prover_setup::IvcSnarkProverSetup;

#[cfg(all(test, feature = "future_snark"))]
pub(crate) use prover_input_helpers::tests::build_standard_rolling_state;
