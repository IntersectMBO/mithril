//! Generator building blocks and asset writers shared by the golden and encoding test suites.

mod asset_generation;
pub(crate) mod proofs;
pub(crate) mod setup;
pub(crate) mod transitions;
mod verification_key;

pub(crate) use proofs::{
    try_verify_prepare_poseidon_ivc, verify_prepare_blake2b_ivc, verify_prepare_poseidon_ivc,
};
pub(crate) use setup::{
    AssetGenerationSetup, GENESIS_EPOCH, build_asset_generation_setup_from_cache,
    build_asset_generation_setup_from_scratch, build_recursive_fixed_bases, build_recursive_global,
    build_shared_recursive_context_from_cache,
};
pub(crate) use transitions::{
    build_genesis_base_case_next_state, build_genesis_base_case_witness,
    build_genesis_protocol_message_preimage, build_same_epoch_certificate_asset_data,
    certificate_public_inputs_for_step, next_message_and_preimage_for_step, next_state_for_step,
    same_epoch_message_and_preimage_for_step, same_epoch_next_state_for_step,
};
pub(crate) use verification_key::golden_recursive_circuit_verification_key_bytes;
