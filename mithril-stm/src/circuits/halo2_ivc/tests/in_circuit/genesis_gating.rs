//! Tests that the circuit bypasses proof verification at genesis (step 0).
//!
//! At genesis the circuit must accept arbitrary certificate and IVC proof bytes
//! because there is no prior certificate or IVC proof to verify. These slow
//! tests use the MockProver to confirm that the gating condition nullifies any
//! accumulator contribution from garbage proof bytes at the constraint level.

use midnight_circuits::types::Instantiable;

use crate::circuits::halo2_ivc::{
    AssignedAccumulator,
    circuit::IvcCircuitData,
    state::State,
    tests::common::{
        generators::{
            GENESIS_EPOCH, build_asset_generation_setup_from_cache,
            build_genesis_base_case_next_state, build_genesis_base_case_witness,
        },
        helpers::{
            assert_recursive_mock_prover_accepts_with_label, build_mock_prover_setup_from_assets,
        },
    },
    types::{CertificateProofBytes, IvcProofBytes},
};

mod slow {
    use super::*;

    #[test]
    fn genesis_step_accepts_garbage_certificate_proof_bytes() {
        // MockProver constraint check: at genesis (step_counter = 0) the circuit gates the
        // certificate accumulator contribution to the group identity via scale_by_bit(0, acc),
        // so 64 garbage bytes in the certificate slot must not violate any constraint.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let public_inputs = [
            mock_prover_setup.global.as_public_input(),
            build_genesis_base_case_next_state(&setup, GENESIS_EPOCH).as_public_input(),
            AssignedAccumulator::as_public_input(&mock_prover_setup.trivial_accumulator),
        ]
        .concat();
        let ivc_circuit_data = IvcCircuitData::try_new(
            mock_prover_setup.global.clone(),
            State::genesis(),
            build_genesis_base_case_witness(&setup),
            CertificateProofBytes::garbage(vec![0u8; 64]),
            IvcProofBytes::empty(),
            mock_prover_setup.trivial_accumulator.clone(),
            &mock_prover_setup.certificate_verifying_key,
            &mock_prover_setup.recursive_verifying_key,
        )
        .expect("valid IvcCircuitData construction");
        assert_recursive_mock_prover_accepts_with_label(
            ivc_circuit_data,
            public_inputs,
            "garbage certificate proof bytes (64 × 0x00)",
        );
    }

    #[test]
    fn genesis_step_accepts_garbage_ivc_proof_bytes() {
        // MockProver constraint check: at genesis (step_counter = 0) the circuit gates the
        // IVC accumulator contribution to the group identity via scale_by_bit(0, acc),
        // so 64 garbage bytes in the IVC slot must not violate any constraint.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let public_inputs = [
            mock_prover_setup.global.as_public_input(),
            build_genesis_base_case_next_state(&setup, GENESIS_EPOCH).as_public_input(),
            AssignedAccumulator::as_public_input(&mock_prover_setup.trivial_accumulator),
        ]
        .concat();
        let ivc_circuit_data = IvcCircuitData::try_new(
            mock_prover_setup.global.clone(),
            State::genesis(),
            build_genesis_base_case_witness(&setup),
            CertificateProofBytes::empty(),
            IvcProofBytes::new(vec![0u8; 64]),
            mock_prover_setup.trivial_accumulator.clone(),
            &mock_prover_setup.certificate_verifying_key,
            &mock_prover_setup.recursive_verifying_key,
        )
        .expect("valid IvcCircuitData construction");
        assert_recursive_mock_prover_accepts_with_label(
            ivc_circuit_data,
            public_inputs,
            "garbage IVC proof bytes (64 × 0x00)",
        );
    }
}
