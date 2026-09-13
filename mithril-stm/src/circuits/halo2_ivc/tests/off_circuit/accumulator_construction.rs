//! Tests that `trivial_accumulator` has the expected structure, verifiable through
//! its public-input encoding.

use std::collections::BTreeMap;

use midnight_circuits::types::Instantiable;

use crate::circuits::halo2_ivc::{
    AssignedAccumulator, EmulatedCurve,
    accumulator::{
        check_accumulator_fixed_bases_present, check_dual_msm_matches_fixed_bases,
        trivial_accumulator,
    },
    errors::IvcCircuitError,
    tests::common::{
        asset_readers::{
            load_embedded_genesis_step_output_asset, load_embedded_recursive_chain_state_asset,
            load_embedded_verification_context_asset,
        },
        generators::build_recursive_fixed_bases,
        helpers::verify_prepare_poseidon_recursive_proof,
    },
};

#[test]
fn trivial_acc_public_inputs_match_stored_genesis_accumulator() {
    // The genesis asset stores a trivial_accumulator clone as next_accumulator.
    // Rebuilding trivial_accumulator from the same fixed-base name set must produce
    // an identical public-input encoding.
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let genesis_step_output =
        load_embedded_genesis_step_output_asset().expect("genesis step output asset should load");

    let combined_fixed_base_names: Vec<String> =
        verification_context.combined_fixed_bases.keys().cloned().collect();

    let accumulator = trivial_accumulator(&combined_fixed_base_names);

    assert_eq!(
        AssignedAccumulator::as_public_input(&accumulator),
        AssignedAccumulator::as_public_input(&genesis_step_output.next_accumulator),
        "trivial_accumulator public inputs should match the stored genesis next_accumulator"
    );
}

#[test]
fn trivial_acc_public_input_length_scales_with_fixed_base_name_count() {
    // Each additional fixed-base name adds exactly one scalar to the rhs
    // fixed_base_scalars map, which contributes one field element to the
    // public-input encoding.
    let empty_accumulator_encoding_length =
        AssignedAccumulator::as_public_input(&trivial_accumulator(&[])).len();

    let three_fixed_base_names: Vec<String> =
        ["a", "b", "c"].iter().map(|name| name.to_string()).collect();
    let encoding_length_with_three_names =
        AssignedAccumulator::as_public_input(&trivial_accumulator(&three_fixed_base_names)).len();

    assert_eq!(
        encoding_length_with_three_names,
        empty_accumulator_encoding_length + 3,
        "each fixed-base name should add exactly one field element to the public-input encoding"
    );
}

#[test]
fn wrong_prefix_for_fixed_bases_fails_check_for_dual_msm_names() {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_chain_state = load_embedded_recursive_chain_state_asset()
        .expect("recursive chain state asset should load");

    let (_, recursive_fixed_bases, _) = build_recursive_fixed_bases(
        &verification_context.certificate_verifying_key,
        &verification_context.recursive_verifying_key,
    );

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        recursive_chain_state.state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_chain_state.accumulator),
    ]
    .concat();

    let err = check_dual_msm_matches_fixed_bases(
        &verify_prepare_poseidon_recursive_proof(
            verification_context.recursive_verifying_key.as_ref(),
            recursive_chain_state.ivc_proof.as_bytes(),
            &public_inputs,
        ),
        "wrong_prefix",
        &recursive_fixed_bases,
    )
    .expect_err("dual msm names should not match the fixed bases");
    let ivc_error = err
        .downcast::<IvcCircuitError>()
        .expect("error chain should carry IvcCircuitError");
    assert!(matches!(
        ivc_error,
        IvcCircuitError::MsmFixedBasesNamesMismatch { .. }
    ));
}

#[test]
fn missing_fixed_base_name_fails_check_for_accumulator_names() {
    let accumulator = trivial_accumulator(&["a".to_string(), "b".to_string()]);

    let fixed_bases: BTreeMap<String, EmulatedCurve> =
        BTreeMap::from([("a".to_string(), EmulatedCurve::default())]);

    let err = check_accumulator_fixed_bases_present(&accumulator, &fixed_bases)
        .expect_err("a fixed base missing from the map should be rejected");
    let ivc_error = err
        .downcast::<IvcCircuitError>()
        .expect("error chain should carry IvcCircuitError");
    assert!(matches!(
        ivc_error,
        IvcCircuitError::MsmFixedBasesNamesMismatch { name } if name == "b"
    ));
}

#[test]
fn all_fixed_base_names_present_succeeds_for_accumulator_names() {
    let accumulator = trivial_accumulator(&["a".to_string(), "b".to_string()]);

    let fixed_bases: BTreeMap<String, EmulatedCurve> = BTreeMap::from([
        ("a".to_string(), EmulatedCurve::default()),
        ("b".to_string(), EmulatedCurve::default()),
    ]);

    check_accumulator_fixed_bases_present(&accumulator, &fixed_bases)
        .expect("every fixed base name referenced by the accumulator is present in the map");
}

// --- Structure of the trivial accumulator ---
// The golden compares whole public-input vectors, so it already covers an unconditional change to
// its own committed shape. What it cannot cover is the component structure across varied counts,
// exact names, duplicates and the empty input — and the flat encoding omits the key strings, so
// preserving the names themselves is only observable here.

mod trivial_accumulator_structure {
    use ff::Field;
    use group::Group;
    use proptest::prelude::*;

    use crate::circuits::halo2_ivc::NativeField;

    use super::*;

    prop_compose! {
        /// Drawn by index from a small pool, which makes repeated names common; randomly
        /// generated strings essentially never collide.
        fn arb_fixed_base_names()(
            indices in prop::collection::vec(0usize..4, 0usize..=8),
        ) -> Vec<String> {
            let pool = ["", "base_one", "clé", "鍵"];
            indices.into_iter().map(|index| pool[index].to_string()).collect()
        }
    }

    fn assert_structure(names: &[String]) -> Result<(), TestCaseError> {
        let accumulator = trivial_accumulator(names);
        let expected: std::collections::BTreeSet<&String> = names.iter().collect();

        let right_named = accumulator.rhs().fixed_base_scalars();
        prop_assert_eq!(
            right_named.keys().collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        for (name, scalar) in &right_named {
            prop_assert_eq!(
                *scalar,
                NativeField::ZERO,
                "{} carries a nonzero scalar",
                name
            );
        }
        prop_assert!(
            accumulator.lhs().fixed_base_scalars().is_empty(),
            "the left side must carry no named scalars"
        );

        for side in [accumulator.lhs(), accumulator.rhs()] {
            prop_assert_eq!(side.bases(), vec![EmulatedCurve::identity()]);
            prop_assert_eq!(side.scalars(), vec![NativeField::ONE]);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn each_distinct_name_appears_once_with_a_zero_scalar(names in arb_fixed_base_names()) {
            assert_structure(&names)?;
        }
    }

    /// Guarantees both chosen shapes on every run.
    #[test]
    fn the_empty_and_all_duplicate_name_lists_keep_the_structure() {
        assert_structure(&[]).expect("an empty name list is valid");
        assert_structure(&["a".to_string(), "a".to_string(), "a".to_string()])
            .expect("a repeated name is one key");
    }
}
