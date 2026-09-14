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

// Both guards run ahead of library calls that panic rather than returning. The existing examples
// build their accumulators through `trivial_accumulator`, whose left-hand named map is always
// empty. The dual-MSM example uses a wrong prefix, which moves the fixed and permutation names
// together while `-G` stays unprefixed and inline labels are skipped, so a correct name carrying
// the wrong point is never reached.

mod fixed_base_guards {
    use ff::Field;
    use group::Group;
    use midnight_circuits::verifier::{fixed_commitment_name, perm_commitment_name};
    use midnight_proofs::poly::{
        CommitmentLabel,
        kzg::msm::{DualMSM, MSMKZG},
    };
    use midnight_proofs::utils::arithmetic::MSM;
    use proptest::prelude::*;

    use crate::circuits::halo2_ivc::{
        Accumulator, Msm, NativeField, PairingEngine, RecursiveEmulation,
    };

    use super::*;

    const PREFIX: &str = "key";

    /// Disjoint per side except `shared`, which both may reference: one map entry then satisfies
    /// both, a relationship the disjoint names cannot express. The empty and multi-byte names are
    /// the exact-string domain this guard is meant to handle.
    const ALL_NAMES: [&str; 6] = ["l0", "l1", "", "shared", "r0", "鍵"];

    fn two_distinct_points() -> (EmulatedCurve, EmulatedCurve) {
        let generator = EmulatedCurve::generator();
        (generator, generator.double())
    }

    fn named_side(names: &[&str]) -> Msm<RecursiveEmulation> {
        let named: BTreeMap<String, NativeField> = names
            .iter()
            .map(|name| ((*name).to_string(), NativeField::ZERO))
            .collect();
        Msm::new(&[EmulatedCurve::default()], &[NativeField::ONE], &named)
    }

    fn available(names: &[&str]) -> BTreeMap<String, EmulatedCurve> {
        names
            .iter()
            .map(|name| ((*name).to_string(), EmulatedCurve::default()))
            .collect()
    }

    prop_compose! {
        /// Names are drawn per side from pools sharing one entry: the disjoint names keep a
        /// dropped side observable, while `shared` reaches the case where a single map entry
        /// satisfies both sides.
        fn arb_side_names()(
            left in prop::collection::vec(
                prop::sample::select(vec!["l0", "l1", "", "shared"]), 0usize..=3,
            ),
            right in prop::collection::vec(
                prop::sample::select(vec!["r0", "鍵", "shared"]), 0usize..=3,
            ),
            withheld in prop::option::of(prop::sample::select(ALL_NAMES.to_vec())),
        ) -> (Vec<&'static str>, Vec<&'static str>, Option<&'static str>) {
            (left, right, withheld)
        }
    }

    proptest! {
        /// Success is exactly that the names both sides reference are available. Extra available
        /// names are allowed, and the points are irrelevant to a names-only guard.
        #[test]
        fn every_referenced_name_on_either_side_must_be_available(
            (left, right, withheld) in arb_side_names(),
        ) {
            let accumulator = Accumulator::<RecursiveEmulation>::new(
                named_side(&left),
                named_side(&right),
            );

            let mut offered: Vec<&str> = ALL_NAMES.to_vec();
            if let Some(name) = withheld {
                offered.retain(|candidate| *candidate != name);
            }

            let referenced: std::collections::BTreeSet<&str> =
                left.iter().chain(right.iter()).copied().collect();
            let expected_success = withheld.is_none_or(|name| !referenced.contains(name));

            let outcome = check_accumulator_fixed_bases_present(&accumulator, &available(&offered));
            match outcome {
                Ok(()) => prop_assert!(expected_success, "a missing name should have been reported"),
                Err(error) => {
                    prop_assert!(!expected_success, "every referenced name was available");
                    let circuit_error = error
                        .downcast_ref::<IvcCircuitError>()
                        .expect("error chain should carry IvcCircuitError");
                    prop_assert_eq!(
                        circuit_error,
                        &IvcCircuitError::MsmFixedBasesNamesMismatch {
                            name: withheld.expect("a name was withheld").to_string(),
                        }
                    );
                }
            }
        }
    }

    /// A name present on one side only, for each side in turn. Both existing examples build a
    /// `trivial_accumulator`, whose left-hand named map is empty, so a guard that only inspected
    /// the right-hand side would pass them.
    #[test]
    fn a_name_missing_from_either_side_alone_is_reported() {
        for (left, right, missing) in [
            (vec!["only_left"], vec![], "only_left"),
            (vec![], vec!["only_right"], "only_right"),
        ] {
            let accumulator =
                Accumulator::<RecursiveEmulation>::new(named_side(&left), named_side(&right));

            let error = check_accumulator_fixed_bases_present(&accumulator, &available(&[]))
                .expect_err("a referenced name that is unavailable must be reported");
            let circuit_error = error
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert_eq!(
                circuit_error,
                &IvcCircuitError::MsmFixedBasesNamesMismatch {
                    name: missing.to_string(),
                }
            );
        }
    }

    /// One label on each side, so every category is exercised in both positions.
    fn dual_msm_with(
        left_label: CommitmentLabel,
        right_label: CommitmentLabel,
        point: EmulatedCurve,
    ) -> DualMSM<PairingEngine> {
        let mut left = MSMKZG::<PairingEngine>::init();
        let mut right = MSMKZG::<PairingEngine>::init();
        left.append_term(NativeField::ONE, point, left_label);
        right.append_term(NativeField::ONE, point, right_label);
        DualMSM::new(left, right)
    }

    fn recognised_label_and_name() -> Vec<(CommitmentLabel, String)> {
        vec![
            (CommitmentLabel::Fixed(0), fixed_commitment_name(PREFIX, 0)),
            (
                CommitmentLabel::Permutation(0),
                perm_commitment_name(PREFIX, 0),
            ),
            // `-G` is looked up unprefixed, unlike the other two.
            (CommitmentLabel::Custom("-G".to_string()), "-G".to_string()),
        ]
    }

    /// The guard compares the base **point**, not only the name, and it must do so for every
    /// recognised category in either position. The existing example passes a wrong prefix, so
    /// every name mismatches at once and a correct name carrying a different point never arises.
    #[test]
    fn every_recognised_label_must_resolve_to_its_own_point_on_either_side() {
        let (point, other_point) = two_distinct_points();

        for (left_label, left_name) in recognised_label_and_name() {
            for (right_label, right_name) in recognised_label_and_name() {
                let dual_msm = dual_msm_with(left_label.clone(), right_label.clone(), point);
                let complete: BTreeMap<String, EmulatedCurve> =
                    BTreeMap::from([(left_name.clone(), point), (right_name.clone(), point)]);

                check_dual_msm_matches_fixed_bases(&dual_msm, PREFIX, &complete)
                    .expect("both recognised labels resolve to their own point");

                for name in [&left_name, &right_name] {
                    let mut missing = complete.clone();
                    missing.remove(name);
                    // Removing a shared name clears both sides; either way the guard must report it.
                    let error = check_dual_msm_matches_fixed_bases(&dual_msm, PREFIX, &missing)
                        .expect_err("a referenced name absent from the map must be reported");
                    assert_eq!(
                        error
                            .downcast_ref::<IvcCircuitError>()
                            .expect("error chain should carry IvcCircuitError"),
                        &IvcCircuitError::MsmFixedBasesNamesMismatch { name: name.clone() }
                    );

                    let mut wrong_point = complete.clone();
                    wrong_point.insert(name.clone(), other_point);
                    let error = check_dual_msm_matches_fixed_bases(&dual_msm, PREFIX, &wrong_point)
                        .expect_err("a name carrying a different point must be reported");
                    assert_eq!(
                        error
                            .downcast_ref::<IvcCircuitError>()
                            .expect("error chain should carry IvcCircuitError"),
                        &IvcCircuitError::MsmFixedBasesNamesMismatch { name: name.clone() }
                    );
                }
            }
        }
    }

    /// Labels the guard does not recognise become inline terms downstream and need no named base,
    /// so they are accepted against an empty map. An empty dual MSM is the same boundary.
    #[test]
    fn unrecognised_labels_need_no_fixed_base() {
        let (point, _) = two_distinct_points();
        let inline = [
            CommitmentLabel::Advice(0),
            CommitmentLabel::Instance(0),
            CommitmentLabel::NoLabel,
            CommitmentLabel::Custom("other".to_string()),
        ];

        for left_label in inline.clone() {
            for right_label in inline.clone() {
                let dual_msm = dual_msm_with(left_label.clone(), right_label.clone(), point);
                check_dual_msm_matches_fixed_bases(&dual_msm, PREFIX, &BTreeMap::new())
                    .expect("an unrecognised label needs no fixed base");
            }
        }

        let empty = DualMSM::new(
            MSMKZG::<PairingEngine>::init(),
            MSMKZG::<PairingEngine>::init(),
        );
        check_dual_msm_matches_fixed_bases(&empty, PREFIX, &BTreeMap::new())
            .expect("an empty dual MSM references nothing");
    }
}
