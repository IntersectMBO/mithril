//! Off-circuit accumulator and verification-key fixed-base helpers for the recursive IVC circuit.

use std::collections::BTreeMap;

use ff::Field;
use midnight_circuits::verifier::SelfEmulation;
use midnight_proofs::poly::{CommitmentLabel, kzg::msm::DualMSM};

use crate::{StmResult, circuits::halo2_ivc::errors::IvcCircuitError};

use super::{
    Accumulator, ConstraintSystem, EmulatedCurve, KZGCommitmentScheme, Msm, NativeField,
    PairingEngine, RecursiveEmulation, VerifyingKey, verifier,
};

/// Builds the trivial accumulator (the default that satisfies the accumulation invariant) for the
/// given fixed-base names.
pub(crate) fn trivial_accumulator(fixed_base_names: &[String]) -> Accumulator<RecursiveEmulation> {
    Accumulator::<RecursiveEmulation>::new(
        Msm::new(
            &[EmulatedCurve::default()],
            &[NativeField::ONE],
            &BTreeMap::new(),
        ),
        Msm::new(
            &[EmulatedCurve::default()],
            &[NativeField::ONE],
            &fixed_base_names
                .iter()
                .map(|name| (name.clone(), NativeField::ZERO))
                .collect(),
        ),
    )
}

/// Returns the fixed bases of a verifying key together with their names.
pub(crate) fn fixed_bases_and_names_from_verifying_key(
    vk_name: &str,
    vk: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
) -> (BTreeMap<String, EmulatedCurve>, Vec<String>) {
    let mut fixed_bases = BTreeMap::new();
    fixed_bases.extend(verifier::fixed_bases::<RecursiveEmulation>(vk_name, vk));
    let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();
    (fixed_bases, fixed_base_names)
}

/// Returns the fixed-base names of a verifying key, derived from its constraint system.
pub(crate) fn fixed_base_names_from_constraint_system(
    vk_name: &str,
    cs: &ConstraintSystem<NativeField>,
) -> Vec<String> {
    let mut fixed_base_names = vec![];
    fixed_base_names.extend(verifier::fixed_base_names::<RecursiveEmulation>(
        vk_name,
        cs.num_fixed_columns() + cs.num_selectors(),
        cs.permutation().columns.len(),
    ));
    fixed_base_names
}

/// Checks that every fixed-base label in `dual_msm` is present in `fixed_bases`
/// with the matching base point, using `prefix` to construct the commitment name.
///
/// This is a pre-flight check for [`Accumulator::from_dual_msm`], which panics on
/// mismatch. Returns `Ok(())` if all labels match, or an `Err` with the first
/// mismatch description.
pub(crate) fn check_dual_msm_matches_fixed_bases(
    dual_msm: &DualMSM<PairingEngine>,
    prefix: &str,
    fixed_bases: &BTreeMap<String, EmulatedCurve>,
) -> StmResult<()> {
    let (lhs, rhs) = dual_msm.split();
    for (label, _, base) in lhs.into_iter().chain(rhs) {
        let name = match label {
            CommitmentLabel::Fixed(i) => verifier::fixed_commitment_name(prefix, *i),
            CommitmentLabel::Permutation(i) => verifier::perm_commitment_name(prefix, *i),
            CommitmentLabel::Custom(s) if s == "-G" => "-G".to_string(),
            _ => continue,
        };
        if fixed_bases.get(&name) != Some(base) {
            return Err(IvcCircuitError::MsmFixedBasesNamesMismatch { name }.into());
        }
    }
    Ok(())
}

/// Checks that every fixed-base name the `accumulator`` references is present in `fixed_bases`.
/// Pre-flight check for `Accumulator::check`, which panics (not returns false) on a missing name.
pub(crate) fn check_accumulator_fixed_bases_present<S: SelfEmulation>(
    accumulator: &Accumulator<S>,
    fixed_bases: &BTreeMap<String, S::C>,
) -> StmResult<()> {
    let names = accumulator
        .lhs()
        .fixed_base_scalars()
        .into_keys()
        .chain(accumulator.rhs().fixed_base_scalars().into_keys());
    for name in names {
        if !fixed_bases.contains_key(&name) {
            return Err(IvcCircuitError::MsmFixedBasesNamesMismatch { name }.into());
        }
    }
    Ok(())
}
