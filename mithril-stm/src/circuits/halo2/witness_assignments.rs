//! Assignment helpers that turn circuit witness values into Halo2 layouter values.
//!
//! This module stays intentionally separate from `gadgets`: it prepares assigned inputs for the
//! circuit while the gadget layer owns constraint logic.

use midnight_circuits::instructions::{AssignmentInstructions, ConversionInstructions};
use midnight_circuits::types::{
    AssignedBit, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
};
use midnight_proofs::circuit::{Layouter, Value};
use midnight_proofs::plonk::Error;
use midnight_zk_stdlib::ZkStdLib;

use crate::circuits::halo2::circuit::CertificateCircuit;
use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};
use crate::circuits::halo2::witness::CircuitWitnessEntry;
use crate::signature_scheme::PrimeOrderProjectivePoint;

/// Assigned Merkle authentication path values consumed by the Merkle path gadget.
pub(crate) struct AssignedMerklePath {
    /// Assigned sibling hashes in leaf-to-root order.
    pub(crate) siblings: Vec<AssignedNative<CircuitBase>>,
    /// Assigned sibling positions converted into circuit bits.
    pub(crate) positions: Vec<AssignedBit<CircuitBase>>,
}

/// Assigned witness values consumed by the Merkle, lottery, and signature gadgets.
pub(crate) struct AssignedWitnessEntry {
    /// Assigned verification key point for the current witness leaf.
    pub(crate) verification_key: AssignedNativePoint<CircuitCurve>,
    /// Assigned lottery target value committed in the witness leaf.
    pub(crate) lottery_target_value: AssignedNative<CircuitBase>,
    /// Assigned Merkle authentication path for the current witness leaf.
    pub(crate) merkle_path: AssignedMerklePath,
    /// Assigned lottery index associated with the current signature witness.
    pub(crate) lottery_index: AssignedNative<CircuitBase>,
}

/// Assigned unique Schnorr signature components used by the signature gadget.
pub(crate) struct AssignedSignatureComponents {
    /// Assigned commitment point extracted from the unique Schnorr signature.
    pub(crate) commitment_point: AssignedNativePoint<CircuitCurve>,
    /// Assigned response scalar extracted from the unique Schnorr signature.
    pub(crate) response: AssignedScalarOfNativeCurve<CircuitCurve>,
    /// Assigned challenge value in the circuit base field.
    pub(crate) challenge_in_base_field: AssignedNative<CircuitBase>,
    /// Assigned challenge converted into the curve scalar field.
    pub(crate) challenge_as_scalar: AssignedScalarOfNativeCurve<CircuitCurve>,
}

/// Assigns one witness entry into the Halo2 value layer consumed by circuit gadgets.
pub(crate) fn assign_witness_entry(
    circuit: &CertificateCircuit,
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    witness_entry: Value<CircuitWitnessEntry>,
) -> Result<AssignedWitnessEntry, CertificateCircuitError> {
    let verification_key = assign_verification_key(std_lib, layouter, witness_entry.clone())?;

    let lottery_target_value = std_lib.assign(
        layouter,
        witness_entry
            .clone()
            .map(|entry| entry.leaf.lottery_target_value().into()),
    )?;
    let merkle_path = assign_merkle_path(circuit, std_lib, layouter, witness_entry.clone())?;

    let lottery_index = std_lib.assign(
        layouter,
        witness_entry.map(|entry| CircuitBase::from(entry.lottery_index)),
    )?;

    Ok(AssignedWitnessEntry {
        verification_key,
        lottery_target_value,
        merkle_path,
        lottery_index,
    })
}

/// Assigns the witness verification key as a Jubjub point usable by downstream gadgets.
fn assign_verification_key(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    witness_entry: Value<CircuitWitnessEntry>,
) -> Result<AssignedNativePoint<CircuitCurve>, CertificateCircuitError> {
    std_lib
        .jubjub()
        .assign(
            layouter,
            witness_entry.map(|entry| entry.leaf.verification_key_point().0),
        )
        .map_err(CertificateCircuitError::from)
}

/// Assigns and validates the Merkle authentication path carried by one witness entry.
fn assign_merkle_path(
    circuit: &CertificateCircuit,
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    witness_entry: Value<CircuitWitnessEntry>,
) -> Result<AssignedMerklePath, CertificateCircuitError> {
    let siblings = std_lib.assign_many(
        layouter,
        witness_entry
            .clone()
            .map_with_result(|entry| -> Result<_, CertificateCircuitError> {
                let merkle_path = entry.merkle_path;
                circuit.validate_merkle_sibling_length(merkle_path.siblings.len())?;
                Ok(merkle_path
                    .siblings
                    .iter()
                    .map(|sibling| sibling.1.into())
                    .collect::<Vec<_>>())
            })?
            .transpose_vec(circuit.merkle_tree_depth() as usize)
            .as_slice(),
    )?;

    let positions = std_lib.assign_many(
        layouter,
        witness_entry
            .clone()
            .map_with_result(|entry| -> Result<_, CertificateCircuitError> {
                let merkle_path = entry.merkle_path;
                circuit.validate_merkle_position_length(merkle_path.siblings.len())?;
                Ok(merkle_path
                    .siblings
                    .iter()
                    .map(|sibling| CircuitBase::from(sibling.0))
                    .collect::<Vec<_>>())
            })?
            .transpose_vec(circuit.merkle_tree_depth() as usize)
            .as_slice(),
    )?;

    let positions = positions
        .iter()
        .map(|position| std_lib.convert(layouter, position))
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(AssignedMerklePath {
        siblings,
        positions,
    })
}

/// Assigns unique Schnorr signature components extracted from one circuit witness entry.
pub(crate) fn assign_signature_components(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    witness_entry: Value<CircuitWitnessEntry>,
) -> Result<AssignedSignatureComponents, CertificateCircuitError> {
    let commitment_point_value = witness_entry
        .clone()
        .map_with_result(|entry| {
            let signature = entry.unique_schnorr_signature;
            let (u, v) = signature.commitment_point.get_coordinates();
            PrimeOrderProjectivePoint::from_coordinates(u, v).map(|point| point.0)
        })
        .map_err(|error| CertificateCircuitError::Backend(error.to_string()))?;
    let commitment_point = std_lib.jubjub().assign(layouter, commitment_point_value)?;
    let response = std_lib.jubjub().assign(
        layouter,
        witness_entry
            .clone()
            .map(|entry| entry.unique_schnorr_signature.response.0),
    )?;
    let challenge_in_base_field = std_lib.assign(
        layouter,
        witness_entry.map(|entry| CircuitBase::from(entry.unique_schnorr_signature.challenge)),
    )?;
    let challenge_as_scalar = std_lib.jubjub().convert(layouter, &challenge_in_base_field)?;

    Ok(AssignedSignatureComponents {
        commitment_point,
        response,
        challenge_in_base_field,
        challenge_as_scalar,
    })
}
