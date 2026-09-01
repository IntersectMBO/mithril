use midnight_circuits::instructions::{AssertionInstructions, EccInstructions};
use midnight_circuits::types::{AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve};
use midnight_proofs::circuit::Layouter;
use midnight_proofs::plonk::Error;
use midnight_zk_stdlib::ZkStdLib;

use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};

/// Assigned inputs required to verify one unique Schnorr signature inside the circuit.
pub(crate) struct UniqueSchnorrSignatureInputs<'a> {
    /// Assigned domain-separation tag for signature verification.
    pub(crate) dst_signature: &'a AssignedNative<CircuitBase>,
    /// Assigned fixed generator of the signing curve.
    pub(crate) generator: &'a AssignedNativePoint<CircuitCurve>,
    /// Assigned verification key corresponding to the signer.
    pub(crate) verification_key: &'a AssignedNativePoint<CircuitCurve>,
    /// Assigned response scalar from the unique Schnorr signature.
    pub(crate) response: &'a AssignedScalarOfNativeCurve<CircuitCurve>,
    /// Assigned challenge value in the circuit base field.
    pub(crate) challenge_in_base_field: &'a AssignedNative<CircuitBase>,
    /// Assigned challenge converted into the curve scalar field.
    pub(crate) challenge_as_scalar: &'a AssignedScalarOfNativeCurve<CircuitCurve>,
    /// Assigned hash-to-curve point derived from the public inputs.
    pub(crate) hash: &'a AssignedNativePoint<CircuitCurve>,
    /// Assigned commitment point from the unique Schnorr signature.
    pub(crate) commitment_point: &'a AssignedNativePoint<CircuitCurve>,
}

/// Verifies the unique Schnorr signature constraints for one assigned witness entry.
pub(crate) fn verify_unique_signature(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    inputs: UniqueSchnorrSignatureInputs<'_>,
) -> Result<(), Error> {
    let cap_r_1 = std_lib.jubjub().msm(
        layouter,
        &[inputs.response.clone(), inputs.challenge_as_scalar.clone()],
        &[inputs.hash.clone(), inputs.commitment_point.clone()],
    )?;

    let cap_r_2 = std_lib.jubjub().msm(
        layouter,
        &[inputs.response.clone(), inputs.challenge_as_scalar.clone()],
        &[inputs.generator.clone(), inputs.verification_key.clone()],
    )?;

    let hx = std_lib.jubjub().x_coordinate(inputs.hash);
    let hy = std_lib.jubjub().y_coordinate(inputs.hash);
    let verification_key_x = std_lib.jubjub().x_coordinate(inputs.verification_key);
    let verification_key_y = std_lib.jubjub().y_coordinate(inputs.verification_key);
    let commitment_point_x = std_lib.jubjub().x_coordinate(inputs.commitment_point);
    let commitment_point_y = std_lib.jubjub().y_coordinate(inputs.commitment_point);
    let cap_r_1_x = std_lib.jubjub().x_coordinate(&cap_r_1);
    let cap_r_1_y = std_lib.jubjub().y_coordinate(&cap_r_1);
    let cap_r_2_x = std_lib.jubjub().x_coordinate(&cap_r_2);
    let cap_r_2_y = std_lib.jubjub().y_coordinate(&cap_r_2);

    let challenge_prime = std_lib.poseidon(
        layouter,
        &[
            inputs.dst_signature.clone(),
            hx,
            hy,
            verification_key_x,
            verification_key_y,
            commitment_point_x.clone(),
            commitment_point_y.clone(),
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ],
    )?;

    std_lib.assert_equal(layouter, inputs.challenge_in_base_field, &challenge_prime)
}

#[cfg(test)]
mod tests {
    use group::Group;
    use midnight_circuits::ecc::curves::CircuitCurve as CircuitCurveTrait;
    use midnight_circuits::instructions::{AssignmentInstructions, ConversionInstructions};
    use midnight_circuits::types::AssignedNative;
    use midnight_proofs::plonk::Error;

    use crate::circuits::halo2::tests::test_helpers::{
        TEST_MERKLE_TREE_DEPTH, assert_relation_rejected, impl_focused_test_relation,
        jubjub_poseidon_used_chips, prove_and_verify_relation, sample_valid_circuit_witness_entry,
    };
    use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};
    use crate::circuits::halo2::witness::{
        CircuitWitnessEntry, MerkleTreeCommitment, SignedMessageWithoutPrefix,
    };
    use crate::signature_scheme::{
        BaseFieldElement, DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE, PrimeOrderProjectivePoint,
    };

    use super::{UniqueSchnorrSignatureInputs, verify_unique_signature};

    impl_focused_test_relation!(
        UniqueSchnorrSignatureRelation,
        (
            CircuitWitnessEntry,
            MerkleTreeCommitment,
            SignedMessageWithoutPrefix
        ),
        error = Error,
        jubjub_poseidon_used_chips(),
        |std_lib, layouter, witness| {
            let merkle_tree_commitment: AssignedNative<CircuitBase> = std_lib.assign(
                layouter,
                witness.clone().map(|(_, commitment, _)| commitment.into()),
            )?;
            let message: AssignedNative<CircuitBase> = std_lib.assign(
                layouter,
                witness.clone().map(|(_, _, message)| message.into()),
            )?;
            let hash = std_lib
                .hash_to_curve(layouter, &[merkle_tree_commitment.clone(), message.clone()])?;
            let generator = std_lib.jubjub().assign_fixed(
                layouter,
                <CircuitCurve as CircuitCurveTrait>::CryptographicGroup::generator(),
            )?;
            let dst_signature = std_lib.assign_fixed(
                layouter,
                CircuitBase::from(DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE),
            )?;
            let verification_key = std_lib.jubjub().assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _, _)| entry.leaf.verification_key_point().0),
            )?;
            let response = std_lib.jubjub().assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _, _)| entry.unique_schnorr_signature.response.0),
            )?;
            let challenge_in_base_field = std_lib.assign(
                layouter,
                witness.clone().map(|(entry, _, _)| {
                    CircuitBase::from(entry.unique_schnorr_signature.challenge)
                }),
            )?;
            let challenge_as_scalar =
                std_lib.jubjub().convert(layouter, &challenge_in_base_field)?;
            let commitment_point = std_lib.jubjub().assign(
                layouter,
                witness.map(|(entry, _, _)| {
                    let (u, v) = entry.unique_schnorr_signature.commitment_point.get_coordinates();
                    PrimeOrderProjectivePoint::from_coordinates(u, v)
                        .expect("unit fixture commitment point should stay prime-order")
                        .0
                }),
            )?;

            verify_unique_signature(
                std_lib,
                layouter,
                UniqueSchnorrSignatureInputs {
                    dst_signature: &dst_signature,
                    generator: &generator,
                    verification_key: &verification_key,
                    response: &response,
                    challenge_in_base_field: &challenge_in_base_field,
                    challenge_as_scalar: &challenge_as_scalar,
                    hash: &hash,
                    commitment_point: &commitment_point,
                },
            )
        }
    );

    #[test]
    fn unique_schnorr_signature_accepts_valid_witness_entry() {
        let relation = UniqueSchnorrSignatureRelation;
        let (entry, merkle_tree_commitment, message) = sample_valid_circuit_witness_entry(
            TEST_MERKLE_TREE_DEPTH as u32,
        )
        .expect("unique_schnorr_signature_accepts_valid_witness_entry should build fixture");

        prove_and_verify_relation(&relation, &(), (entry, merkle_tree_commitment, message))
            .expect("unique_schnorr_signature_accepts_valid_witness_entry should succeed");
    }

    #[test]
    fn unique_schnorr_signature_rejects_wrong_challenge() {
        let relation = UniqueSchnorrSignatureRelation;
        let (mut entry, merkle_tree_commitment, message) =
            sample_valid_circuit_witness_entry(TEST_MERKLE_TREE_DEPTH as u32)
                .expect("unique_schnorr_signature_rejects_wrong_challenge should build fixture");
        entry.unique_schnorr_signature.challenge =
            entry.unique_schnorr_signature.challenge + BaseFieldElement::from(1u64);

        assert_relation_rejected(prove_and_verify_relation(
            &relation,
            &(),
            (entry, merkle_tree_commitment, message),
        ));
    }
}
