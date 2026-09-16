//! In-circuit verification of the genesis standard-Schnorr signature (the IVC trust anchor).

use group::Group;

use crate::circuits::halo2_ivc::{
    AssignedBit, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
    AssignmentInstructions, CircuitCurve, CircuitCurveTrait, ConversionInstructions,
    EccInstructions, EqualityInstructions, Error, Layouter, NativeField, ZkStdLib,
};
use crate::signature_scheme::DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE;

/// Assigned inputs required to verify the genesis Schnorr signature in-circuit.
pub(crate) struct GenesisSchnorrSignatureInputs<'a> {
    /// Assigned genesis verification key.
    pub(crate) verification_key: &'a AssignedNativePoint<CircuitCurve>,
    /// Assigned genesis message.
    pub(crate) message: &'a AssignedNative<NativeField>,
    /// Assigned response scalar from the genesis signature.
    pub(crate) response: &'a AssignedScalarOfNativeCurve<CircuitCurve>,
    /// Assigned challenge from the genesis signature, in the native field.
    pub(crate) challenge: &'a AssignedNative<NativeField>,
}

/// Verifies the genesis Schnorr signature in-circuit.
///
/// Reconstructs the challenge via Poseidon hash over the genesis verification key,
/// the reconstructed nonce commitment, and the genesis message, then checks
/// equality against the committed challenge scalar. Returns an `AssignedBit` that
/// is `true` when the signature is valid.
pub(crate) fn verify_genesis_signature(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<NativeField>,
    inputs: GenesisSchnorrSignatureInputs<'_>,
) -> Result<AssignedBit<NativeField>, Error> {
    let jubjub_chip = std_lib.jubjub();
    let native_gadget = std_lib.bls12_381().scalar_field_chip();
    let response = inputs.response.clone();
    let challenge_as_scalar: AssignedScalarOfNativeCurve<_> =
        jubjub_chip.convert(layouter, inputs.challenge)?;

    let dst_signature: AssignedNative<_> =
        native_gadget.assign_fixed(layouter, DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE.0)?;
    let generator: AssignedNativePoint<_> = jubjub_chip.assign_fixed(
        layouter,
        <CircuitCurve as CircuitCurveTrait>::CryptographicGroup::generator(),
    )?;

    let cap_r = jubjub_chip.msm(
        layouter,
        &[response, challenge_as_scalar.clone()],
        &[generator.clone(), inputs.verification_key.clone()],
    )?;

    let verification_key_x = jubjub_chip.x_coordinate(inputs.verification_key);
    let verification_key_y = jubjub_chip.y_coordinate(inputs.verification_key);
    let cap_r_x = jubjub_chip.x_coordinate(&cap_r);
    let cap_r_y = jubjub_chip.y_coordinate(&cap_r);

    let recomputed_challenge = std_lib.poseidon(
        layouter,
        &[
            dst_signature.clone(),
            verification_key_x,
            verification_key_y,
            cap_r_x,
            cap_r_y,
            inputs.message.clone(),
        ],
    )?;

    native_gadget.is_equal(layouter, &recomputed_challenge, inputs.challenge)
}
