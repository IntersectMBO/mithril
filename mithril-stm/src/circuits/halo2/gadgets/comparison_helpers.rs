use ff::{Field, PrimeField};
use midnight_circuits::instructions::{
    ArithInstructions, AssertionInstructions, AssignmentInstructions, DecompositionInstructions,
};
use midnight_circuits::types::AssignedNative;
use midnight_proofs::circuit::Layouter;
use midnight_proofs::plonk::Error;
use midnight_zk_stdlib::ZkStdLib;
use num_bigint::BigUint;
use num_traits::{Num, One};

use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::types::CircuitBase;

/// Splits a field element into `(lower, upper)` limbs at `num_bits` using LE encoding.
pub(super) fn split_field_element_into_le_limbs<Fp: PrimeField>(
    value: &Fp,
    num_bits: u32,
) -> Result<(Fp, Fp), CertificateCircuitError> {
    let field_bits = Fp::NUM_BITS;
    if num_bits >= field_bits {
        return Err(CertificateCircuitError::InvalidBitDecompositionRange {
            num_bits,
            field_bits,
        });
    }

    let value_big = BigUint::from_bytes_le(value.to_repr().as_ref());
    let lower_mask = (BigUint::one() << num_bits) - BigUint::one();
    let lower_big = value_big.clone() & &lower_mask;
    let upper_big = value_big >> num_bits;
    let lower = big_unsigned_integer_to_field_element::<Fp>(lower_big)?;
    let upper = big_unsigned_integer_to_field_element::<Fp>(upper_big)?;
    Ok((lower, upper))
}

/// Parses the prime-field modulus into a `BigUint` for limb splitting and reduction helpers.
fn field_modulus_as_biguint<Fp: PrimeField>() -> Result<BigUint, CertificateCircuitError> {
    BigUint::from_str_radix(&Fp::MODULUS[2..], 16)
        .map_err(|_| CertificateCircuitError::FieldModulusParseFailed)
}

/// Reduces a non-negative integer modulo the field modulus and converts it into a field element.
fn big_unsigned_integer_to_field_element<Fp: PrimeField>(
    e: BigUint,
) -> Result<Fp, CertificateCircuitError> {
    let modulus = field_modulus_as_biguint::<Fp>()?;
    let e = e % modulus;
    Fp::from_str_vartime(&e.to_str_radix(10)[..])
        .ok_or(CertificateCircuitError::FieldElementConversionFailed)
}

/// Constrains two assigned field elements to share the same least-significant-bit parity.
pub(super) fn assert_equal_parity(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    x: &AssignedNative<CircuitBase>,
    y: &AssignedNative<CircuitBase>,
) -> Result<(), Error> {
    let sgn0 = std_lib.sgn0(layouter, x)?;
    let sgn1 = std_lib.sgn0(layouter, y)?;
    std_lib.assert_equal(layouter, &sgn0, &sgn1)
}

/// Decomposes a 255-bit assigned value into `(low_127_bits, high_128_bits)` and constrains
/// the reconstruction to match the original witness.
pub(super) fn decompose_unsafe(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    x: &AssignedNative<CircuitBase>,
) -> Result<(AssignedNative<CircuitBase>, AssignedNative<CircuitBase>), CertificateCircuitError> {
    let x_value = x.value();
    let base127 = CircuitBase::from_u128(1_u128 << 127);
    let (x_low, x_high) = x_value
        .map_with_result(|v| split_field_element_into_le_limbs(v, 127))?
        .unzip();

    let x_low_assigned: AssignedNative<_> = std_lib.assign(layouter, x_low)?;
    let x_high_assigned: AssignedNative<_> = std_lib.assign(layouter, x_high)?;

    let x_combined: AssignedNative<_> = std_lib.linear_combination(
        layouter,
        &[
            (CircuitBase::ONE, x_low_assigned.clone()),
            (base127, x_high_assigned.clone()),
        ],
        CircuitBase::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &x_combined)?;

    assert_equal_parity(std_lib, layouter, x, &x_low_assigned)?;

    Ok((x_low_assigned, x_high_assigned))
}
