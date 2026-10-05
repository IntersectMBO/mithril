//! Combines assigned bytes into a single field element via a base-weighted linear combination.

use ff::Field;

use crate::circuits::halo2_ivc::{
    ArithInstructions, AssignedNative, Error, Layouter, NativeField,
    errors::{IvcCircuitError, to_synthesis_error},
};

/// Rejects more bytes than base weights, which would silently truncate the combination.
///
/// Fewer bytes than bases is allowed (e.g. an 8-byte epoch against 32 base weights).
fn check_byte_count(byte_count: usize, base_count: usize) -> Result<(), IvcCircuitError> {
    if byte_count > base_count {
        return Err(IvcCircuitError::ByteCountExceedsBaseCount {
            bytes: byte_count,
            bases: base_count,
        });
    }
    Ok(())
}

/// Combines `bytes` into a field element as `sum(bytes[i] * bases[i])`.
pub(crate) fn combine_bytes(
    native_gadget: &impl ArithInstructions<NativeField, AssignedNative<NativeField>>,
    layouter: &mut impl Layouter<NativeField>,
    bytes: impl IntoIterator<Item = impl Into<AssignedNative<NativeField>>>,
    bases: &[NativeField],
) -> Result<AssignedNative<NativeField>, Error> {
    let bytes: Vec<AssignedNative<NativeField>> = bytes.into_iter().map(Into::into).collect();
    check_byte_count(bytes.len(), bases.len()).map_err(to_synthesis_error)?;

    let items: Vec<_> = bytes
        .into_iter()
        .zip(bases.iter())
        .map(|(v, base)| (*base, v))
        .collect();

    native_gadget.linear_combination(layouter, &items, NativeField::ZERO)
}

#[cfg(test)]
mod tests {
    use super::{IvcCircuitError, check_byte_count};

    #[test]
    fn check_byte_count_accepts_equal_or_fewer_bytes() {
        assert!(check_byte_count(32, 32).is_ok());
        assert!(check_byte_count(8, 32).is_ok());
        assert!(check_byte_count(0, 0).is_ok());
    }

    #[test]
    fn check_byte_count_rejects_more_bytes_than_bases() {
        assert_eq!(
            check_byte_count(33, 32),
            Err(IvcCircuitError::ByteCountExceedsBaseCount {
                bytes: 33,
                bases: 32,
            })
        );
    }
}
