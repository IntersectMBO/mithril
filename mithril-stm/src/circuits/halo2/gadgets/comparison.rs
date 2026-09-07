use midnight_circuits::instructions::{BinaryInstructions, EqualityInstructions};
use midnight_circuits::types::{AssignedBit, AssignedNative};
use midnight_proofs::circuit::Layouter;
use midnight_zk_stdlib::ZkStdLib;

use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::gadgets::comparison_helpers::decompose_unsafe;
use crate::circuits::halo2::types::CircuitBase;

/// Compares two assigned 255-bit values and returns a bit witnessing whether `x < y`.
pub(super) fn lower_than_native(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    x: &AssignedNative<CircuitBase>,
    y: &AssignedNative<CircuitBase>,
) -> Result<AssignedBit<CircuitBase>, CertificateCircuitError> {
    let (x_low_assigned, x_high_assigned) = decompose_unsafe(std_lib, layouter, x)?;
    let (y_low_assigned, y_high_assigned) = decompose_unsafe(std_lib, layouter, y)?;

    let is_equal_high = std_lib.is_equal(layouter, &x_high_assigned, &y_high_assigned)?;
    let is_less_low = std_lib.lower_than(layouter, &x_low_assigned, &y_low_assigned, 127)?;
    let is_less_high = std_lib.lower_than(layouter, &x_high_assigned, &y_high_assigned, 128)?;

    let low_less = std_lib.and(layouter, &[is_equal_high, is_less_low])?;
    std_lib
        .or(layouter, &[is_less_high, low_less])
        .map_err(CertificateCircuitError::from)
}

#[cfg(test)]
mod tests {
    use midnight_circuits::instructions::AssignmentInstructions;

    use crate::circuits::halo2::errors::CertificateCircuitError;
    use crate::circuits::halo2::tests::test_helpers::{
        assert_relation_rejected, comparison_used_chips, impl_focused_test_relation,
        prove_and_verify_relation,
    };
    use crate::signature_scheme::BaseFieldElement;

    use super::lower_than_native;

    type ComparisonWitness = (BaseFieldElement, BaseFieldElement);

    impl_focused_test_relation!(
        ComparisonLessThanRelation,
        ComparisonWitness,
        error = CertificateCircuitError,
        comparison_used_chips(),
        |std_lib, layouter, witness| {
            let x = std_lib.assign(layouter, witness.map(|(x, _)| x.into()))?;
            let y = std_lib.assign(layouter, witness.map(|(_, y)| y.into()))?;

            let is_less = lower_than_native(std_lib, layouter, &x, &y)?;
            std_lib
                .assert_true(layouter, &is_less)
                .map_err(CertificateCircuitError::from)
        }
    );

    #[test]
    fn lower_than_native_accepts_strictly_increasing_values() {
        let relation = ComparisonLessThanRelation;

        prove_and_verify_relation(
            &relation,
            &(),
            (BaseFieldElement::from(3u64), BaseFieldElement::from(5u64)),
        )
        .expect("lower_than_native_accepts_strictly_increasing_values should succeed");
    }

    #[test]
    fn lower_than_native_rejects_equal_values() {
        let relation = ComparisonLessThanRelation;

        assert_relation_rejected(prove_and_verify_relation(
            &relation,
            &(),
            (BaseFieldElement::from(7u64), BaseFieldElement::from(7u64)),
        ));
    }
}
