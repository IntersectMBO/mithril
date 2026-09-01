use midnight_circuits::instructions::EccInstructions;
use midnight_circuits::types::{AssignedNative, AssignedNativePoint};
use midnight_proofs::circuit::Layouter;
use midnight_proofs::plonk::Error;
use midnight_zk_stdlib::ZkStdLib;

use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::gadgets::comparison::lower_than_native;
use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};

use super::LOTTERY_BIT_BOUND;

/// Constrains the current witness to have won the lottery for the assigned index.
pub(crate) fn assert_lottery_won(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    lottery_prefix: &AssignedNative<CircuitBase>,
    commitment_point: &AssignedNativePoint<CircuitCurve>,
    lottery_index: &AssignedNative<CircuitBase>,
    lottery_target_value: &AssignedNative<CircuitBase>,
) -> Result<(), CertificateCircuitError> {
    let commitment_point_x = std_lib.jubjub().x_coordinate(commitment_point);
    let commitment_point_y = std_lib.jubjub().y_coordinate(commitment_point);
    let lottery_evaluation_value = std_lib.poseidon(
        layouter,
        &[
            lottery_prefix.clone(),
            commitment_point_x,
            commitment_point_y,
            lottery_index.clone(),
        ],
    )?;
    let is_less = lower_than_native(
        std_lib,
        layouter,
        lottery_target_value,
        &lottery_evaluation_value,
    )?;
    std_lib
        .assert_false(layouter, &is_less)
        .map_err(CertificateCircuitError::from)
}

/// Constrains the current lottery index to be strictly greater than the previous one.
pub(crate) fn assert_strictly_increasing_lottery_index(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    previous_lottery_index: &AssignedNative<CircuitBase>,
    lottery_index: &AssignedNative<CircuitBase>,
) -> Result<(), Error> {
    let is_less = std_lib.lower_than(
        layouter,
        previous_lottery_index,
        lottery_index,
        LOTTERY_BIT_BOUND,
    )?;
    std_lib.assert_true(layouter, &is_less)
}

/// Constrains a lottery index to lie in the interval `[0, m)`.
pub(crate) fn assert_lottery_index_in_bounds(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    lottery_index: &AssignedNative<CircuitBase>,
    m: &AssignedNative<CircuitBase>,
) -> Result<(), Error> {
    let is_less = std_lib.lower_than(layouter, lottery_index, m, LOTTERY_BIT_BOUND)?;
    std_lib.assert_true(layouter, &is_less)
}

#[cfg(test)]
mod tests {
    use midnight_circuits::instructions::AssignmentInstructions;
    use midnight_proofs::plonk::Error;

    use crate::LotteryIndex;
    use crate::circuits::halo2::errors::CertificateCircuitError;
    use crate::circuits::halo2::tests::test_helpers::{
        assert_relation_rejected, comparison_used_chips, impl_focused_test_relation,
        jubjub_poseidon_used_chips, prove_and_verify_relation,
    };
    use crate::circuits::halo2::types::CircuitBase;
    use crate::circuits::halo2::witness::LotteryTargetValue as CircuitLotteryTargetValue;
    use crate::signature_scheme::PrimeOrderProjectivePoint;

    use super::{
        assert_lottery_index_in_bounds, assert_lottery_won,
        assert_strictly_increasing_lottery_index,
    };

    type LotteryWonWitness = (
        CircuitLotteryTargetValue,
        PrimeOrderProjectivePoint,
        LotteryIndex,
        CircuitLotteryTargetValue,
    );

    impl_focused_test_relation!(
        LotteryWonRelation,
        LotteryWonWitness,
        error = CertificateCircuitError,
        jubjub_poseidon_used_chips(),
        |std_lib, layouter, witness| {
            let lottery_prefix =
                std_lib.assign(layouter, witness.map(|(prefix, _, _, _)| prefix.into()))?;
            let commitment_point = std_lib
                .jubjub()
                .assign(layouter, witness.map(|(_, point, _, _)| point.0))?;
            let lottery_index = std_lib.assign(
                layouter,
                witness.map(|(_, _, index, _)| CircuitBase::from(index)),
            )?;
            let lottery_target_value =
                std_lib.assign(layouter, witness.map(|(_, _, _, target)| target.into()))?;

            assert_lottery_won(
                std_lib,
                layouter,
                &lottery_prefix,
                &commitment_point,
                &lottery_index,
                &lottery_target_value,
            )
        }
    );

    impl_focused_test_relation!(
        IncreasingIndexRelation,
        (LotteryIndex, LotteryIndex),
        error = Error,
        comparison_used_chips(),
        |std_lib, layouter, witness| {
            let previous_lottery_index = std_lib.assign(
                layouter,
                witness.map(|(previous, _)| CircuitBase::from(previous)),
            )?;
            let lottery_index = std_lib.assign(
                layouter,
                witness.map(|(_, current)| CircuitBase::from(current)),
            )?;

            assert_strictly_increasing_lottery_index(
                std_lib,
                layouter,
                &previous_lottery_index,
                &lottery_index,
            )
        }
    );

    impl_focused_test_relation!(
        InBoundsIndexRelation,
        (LotteryIndex, u32),
        error = Error,
        comparison_used_chips(),
        |std_lib, layouter, witness| {
            let lottery_index =
                std_lib.assign(layouter, witness.map(|(index, _)| CircuitBase::from(index)))?;
            let m = std_lib.assign(
                layouter,
                witness.map(|(_, m)| CircuitBase::from(u64::from(m))),
            )?;

            assert_lottery_index_in_bounds(std_lib, layouter, &lottery_index, &m)
        }
    );

    #[test]
    fn lottery_won_accepts_max_target_value() {
        let relation = LotteryWonRelation;
        let witness = (
            CircuitLotteryTargetValue::from(7u64),
            PrimeOrderProjectivePoint::create_generator(),
            3u64,
            -CircuitLotteryTargetValue::ONE,
        );

        prove_and_verify_relation(&relation, &(), witness)
            .expect("lottery_won_accepts_max_target_value should succeed");
    }

    #[test]
    fn lottery_won_rejects_small_target_value() {
        let relation = LotteryWonRelation;
        let witness = (
            CircuitLotteryTargetValue::from(7u64),
            PrimeOrderProjectivePoint::create_generator(),
            3u64,
            CircuitLotteryTargetValue::ZERO,
        );

        assert_relation_rejected(prove_and_verify_relation(&relation, &(), witness));
    }

    #[test]
    fn index_constraints_accept_strict_order_below_m() {
        let relation = InBoundsIndexRelation;
        prove_and_verify_relation(&relation, &(), (2u64, 3u32))
            .expect("index_constraints_accept_strict_order_below_m should succeed");

        let relation = IncreasingIndexRelation;
        prove_and_verify_relation(&relation, &(), (1u64, 2u64))
            .expect("index_constraints_accept_strict_order_below_m should succeed");
    }

    #[test]
    fn index_constraints_reject_index_at_upper_bound() {
        let relation = InBoundsIndexRelation;
        assert_relation_rejected(prove_and_verify_relation(&relation, &(), (3u64, 3u32)));
    }
}
