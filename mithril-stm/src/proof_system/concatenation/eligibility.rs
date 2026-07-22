use anyhow::anyhow;

use crate::{PhiFValue, Stake, StmResult};

cfg_num_integer! {
    use num_bigint::{BigInt, Sign};
    use num_rational::Ratio;
    use num_traits::{One, Signed};
    use std::ops::Neg;

    /// Checks that ev is successful in the lottery. In particular, it compares the output of `phi`
    /// (a real) to the output of `ev` (a hash).  It uses the same technique used in the
    /// [Cardano ledger](https://github.com/input-output-hk/cardano-ledger/). In particular,
    /// `ev` is a natural in `[0,2^512]`, while `phi` is a floating point in `[0, 1]`, and so what
    /// this check does is verify whether `p < 1 - (1 - phi_f)^w`, with `p = ev / 2^512`.
    ///
    /// The calculation is done using the following optimization:
    ///
    /// let `q = 1 / (1 - p)` and `c = ln(1 - phi_f)`
    ///
    /// then          `p < 1 - (1 - phi_f)^w`
    /// `<=> 1 / (1 - p) < exp(-w * c)`
    /// `<=> q           < exp(-w * c)`
    ///
    /// This can be computed using the taylor expansion. Using error estimation, we can do
    /// an early stop, once we know that the result is either above or below.  We iterate 1000
    /// times. If no conclusive result has been reached, we return false.
    ///
    /// Note that         1             1               evMax
    ///             q = ----- = ------------------ = -------------
    ///                 1 - p    1 - (ev / evMax)    (evMax - ev)
    ///
    /// Used to determine winning lottery tickets.
    pub(crate) fn is_lottery_won(phi_f: PhiFValue, ev: [u8; 64], stake: Stake, total_stake: Stake) -> StmResult<bool> {
        // If phi_f = 1, then we automatically break with true
        if (phi_f - 1.0).abs() < PhiFValue::EPSILON {
            return Ok(true);
        } else if !(phi_f > 0.0 && phi_f <= 1.0) {
            return Err(anyhow!("phi_f must be in the range (0, 1], got {phi_f}"));
        }

        let ev_max = BigInt::from(2u8).pow(512);
        let ev = BigInt::from_bytes_le(Sign::Plus, &ev);
        let q = Ratio::new_raw(ev_max.clone(), ev_max - ev);

        let c =
            Ratio::from_float((1.0 - phi_f).ln()).ok_or_else(|| anyhow!("phi_f must not be infinite or NaN, got {phi_f}"))?;
        let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total_stake));
        let x = (w * c).neg();

        // Now we compute a taylor function that breaks when the result is known.
        Ok(taylor_comparison(1000, q, x))
    }

    /// Checks if cmp < exp(x). Uses error approximation for an early stop. Whenever the value being
    /// compared, `cmp`, is smaller (or greater) than the current approximation minus an `error_term`
    /// (plus an `error_term` respectively), then we stop approximating. The choice of the `error_term`
    /// is specific to our use case, and this function should not be used in other contexts without
    /// reconsidering the `error_term`. As a conservative value of the `error_term` we choose
    /// `new_x * M`, where `new_x` is the next term of the taylor expansion, and `M` is the largest
    /// value of `x` in a reasonable range. Note that `x >= 0`, given that `x = - w * c`, with
    /// `0 <= w <= 1` and `c < 0`, as `c` is defined as `c = ln(1.0 - phi_f)` with `phi_f \in (0,1)`.
    /// Therefore, a good integral bound is the maximum value that `|ln(1.0 - phi_f)|` can take with
    /// `phi_f \in [0, 0.95]` (if we expect to have `phi_f > 0.95` this bound should be extended),
    /// which is `3`. Hence, we set `M = 3`.
    #[allow(clippy::redundant_clone)]
    fn taylor_comparison(bound: usize, cmp: Ratio<BigInt>, x: Ratio<BigInt>) -> bool {
        let mut new_x = x.clone();
        let mut phi: Ratio<BigInt> = One::one();
        let mut divisor: BigInt = One::one();
        for _ in 0..bound {
            phi += new_x.clone();

            divisor += 1;
            new_x = (new_x.clone() * x.clone()) / divisor.clone();
            let error_term = new_x.clone().abs() * BigInt::from(3); // new_x * M

            if cmp > (phi.clone() + error_term.clone()) {
                return false;
            } else if cmp < phi.clone() - error_term.clone() {
                return true;
            }
        }
        false
    }
}

cfg_rug! {
    use rug::{Float, integer::Order, ops::Pow};
    /// The crate `rug` has sufficient optimizations to not require a taylor approximation with early
    /// stop. The difference between the current implementation and the one using the optimization
    /// above is around 10% faster. We perform the computations with 117 significant bits of
    /// precision, since this is enough to represent the fraction of a single lovelace. We have that
    /// 1e6 lovelace equals 1 ada, and there is 45 billion ada in circulation. Meaning there are
    /// 4.5e16 lovelace, so 1e-17 is sufficient to represent fractions of the stake distribution. In
    /// order to keep the error in the 1e-17 range, we need to carry out the computations with 34
    /// decimal digits (in order to represent the 4.5e16 ada without any rounding errors, we need
    /// double that precision).
    pub(crate) fn is_lottery_won(phi_f: PhiFValue, ev: [u8; 64], stake: Stake, total_stake: Stake) -> StmResult<bool> {
        // If phi_f = 1, then we automatically break with true
        if (phi_f - 1.0).abs() < PhiFValue::EPSILON {
            return Ok(true);
        } else if !(phi_f > 0.0 && phi_f <= 1.0) {
            return Err(anyhow!("phi_f must be in the range (0, 1], got {phi_f}"));
        }
        let ev = rug::Integer::from_digits(&ev, Order::LsfLe);
        let ev_max: Float = Float::with_val(117, 2).pow(512);
        let q = ev / ev_max;

        let w = Float::with_val(117, stake) / Float::with_val(117, total_stake);
        let phi = Float::with_val(117, 1.0) - Float::with_val(117, 1.0 - phi_f).pow(w);

        Ok(q < phi)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, Sign};
    use num_rational::Ratio;
    use proptest::prelude::*;

    use super::*;
    // Implementation of `is_lottery_won` without approximation. We only get the precision of f64 here.
    fn trivial_is_lottery_won(phi_f: f64, ev: [u8; 64], stake: Stake, total_stake: Stake) -> bool {
        let ev_max = BigInt::from(2u8).pow(512);
        let ev = BigInt::from_bytes_le(Sign::Plus, &ev);
        let q = Ratio::new_raw(ev, ev_max);

        let w = stake as f64 / total_stake as f64;
        let phi = Ratio::from_float(1.0 - (1.0 - phi_f).powf(w)).unwrap();
        q < phi
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        /// Checking the `is_lottery_won` function.
        fn is_lottery_won_check_precision_against_trivial_implementation(
            phi_f in 0.01..0.5f64,
            ev_1 in any::<[u8; 32]>(),
            ev_2 in any::<[u8; 32]>(),
            total_stake in 100_000_000..1_000_000_000u64,
            stake in 1_000_000..50_000_000u64
        ) {
            let mut ev = [0u8; 64];
            ev.copy_from_slice(&[&ev_1[..], &ev_2[..]].concat());

            let quick_result = trivial_is_lottery_won(phi_f, ev, stake, total_stake);
            let result = is_lottery_won(phi_f, ev, stake, total_stake).unwrap();
            assert_eq!(quick_result, result);
        }

        #[cfg(any(feature = "num-integer-backend", target_family = "wasm", windows))]
        #[test]
        /// Checking the early break of Taylor computation
        fn taylor_comparison_breaks_early(
            x in -0.9..0.9f64,
        ) {
            let exponential = num_traits::float::Float::exp(x);
            let cmp_n = Ratio::from_float(exponential - 2e-10_f64).unwrap();
            let cmp_p = Ratio::from_float(exponential + 2e-10_f64).unwrap();
            assert!(taylor_comparison(1000, cmp_n, Ratio::from_float(x).unwrap()));
            assert!(!taylor_comparison(1000, cmp_p, Ratio::from_float(x).unwrap()));
        }
    }

    #[test]
    fn is_lottery_won_rejects_out_of_range_phi_f() {
        let ev = [0u8; 64];
        let stake = 100;
        let total_stake = 1000;

        for invalid_phi_f in [-0.5, 0.0, 1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                is_lottery_won(invalid_phi_f, ev, stake, total_stake).is_err(),
                "phi_f = {invalid_phi_f} should be rejected"
            );
        }
    }
}
