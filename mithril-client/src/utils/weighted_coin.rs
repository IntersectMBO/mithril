use rand::{RngExt, SeedableRng};
use rand::distr::Bernoulli;
use rand::rngs::StdRng;

use mithril_common::entities::Percentage;

/// Seeded generator of booleans that are `true` with the probability of the given [Percentage].
///
/// For a given seed and percentage, the sequence of flips is always the same.
pub struct WeightedCoin {
    distribution: Bernoulli,
    rng: StdRng,
}

impl WeightedCoin {
    /// Constructs a new `WeightedCoin`.
    pub fn new(percentage: Percentage, seed: [u8; 32]) -> Self {
        Self {
            distribution: Bernoulli::from_ratio(u32::from(*percentage), 100)
                .expect("a Percentage is always within 0..=100"),
            rng: StdRng::from_seed(seed),
        }
    }

    /// Flip once, returning `true` with the probability of the percentage.
    pub fn flip(&mut self) -> bool {
        self.rng.sample(self.distribution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flip_n_times(coin: &mut WeightedCoin, n: usize) -> Vec<bool> {
        (0..n).map(|_| coin.flip()).collect()
    }

    #[test]
    fn zero_percent_always_yields_false() {
        let mut coin = WeightedCoin::new(Percentage::ZERO, [0; 32]);

        let flips = flip_n_times(&mut coin, 1_000);

        assert!(flips.iter().all(|flip| !flip));
    }

    #[test]
    fn hundred_percent_always_yields_true() {
        let mut coin = WeightedCoin::new(Percentage::HUNDRED, [0; 32]);

        let flips = flip_n_times(&mut coin, 1_000);

        assert!(flips.iter().all(|flip| *flip));
    }

    #[test]
    fn same_seed_and_percentage_yield_same_sequence() {
        let mut coin = WeightedCoin::new(Percentage::new(50), [7; 32]);
        let mut other_coin = WeightedCoin::new(Percentage::new(50), [7; 32]);

        assert_eq!(
            flip_n_times(&mut coin, 1_000),
            flip_n_times(&mut other_coin, 1_000)
        );
    }

    #[test]
    fn different_seeds_yield_different_sequences() {
        let mut coin = WeightedCoin::new(Percentage::new(50), [0; 32]);
        let mut other_coin = WeightedCoin::new(Percentage::new(50), [1; 32]);

        assert_ne!(
            flip_n_times(&mut coin, 1_000),
            flip_n_times(&mut other_coin, 1_000)
        );
    }

    #[test]
    fn ratio_of_true_is_close_to_percentage() {
        let total_flips = 30_000;
        let mut coin = WeightedCoin::new(Percentage::new(30), [0; 32]);

        let true_count = flip_n_times(&mut coin, total_flips).iter().filter(|flip| **flip).count();

        let true_ratio = true_count as f64 / total_flips as f64;
        assert!(
            (0.29..=0.31).contains(&true_ratio),
            "expected a ratio of true close to 0.30, got {true_ratio}"
        );
    }
}
