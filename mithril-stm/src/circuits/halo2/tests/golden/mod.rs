//! Golden tests lock in Halo2 STM circuit behavior for safe refactors and hardening.
//! cases/ holds the test cases (positive and negative); helpers.rs provides shared helpers.

pub(crate) mod cases;
pub(crate) mod helpers;

#[cfg(test)]
mod golden_verification_key_test {

    use crate::{
        Parameters,
        circuits::halo2::tests::golden::helpers::compute_unsafe_circuit_verification_key,
    };

    // Golden test circuit verification key for the non-recursive circuit
    // This key is generated with the following parameters:
    // - m: 10,
    // - k: 1,
    // - phi_f: 0.2,
    // - merkle_tree_depth: 3
    const GOLDEN_NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY: &[u8] =
        include_bytes!("assets/golden_non_recursive_verification_key.asset");

    fn golden_value_non_recursive_circuit() -> Vec<u8> {
        let params = Parameters {
            m: 10,
            k: 1,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 3;
        compute_unsafe_circuit_verification_key(&params, merkle_tree_depth)
    }

    #[test]
    fn golden_non_recursive_modification_test() {
        let golden_value = golden_value_non_recursive_circuit();
        assert_eq!(
            GOLDEN_NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY,
            golden_value.as_slice()
        );
    }
}
