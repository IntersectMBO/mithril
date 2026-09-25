//! Golden tests lock in recursive Halo2 IVC verification behavior.

mod positive;

#[cfg(test)]
mod golden_verification_key_test {

    use crate::circuits::halo2_ivc::tests::common::generators::golden_recursive_circuit_verification_key_bytes;

    // Golden test circuit verification key for the recursive circuit
    // This key is generated with an unsafe SRS generated on the fly
    // used to also generate a non-recursive verification key
    const GOLDEN_RECURSIVE_CIRCUIT_VERIFICATION_KEY: &[u8] =
        include_bytes!("../assets/golden_recursive_circuit_verification_key.asset");

    mod slow {
        use super::*;

        #[test]
        pub fn golden_recursive_modification_test() {
            let golden_value = golden_recursive_circuit_verification_key_bytes();

            assert_eq!(
                GOLDEN_RECURSIVE_CIRCUIT_VERIFICATION_KEY,
                golden_value.as_slice()
            );
        }
    }
}
