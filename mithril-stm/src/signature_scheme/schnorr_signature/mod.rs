//! Schnorr Signature module
//!
//! This module implements standard Schnorr signature and a variant of the algorithm.
//! Specifically, it extends the classic scheme by appending a deterministic
//! value derived solely from the message and the signing key. This ungrindable
//! value produces a unique, reproducible identification tag for each signature,
//! which can be leveraged in lottery-based schemes such as Mithril multi-signatures.

mod error;
mod jubjub;
mod signing_key;
mod standard_signature;
mod unique_signature;
mod verification_key;

pub use error::*;
pub use jubjub::BaseFieldElement;
pub(crate) use jubjub::DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE;
pub(crate) use jubjub::*;
pub use signing_key::*;
pub use standard_signature::*;
pub use unique_signature::*;
pub use verification_key::*;

/// Domain Separation Tag (DST) for the Schnorr Proof of Bound Possession.
const DOMAIN_SEPARATION_TAG_SCHNORR_PROOF_OF_BOUND_POSSESSION: &[u8] = b"SCHNORR_POBP_DST";

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::signature_scheme::{
        BaseFieldElement, PrimeOrderProjectivePoint, SchnorrSignatureError, SchnorrSigningKey,
        SchnorrVerificationKey, UniqueSchnorrSignature,
    };

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn verification_key(seed in any::<[u8;32]>()) {
            // Valid generation check
            let sk = SchnorrSigningKey::generate(&mut ChaCha20Rng::from_seed(seed));
            let g = PrimeOrderProjectivePoint::create_generator();
            let vk = sk.0 * g;
            let vk_from_sk = SchnorrVerificationKey::new_from_signing_key(sk);
            assert_eq!(vk, vk_from_sk.0);
        }

        #[test]
        fn valid_signing_verification(
            msg in prop::collection::vec(any::<u8>(), 1..128),
            seed in any::<[u8;32]>(),
        ) {
            let sk = SchnorrSigningKey::generate(&mut ChaCha20Rng::from_seed(seed));
            let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();

            let sig_result = sk.sign_unique(&[base_input], &mut ChaCha20Rng::from_seed(seed));
            assert!(sig_result.is_ok(), "Signature generation failed");

            let sig = sig_result.unwrap();

            assert!(sig.verify(&[base_input], &vk).is_ok(), "Verification failed.");
        }

        #[test]
        fn invalid_signature(msg in prop::collection::vec(any::<u8>(), 1..128), seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk1 = SchnorrSigningKey::generate(&mut rng);
            let vk1 = SchnorrVerificationKey::new_from_signing_key(sk1);
            let sk2 = SchnorrSigningKey::generate(&mut rng);
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            let fake_sig = sk2.sign_unique(&[base_input], &mut rng).unwrap();

            let error = fake_sig.verify(&[base_input], &vk1).expect_err("Fake signature should not be verified");

            assert!(
                matches!(
                    error.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::UniqueSignatureInvalid(_))
                ),
                "Unexpected error: {error:?}"
            );
        }

        #[test]
        fn signing_key_to_from_bytes(seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let mut sk_bytes = sk.to_bytes();

            // Valid conversion
            let recovered_sk = SchnorrSigningKey::from_bytes(&sk_bytes).unwrap();
            assert_eq!(sk.0, recovered_sk.0, "Recovered signing key does not match with the original!");

            // Not enough bytes
            let mut short_bytes = [0u8; 31];
            short_bytes.copy_from_slice(sk_bytes.get(..31).unwrap());
            let result = SchnorrSigningKey::from_bytes(&short_bytes).expect_err("From bytes conversion of signing key should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::Serialization)
                ),
                "Unexpected error: {result:?}"
            );

            // Invalid bytes
            sk_bytes[31] |= 0xff;
            let result = SchnorrSigningKey::from_bytes(&sk_bytes).expect_err("From bytes conversion of signing key should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::ScalarFieldElementSerialization)
                ),
                "Unexpected error: {result:?}"
            );
        }

        #[test]
        fn verification_key_to_from_bytes(seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());
            let mut vk_bytes = vk.to_bytes();

            // Valid conversion
            let recovered_vk = SchnorrVerificationKey::from_bytes(&vk_bytes).unwrap();
            assert_eq!(vk.0, recovered_vk.0, "Recovered verification key does not match with the original!");

            // Not enough bytes
            let mut short_bytes = [0u8; 31];
            short_bytes.copy_from_slice(vk_bytes.get(..31).unwrap());
            let result = SchnorrVerificationKey::from_bytes(&short_bytes).expect_err("From bytes conversion of verification key should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::Serialization)
                ),
                "Unexpected error: {result:?}"
            );

            // Invalid bytes
            vk_bytes[31] |= 0xff;
            let result = SchnorrVerificationKey::from_bytes(&vk_bytes).expect_err("From bytes conversion of verification key should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::BaseFieldElementSerialization)
                ),
                "Unexpected error: {result:?}"
            );
        }

        #[test]
        fn signature_to_from_bytes(msg in prop::collection::vec(any::<u8>(), 1..128), seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            let signature = sk.sign_unique(&[base_input], &mut ChaCha20Rng::from_seed(seed)).unwrap();
            let signature_bytes = signature.to_bytes();

            // Valid conversion
            let recovered_signature = UniqueSchnorrSignature::from_bytes(&signature_bytes).unwrap();
            assert_eq!(signature, recovered_signature, "Recovered signature does not match with the original!");

            // Test invalid `commitment_point`
            let mut corrupted_bytes = signature_bytes;
            corrupted_bytes[31] |= 0xff;
            let result = UniqueSchnorrSignature::from_bytes(&corrupted_bytes).expect_err("From bytes conversion of signature should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::ProjectivePointSerialization)
                ),
                "Unexpected error: {result:?}"
            );

            // Test invalid `response`
            let mut corrupted_bytes = signature_bytes;
            corrupted_bytes[63] |= 0xff;
            let result = UniqueSchnorrSignature::from_bytes(&corrupted_bytes).expect_err("From bytes conversion should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::ScalarFieldElementSerialization)
                ),
                "Unexpected error: {result:?}"
            );

            // Test invalid `challenge`
            let mut corrupted_bytes = signature_bytes;
            corrupted_bytes[95] |= 0xff;
            let result = UniqueSchnorrSignature::from_bytes(&corrupted_bytes).expect_err("From bytes conversion should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::BaseFieldElementSerialization)
                ),
                "Unexpected error: {result:?}"
            );

            // Not enough bytes
            let mut short_bytes = [0u8; 95];
            short_bytes.copy_from_slice(signature_bytes.get(..95).unwrap());
            let result = UniqueSchnorrSignature::from_bytes(&short_bytes).expect_err("From bytes conversion of signature should fail");
            assert!(
                matches!(
                    result.downcast_ref::<SchnorrSignatureError>(),
                    Some(SchnorrSignatureError::Serialization)
                ),
                "Unexpected error: {result:?}"
            );
        }
    }
}
