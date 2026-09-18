use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

use crate::StmResult;

use super::{
    BaseFieldElement, DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE, PrimeOrderProjectivePoint,
    ProjectivePoint, ScalarFieldElement, SchnorrSignatureError, SchnorrVerificationKey,
    compute_poseidon_digest,
};

/// Structure of the Unique Schnorr signature to use with the SNARK
///
/// This signature includes a value `commitment_point` which depends only on
/// the message and the signing key.
/// This value is used in the lottery process to determine the correct indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct UniqueSchnorrSignature {
    /// Deterministic value depending on the message and signing key
    pub(crate) commitment_point: ProjectivePoint,
    /// Part of the Unique Schnorr signature depending on the signing key
    pub(crate) response: ScalarFieldElement,
    /// Part of the Unique Schnorr signature NOT depending on the signing key
    pub(crate) challenge: BaseFieldElement,
}

impl UniqueSchnorrSignature {
    /// This function performs the verification of a Unique Schnorr signature given the signature, the signed message
    /// and a verification key derived from the signing key used to sign.
    ///
    /// Input:
    ///     - a Unique Schnorr signature
    ///     - a message: some BaseFieldElements
    ///     - a verification key: a value depending on the signing key
    /// Output:
    ///     - Ok(()) if the signature verifies and an error if not
    ///
    /// The protocol computes:
    ///     - msg_hash_point = H(msg)
    ///     - random_point_1_recomputed = response * msg_hash_point + challenge * commitment_point
    ///     - random_point_2_recomputed = response * prime_order_generator_point + challenge * verification_key
    ///     - challenge_recomputed = Poseidon(DST || H(msg) || verification_key
    ///     || commitment_point || random_point_1_recomputed || random_point_2_recomputed)
    ///
    /// Check: challenge == challenge_recomputed
    ///
    pub fn verify(
        &self,
        msg: &[BaseFieldElement],
        verification_key: &SchnorrVerificationKey,
    ) -> StmResult<()> {
        // Check that the verification key is valid
        verification_key
            .is_valid()
            .with_context(|| "Signature verification failed due to invalid verification key")?;

        let prime_order_generator_point = PrimeOrderProjectivePoint::create_generator();

        // First hashing the message to a scalar then hashing it to a curve point
        let msg_hash_point = ProjectivePoint::hash_to_projective_point(msg)?;

        // Computing random_point_1_recomputed = response *  H(msg) + challenge * commitment_point
        let challenge_as_scalar = ScalarFieldElement::from_base_field(&self.challenge)?;
        let random_point_1_recomputed =
            self.response * msg_hash_point + challenge_as_scalar * self.commitment_point;

        // Computing random_point_2_recomputed = response * prime_order_generator_point + challenge * vk
        let random_point_2_recomputed =
            self.response * prime_order_generator_point + challenge_as_scalar * verification_key.0;

        // Since the hash function takes as input scalar elements
        // We need to convert the EC points to their coordinates
        let mut points_coordinates: Vec<BaseFieldElement> =
            vec![DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE];
        points_coordinates.extend(
            [
                msg_hash_point,
                ProjectivePoint::from(verification_key.0),
                self.commitment_point,
                random_point_1_recomputed,
                ProjectivePoint::from(random_point_2_recomputed),
            ]
            .iter()
            .flat_map(|point| {
                let (u, v) = point.get_coordinates();
                [u, v]
            }),
        );

        let challenge_recomputed = compute_poseidon_digest(&points_coordinates);

        if challenge_recomputed != self.challenge {
            return Err(anyhow!(SchnorrSignatureError::UniqueSignatureInvalid(
                Box::new(*self)
            )));
        }

        Ok(())
    }

    /// Convert a `UniqueSchnorrSignature` into its canonical raw byte representation.
    ///
    /// This exact byte layout is depended on by `SingleSignature`'s legacy decoder — it must
    /// not change.
    pub fn to_raw_bytes(self) -> [u8; 96] {
        let mut out = [0; 96];
        out[0..32].copy_from_slice(&self.commitment_point.to_bytes());
        out[32..64].copy_from_slice(&self.response.to_bytes());
        out[64..96].copy_from_slice(&self.challenge.to_bytes());

        out
    }

    /// Convert bytes into a `UniqueSchnorrSignature`.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        if bytes.len() < 96 {
            return Err(anyhow!(SchnorrSignatureError::Serialization))
                .with_context(|| "Not enough bytes provided to create a signature.");
        }

        let commitment_point = ProjectivePoint::from_bytes(
            bytes
                .get(0..32)
                .ok_or(SchnorrSignatureError::Serialization)
                .with_context(|| "Could not get the bytes of `commitment_point`")?,
        )
        .with_context(|| "Could not convert bytes to `commitment_point`")?;

        let response = ScalarFieldElement::from_bytes(
            bytes
                .get(32..64)
                .ok_or(SchnorrSignatureError::Serialization)
                .with_context(|| "Could not get the bytes of `response`")?,
        )
        .with_context(|| "Could not convert the bytes to `response`")?;

        let challenge = BaseFieldElement::from_bytes(
            bytes
                .get(64..96)
                .ok_or(SchnorrSignatureError::Serialization)
                .with_context(|| "Could not get the bytes of `challenge`")?,
        )
        .with_context(|| "Could not convert bytes to `challenge`")?;

        Ok(Self {
            commitment_point,
            response,
            challenge,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::signature_scheme::{
        BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, UniqueSchnorrSignature,
    };

    #[test]
    fn valid_signature_verification() {
        let msg = vec![0, 0, 0, 1];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());

        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();

        sig.verify(&[base_input], &vk)
            .expect("Valid signature should verify successfully");
    }

    #[test]
    fn invalid_signature() {
        let msg = vec![0, 0, 0, 1];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let msg2 = vec![0, 0, 0, 2];
        let base_input2 = BaseFieldElement::try_from(msg2.as_slice()).unwrap();
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());
        let sk2 = SchnorrSigningKey::generate(&mut rng);
        let vk2 = SchnorrVerificationKey::new_from_signing_key(sk2);

        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();
        let sig2 = sk.sign_unique(&[base_input2], &mut rng).unwrap();

        // Wrong verification key is used
        let result1 = sig.verify(&[base_input], &vk2);
        let result2 = sig2.verify(&[base_input], &vk);

        result1.expect_err("Wrong verification key used, test should fail.");
        // Wrong message is verified
        result2.expect_err("Wrong message used, test should fail.");
    }

    #[test]
    fn from_bytes_signature_not_enough_bytes() {
        let msg = vec![0u8; 95];
        let result = UniqueSchnorrSignature::from_raw_bytes(&msg);
        result.expect_err("Not enough bytes.");
    }

    #[test]
    fn from_bytes_signature_exact_size() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();
        let sig_bytes: [u8; 96] = sig.to_raw_bytes();

        let sig_restored = UniqueSchnorrSignature::from_raw_bytes(&sig_bytes).unwrap();
        assert_eq!(sig, sig_restored);
    }

    #[test]
    fn from_bytes_signature_extra_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();
        let sig_bytes: [u8; 96] = sig.to_raw_bytes();

        let mut extended_bytes = sig_bytes.to_vec();
        extended_bytes.extend_from_slice(&[0xFF; 10]);

        let sig_restored = UniqueSchnorrSignature::from_raw_bytes(&extended_bytes).unwrap();
        assert_eq!(sig, sig_restored);
    }

    #[test]
    fn to_bytes_is_deterministic() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();

        // Converting to bytes multiple times should give same result
        let bytes1 = sig.to_raw_bytes();
        let bytes2 = sig.to_raw_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn signature_roundtrip_preserves_verification() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let msg = vec![5, 6, 7, 8, 9];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());

        // Create and verify original signature
        let sig = sk.sign_unique(&[base_input], &mut rng).unwrap();
        sig.verify(&[base_input], &vk)
            .expect("Original signature should verify");

        // Roundtrip through bytes
        let sig_bytes = sig.to_raw_bytes();
        let sig_restored = UniqueSchnorrSignature::from_raw_bytes(&sig_bytes).unwrap();

        // Restored signature should still verify
        sig_restored
            .verify(&[base_input], &vk)
            .expect("Restored signature should verify");
    }

    mod golden {
        use super::*;

        const GOLDEN_BYTES: &[u8; 96] = &[
            39, 90, 41, 56, 174, 106, 33, 173, 254, 49, 113, 116, 208, 4, 121, 177, 236, 223, 173,
            108, 193, 135, 214, 159, 99, 93, 108, 202, 201, 200, 141, 148, 230, 175, 77, 63, 232,
            229, 34, 36, 7, 205, 254, 86, 70, 160, 49, 87, 114, 98, 20, 88, 141, 224, 113, 109,
            208, 226, 177, 140, 55, 79, 174, 10, 121, 59, 197, 98, 35, 17, 213, 33, 65, 143, 110,
            106, 145, 86, 141, 107, 204, 91, 39, 205, 113, 69, 87, 194, 239, 242, 188, 14, 194,
            239, 173, 14,
        ];

        fn golden_value() -> UniqueSchnorrSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let msg = [0u8; 32];
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            sk.sign_unique(&[base_input], &mut rng).unwrap()
        }

        #[test]
        fn golden_conversions() {
            let value = UniqueSchnorrSignature::from_raw_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = UniqueSchnorrSignature::to_raw_bytes(value);
            let golden_serialized = UniqueSchnorrSignature::to_raw_bytes(golden_value());
            assert_eq!(golden_serialized, serialized);
        }
    }

    mod golden_json {
        use super::*;

        const GOLDEN_JSON: &str = r#"
        {
            "commitment_point": [39, 90, 41, 56, 174, 106, 33, 173, 254, 49, 113, 116, 208, 4, 121, 177, 236, 223, 173, 108, 193, 135, 214, 159, 99, 93, 108, 202, 201, 200, 141, 148], 
            "response": [230, 175, 77, 63, 232, 229, 34, 36, 7, 205, 254, 86, 70, 160, 49, 87, 114, 98, 20, 88, 141, 224, 113, 109, 208, 226, 177, 140, 55, 79, 174, 10], 
            "challenge": [121, 59, 197, 98, 35, 17, 213, 33, 65, 143, 110, 106, 145, 86, 141, 107, 204, 91, 39, 205, 113, 69, 87, 194, 239, 242, 188, 14, 194, 239, 173, 14]
        }"#;

        fn golden_value() -> UniqueSchnorrSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let msg = [0u8; 32];
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            sk.sign_unique(&[base_input], &mut rng).unwrap()
        }

        #[test]
        fn golden_conversions() {
            let value = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_value(), value);

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }
    }
}
