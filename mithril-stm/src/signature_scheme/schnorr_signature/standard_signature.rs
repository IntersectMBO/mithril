use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

use crate::StmResult;

use super::{
    BaseFieldElement, DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE, PrimeOrderProjectivePoint,
    ProjectivePoint, ScalarFieldElement, SchnorrSignatureError, SchnorrVerificationKey,
    compute_poseidon_digest,
};

/// Structure of the standard (non-unique) Schnorr signature to use with the SNARK.
///
/// This signature consists of only a `response` and a `challenge`. It is used
/// by the SNARK genesis certificate, which does not require the
/// per-signer uniqueness tag carried by `UniqueSchnorrSignature`.
#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct StandardSchnorrSignature {
    /// Part of the standard Schnorr signature depending on the signing key
    pub(crate) response: ScalarFieldElement,
    /// Part of the standard Schnorr signature NOT depending on the signing key
    pub(crate) challenge: BaseFieldElement,
}

impl StandardSchnorrSignature {
    /// Verify a standard Schnorr signature against a verification key.
    pub fn verify(
        &self,
        msg: &[BaseFieldElement],
        verification_key: &SchnorrVerificationKey,
    ) -> StmResult<()> {
        verification_key
            .is_valid()
            .with_context(|| "Signature verification failed due to invalid verification key")?;

        let prime_order_generator_point = PrimeOrderProjectivePoint::create_generator();

        let challenge_as_scalar = ScalarFieldElement::from_base_field(&self.challenge)?;

        let random_point_recomputed =
            self.response * prime_order_generator_point + challenge_as_scalar * verification_key.0;

        let mut points_coordinates: Vec<BaseFieldElement> =
            vec![DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE];
        points_coordinates.extend(
            [
                ProjectivePoint::from(verification_key.0),
                ProjectivePoint::from(random_point_recomputed),
            ]
            .iter()
            .flat_map(|point| {
                let (u, v) = point.get_coordinates();
                [u, v]
            }),
        );

        points_coordinates.extend_from_slice(msg);
        let challenge_recomputed = compute_poseidon_digest(&points_coordinates);

        if challenge_recomputed != self.challenge {
            return Err(anyhow!(SchnorrSignatureError::StandardSignatureInvalid(
                Box::new(*self)
            )));
        }

        Ok(())
    }

    /// Convert a `StandardSchnorrSignature` into its canonical raw byte representation.
    ///
    /// This exact byte layout backs the public `SchnorrSignature` hex API (`ProtocolKey`'s
    /// `bytes_hex_codec`) and genesis certificate messages — it must not change.
    pub fn to_raw_bytes(self) -> [u8; 64] {
        let mut out = [0; 64];
        out[0..32].copy_from_slice(&self.response.to_bytes());
        out[32..64].copy_from_slice(&self.challenge.to_bytes());

        out
    }

    /// Convert bytes into a `StandardSchnorrSignature`.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        if bytes.len() < 64 {
            return Err(anyhow!(SchnorrSignatureError::Serialization))
                .with_context(|| "Not enough bytes provided to create a standard signature.");
        }

        let response = ScalarFieldElement::from_bytes(
            bytes
                .get(0..32)
                .ok_or(SchnorrSignatureError::Serialization)
                .with_context(|| "Could not get the bytes of `response`")?,
        )
        .with_context(|| "Could not convert the bytes to `response`")?;

        let challenge = BaseFieldElement::from_bytes(
            bytes
                .get(32..64)
                .ok_or(SchnorrSignatureError::Serialization)
                .with_context(|| "Could not get the bytes of `challenge`")?,
        )
        .with_context(|| "Could not convert bytes to `challenge`")?;

        Ok(Self {
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
        BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, StandardSchnorrSignature,
    };

    #[test]
    fn valid_signature_verification() {
        let msg = vec![0, 0, 0, 1];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());

        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();

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

        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();
        let sig2 = sk.sign_standard(&[base_input2], &mut rng).unwrap();

        // Wrong verification key is used
        let result1 = sig.verify(&[base_input], &vk2);
        let result2 = sig2.verify(&[base_input], &vk);

        result1.expect_err("Wrong verification key used, test should fail.");
        // Wrong message is verified
        result2.expect_err("Wrong message used, test should fail.");
    }

    #[test]
    fn from_bytes_signature_not_enough_bytes() {
        let msg = vec![0u8; 62];
        let result = StandardSchnorrSignature::from_raw_bytes(&msg);
        result.expect_err("Not enough bytes.");
    }

    #[test]
    fn from_bytes_signature_exact_size() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();
        let sig_bytes: [u8; 64] = sig.to_raw_bytes();

        let sig_restored = StandardSchnorrSignature::from_raw_bytes(&sig_bytes).unwrap();
        assert_eq!(sig, sig_restored);
    }

    #[test]
    fn from_bytes_signature_extra_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();
        let sig_bytes: [u8; 64] = sig.to_raw_bytes();

        let mut extended_bytes = sig_bytes.to_vec();
        extended_bytes.extend_from_slice(&[0xFF; 10]);

        let sig_restored = StandardSchnorrSignature::from_raw_bytes(&extended_bytes).unwrap();
        assert_eq!(sig, sig_restored);
    }

    #[test]
    fn to_bytes_is_deterministic() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let msg = vec![1, 2, 3];
        let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
        let sk = SchnorrSigningKey::generate(&mut rng);

        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();

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
        let sig = sk.sign_standard(&[base_input], &mut rng).unwrap();
        sig.verify(&[base_input], &vk)
            .expect("Original signature should verify");

        // Roundtrip through bytes
        let sig_bytes = sig.to_raw_bytes();
        let sig_restored = StandardSchnorrSignature::from_raw_bytes(&sig_bytes).unwrap();

        // Restored signature should still verify
        sig_restored
            .verify(&[base_input], &vk)
            .expect("Restored signature should verify");
    }

    mod golden {
        use super::*;

        const GOLDEN_BYTES: &[u8; 64] = &[
            89, 31, 136, 32, 189, 143, 85, 123, 245, 193, 16, 101, 157, 76, 171, 14, 26, 223, 158,
            251, 178, 94, 154, 145, 52, 226, 28, 128, 91, 194, 64, 13, 52, 213, 250, 160, 97, 148,
            121, 152, 86, 52, 119, 71, 95, 43, 99, 176, 253, 251, 93, 57, 253, 180, 166, 191, 154,
            32, 190, 221, 236, 248, 81, 22,
        ];

        fn golden_value() -> StandardSchnorrSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let msg = [0u8; 32];
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            sk.sign_standard(&[base_input], &mut rng).unwrap()
        }

        #[test]
        fn golden_conversions() {
            let value = StandardSchnorrSignature::from_raw_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = StandardSchnorrSignature::to_raw_bytes(value);
            let golden_serialized = StandardSchnorrSignature::to_raw_bytes(golden_value());
            assert_eq!(golden_serialized, serialized);
        }
    }

    mod golden_json {
        use super::*;

        const GOLDEN_JSON: &str = r#"
        {
            "response": [89,31,136,32,189,143,85,123,245,193,16,101,157,76,171,14,26,223,158,251,178,94,154,145,52,226,28,128,91,194,64,13],
            "challenge": [52,213,250,160,97,148,121,152,86,52,119,71,95,43,99,176,253,251,93,57,253,180,166,191,154,32,190,221,236,248,81,22]
        }"#;

        fn golden_value() -> StandardSchnorrSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            let msg = [0u8; 32];
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            sk.sign_standard(&[base_input], &mut rng).unwrap()
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
