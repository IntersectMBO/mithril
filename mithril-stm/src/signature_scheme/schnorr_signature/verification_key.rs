use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use anyhow::{Context, anyhow};
use midnight_curves::JubjubSubgroup;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    StandardSchnorrSignature, StmResult,
    signature_scheme::{
        BaseFieldElement,
        schnorr_signature::DOMAIN_SEPARATION_TAG_SCHNORR_PROOF_OF_BOUND_POSSESSION,
    },
};

use super::{PrimeOrderProjectivePoint, ProjectivePoint, SchnorrSignatureError, SchnorrSigningKey};

/// Schnorr verification key, it consists of a point on the Jubjub curve
/// vk = g * sk, where g is a generator
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrVerificationKey(pub(crate) PrimeOrderProjectivePoint);

impl SchnorrVerificationKey {
    /// Convert a Schnorr signing key into a verification key
    ///
    /// This is done by computing `vk = g * sk` where g is the generator
    /// of the subgroup and sk is the schnorr signing key
    pub fn new_from_signing_key(signing_key: SchnorrSigningKey) -> Self {
        let generator = PrimeOrderProjectivePoint::create_generator();

        SchnorrVerificationKey(signing_key.0 * generator)
    }

    pub fn is_valid(&self) -> StmResult<()> {
        let projective_point = ProjectivePoint::from(self.0);
        if !projective_point.is_prime_order() {
            return Err(anyhow!(SchnorrSignatureError::PointIsNotPrimeOrder(
                Box::new(self.0)
            )));
        }
        self.0.is_on_curve()?;

        Ok(())
    }

    /// Implementation of the verification of the proof of bound possession of a Schnorr signing key.
    ///
    /// This function receives a prefix and verifies a standard Schnorr signature of:
    /// Sha256("SCHNORR_POBP_DST" || prefix || verification_key_bytes)
    /// to assert that a signing key is bound to a given stake, epoch and pool_id.
    /// The prefix is composed of a given stake, epoch and pool_id.
    pub fn verify_proof_of_bound_possession(
        &self,
        prefix: &[u8],
        signature: &StandardSchnorrSignature,
    ) -> StmResult<()> {
        let digest: [u8; 32] = Sha256::digest(
            [
                DOMAIN_SEPARATION_TAG_SCHNORR_PROOF_OF_BOUND_POSSESSION,
                prefix,
                &self.to_bytes(),
            ]
            .concat(),
        )
        .into();
        let field_element = BaseFieldElement::from_raw(&digest)?;
        signature.verify(&[field_element], self)
    }

    /// Returns the underlying Jubjub subgroup point for circuit witness encoding.
    pub(crate) fn as_jubjub_subgroup(&self) -> &JubjubSubgroup {
        &self.0.0
    }

    /// Convert a `SchnorrVerificationKey` into bytes by decomposing it into
    /// its coordinates first.
    pub fn to_bytes(self) -> [u8; 64] {
        let (x, y) = self.0.get_coordinates();
        let mut output = [0; 64];
        output[0..32].copy_from_slice(&x.to_bytes());
        output[32..64].copy_from_slice(&y.to_bytes());
        output
    }

    /// Convert bytes into a `SchnorrVerificationKey`.
    ///
    /// The bytes must represent two Jubjub Base field elements or the conversion will fail
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if bytes.len() < 64 {
            return Err(anyhow!(SchnorrSignatureError::Serialization)).with_context(
                || "Not enough bytes provided to construct a Schnorr verification key.",
            );
        }
        let x = BaseFieldElement::from_bytes(&bytes[0..32])?;
        let y = BaseFieldElement::from_bytes(&bytes[32..64])?;
        let prime_order_projective_point = PrimeOrderProjectivePoint::from_coordinates(x, y)
            .with_context(|| "Cannot construct Schnorr verification key from given bytes.")?;

        Ok(SchnorrVerificationKey(prime_order_projective_point))
    }
}

impl Hash for SchnorrVerificationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash_slice(&self.to_bytes(), state)
    }
}

impl PartialOrd for SchnorrVerificationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for SchnorrVerificationKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::signature_scheme::{ScalarFieldElement, SchnorrSigningKey, SchnorrVerificationKey};

    #[test]
    fn different_signing_keys_produce_different_verification_keys() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk1 = SchnorrSigningKey::generate(&mut rng);
        let sk2 = SchnorrSigningKey::generate(&mut rng);

        let vk1 = SchnorrVerificationKey::new_from_signing_key(sk1);
        let vk2 = SchnorrVerificationKey::new_from_signing_key(sk2);

        assert_ne!(
            vk1, vk2,
            "Different signing keys should produce different verification keys"
        );
    }

    #[test]
    fn same_signing_key_produces_same_verification_key() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);

        let vk1 = SchnorrVerificationKey::new_from_signing_key(sk.clone());
        let vk2 = SchnorrVerificationKey::new_from_signing_key(sk);

        assert_eq!(
            vk1, vk2,
            "Same signing key should produce same verification key"
        );
    }

    #[test]
    fn valid_verification_key_passes_validation() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk);

        let result = vk.is_valid();

        assert!(
            result.is_ok(),
            "Valid verification key should pass validation"
        );
    }

    #[test]
    fn zero_verification_key_fails_validation() {
        let sk = SchnorrSigningKey(ScalarFieldElement::get_zero());
        let vk = SchnorrVerificationKey::new_from_signing_key(sk);

        let result = vk.is_valid();

        assert!(
            result.is_err(),
            "Zero verification key should fail validation"
        );
    }

    #[test]
    fn from_bytes_not_enough_bytes() {
        let bytes = vec![0u8; 31];
        let result = SchnorrVerificationKey::from_bytes(&bytes);

        result.expect_err("Should fail with insufficient bytes");
    }

    #[test]
    fn from_bytes_exact_size() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk);
        let vk_bytes = vk.to_bytes();

        let vk_restored = SchnorrVerificationKey::from_bytes(&vk_bytes).unwrap();

        assert_eq!(vk, vk_restored);
    }

    #[test]
    fn from_bytes_extra_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk);
        let vk_bytes = vk.to_bytes();

        let mut extended_bytes = vk_bytes.to_vec();
        extended_bytes.extend_from_slice(&[0xFF; 10]);

        let vk_restored = SchnorrVerificationKey::from_bytes(&extended_bytes).unwrap();

        assert_eq!(vk, vk_restored);
    }

    #[test]
    fn to_bytes_is_deterministic() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk);

        let bytes1 = vk.to_bytes();
        let bytes2 = vk.to_bytes();

        assert_eq!(bytes1, bytes2, "to_bytes should be deterministic");
    }

    #[test]
    fn valid_proof_of_bound_possession_verification() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());
        let prefix = b"stake=100|epoch=5|pool_id=pool1abc";

        let signature = sk.create_proof_of_bound_possession(prefix, &mut rng).unwrap();

        vk.verify_proof_of_bound_possession(prefix, &signature)
            .expect("Valid PoBP should verify successfully");
    }

    #[test]
    fn proof_of_bound_possession_fails_with_wrong_prefix() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());
        let prefix = b"stake=100|epoch=5|pool_id=pool1abc";
        let replayed_prefix = b"stake=100|epoch=6|pool_id=pool1abc"; // different epoch

        let signature = sk.create_proof_of_bound_possession(prefix, &mut rng).unwrap();

        vk.verify_proof_of_bound_possession(replayed_prefix, &signature)
            .expect_err("PoBP signed for one prefix must not verify against a different prefix");
    }

    #[test]
    fn proof_of_bound_possession_fails_with_wrong_verification_key() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk1 = SchnorrSigningKey::generate(&mut rng);
        let sk2 = SchnorrSigningKey::generate(&mut rng);
        let vk2 = SchnorrVerificationKey::new_from_signing_key(sk2);
        let prefix = b"stake=100|epoch=5|pool_id=pool1abc";

        let signature = sk1.create_proof_of_bound_possession(prefix, &mut rng).unwrap();

        vk2.verify_proof_of_bound_possession(prefix, &signature)
            .expect_err("PoBP signed by sk1 must not verify against sk2's verification key");
    }

    #[test]
    fn proof_of_bound_possession_succeeds_with_empty_prefix() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let vk = SchnorrVerificationKey::new_from_signing_key(sk.clone());

        let signature = sk.create_proof_of_bound_possession(&[], &mut rng).unwrap();

        vk.verify_proof_of_bound_possession(&[], &signature)
            .expect("Empty prefix should still round-trip successfully");
    }

    mod golden {
        use super::*;

        const GOLDEN_BYTES: &[u8; 64] = &[
            186, 22, 69, 162, 1, 67, 125, 160, 104, 197, 105, 109, 200, 34, 186, 196, 171, 155,
            191, 178, 11, 116, 108, 8, 111, 249, 47, 39, 137, 55, 62, 62, 144, 52, 95, 161, 127,
            253, 49, 32, 140, 217, 231, 207, 32, 238, 244, 196, 97, 241, 47, 95, 101, 9, 70, 136,
            194, 66, 187, 253, 200, 32, 218, 43,
        ];

        fn golden_value() -> SchnorrVerificationKey {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            SchnorrVerificationKey::new_from_signing_key(sk)
        }

        #[test]
        fn golden_conversions() {
            let value = SchnorrVerificationKey::from_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = SchnorrVerificationKey::to_bytes(value);
            let golden_serialized = SchnorrVerificationKey::to_bytes(golden_value());
            assert_eq!(golden_serialized, serialized);
        }
    }

    mod golden_json {
        use super::*;

        const GOLDEN_JSON: &str = r#"[144, 52, 95, 161, 127, 253, 49, 32, 140, 217, 231, 207, 32, 238, 244, 196, 97, 241, 47, 95, 101, 9, 70, 136, 194, 66, 187, 253, 200, 32, 218, 43]"#;

        fn golden_value() -> SchnorrVerificationKey {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = SchnorrSigningKey::generate(&mut rng);
            SchnorrVerificationKey::new_from_signing_key(sk)
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
