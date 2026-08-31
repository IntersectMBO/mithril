//! Opaque digest identifying a circuit verification key.
//!
//! The digest is computed as a Poseidon hash over the canonical byte serialization of a
//! verifying key. Poseidon is SNARK-friendly and native to the scalar field of the circuits, so
//! the digest computation stays cheap if the registry check is ever proven in-circuit. It lets
//! callers reference a circuit verification key, for example in a signed registry, without
//! carrying the key itself or depending on its internal structure.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Context, anyhow};
use digest::Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::hash::poseidon::MidnightPoseidonDigest;
use crate::{StmError, StmResult, codec::TryToBytes};

/// Byte length of a circuit verification key digest.
pub const CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE: usize = 32;

/// Poseidon digest of the canonical byte serialization of a circuit verification key.
///
/// Serialized as a lowercase hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CircuitVerificationKeyDigest([u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE]);

impl CircuitVerificationKeyDigest {
    /// Compute the digest of a verifying key from its canonical byte serialization.
    pub(crate) fn try_from_verification_key<K: TryToBytes>(
        verification_key: &K,
    ) -> StmResult<Self> {
        Ok(Self::from_canonical_key_bytes(
            &verification_key.to_bytes_vec()?,
        ))
    }

    /// Compute the digest of a verifying key already in its canonical byte serialization.
    fn from_canonical_key_bytes(canonical_key_bytes: &[u8]) -> Self {
        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(canonical_key_bytes);
        Self(hasher.finalize().into())
    }

    /// Compute the digests of the embedded production circuit verification keys, certificate
    /// circuit first, then IVC circuit.
    ///
    /// The embedded constants are already the canonical key serializations, so the digests are
    /// computed directly over them without the costly verifying key deserialization.
    pub fn compute_for_production_circuits() -> (Self, Self) {
        (
            Self::from_canonical_key_bytes(NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION),
            Self::from_canonical_key_bytes(RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION),
        )
    }

    /// Return the digest bytes.
    pub fn as_bytes(&self) -> &[u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE] {
        &self.0
    }
}

impl Display for CircuitVerificationKeyDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for CircuitVerificationKeyDigest {
    type Err = StmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            hex::decode(s).with_context(|| "CircuitVerificationKeyDigest: invalid hex encoding")?;
        let bytes: [u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE] =
            bytes.try_into().map_err(|bytes: Vec<u8>| {
                anyhow!(
                    "CircuitVerificationKeyDigest: expected {CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE} bytes, got {}",
                    bytes.len()
                )
            })?;

        Ok(Self(bytes))
    }
}

impl Serialize for CircuitVerificationKeyDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CircuitVerificationKeyDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_string = String::deserialize(deserializer)?;
        hex_string.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::halo2_ivc::tests::common::asset_readers::load_embedded_verification_context_asset;

    use super::*;

    #[test]
    #[ignore = "helper printing the production circuit verification key digests, run it to author the circuit verification key registry"]
    fn print_circuit_verification_key_digests_for_production() {
        let (certificate_circuit_digest, ivc_circuit_digest) =
            CircuitVerificationKeyDigest::compute_for_production_circuits();

        println!("certificate-circuit: {certificate_circuit_digest}");
        println!("ivc-circuit: {ivc_circuit_digest}");
    }

    #[test]
    fn digest_is_deterministic_and_separates_different_keys() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let certificate_key_digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();
        let certificate_key_digest_again = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();
        let recursive_key_digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.recursive_verifying_key,
        )
        .unwrap();

        assert_eq!(certificate_key_digest, certificate_key_digest_again);
        assert_ne!(certificate_key_digest, recursive_key_digest);
    }

    #[test]
    fn digest_is_poseidon_hash_of_canonical_key_bytes() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();

        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(context.certificate_verifying_key.to_bytes_vec().unwrap());
        let expected: [u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE] = hasher.finalize().into();

        assert_eq!(&expected, digest.as_bytes());
    }

    #[test]
    fn digest_round_trips_through_hex_string() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();

        let hex_string = digest.to_string();
        let restored: CircuitVerificationKeyDigest = hex_string.parse().unwrap();

        assert_eq!(digest, restored);
    }

    #[test]
    fn digest_round_trips_through_serde_json() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();

        let json = serde_json::to_string(&digest).unwrap();
        let restored: CircuitVerificationKeyDigest = serde_json::from_str(&json).unwrap();

        assert_eq!(json, format!("\"{digest}\""));
        assert_eq!(digest, restored);
    }

    #[test]
    fn from_str_rejects_invalid_hex_and_wrong_length() {
        "not-hex"
            .parse::<CircuitVerificationKeyDigest>()
            .expect_err("non-hex input must be rejected");
        "abcd"
            .parse::<CircuitVerificationKeyDigest>()
            .expect_err("input shorter than the digest size must be rejected");
    }

    mod golden {
        use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
        use crate::circuits::halo2_ivc::keys::RecursiveCircuitVerifyingKey;
        use crate::codec::TryFromBytes;

        use super::*;

        struct FixedBytesVerificationKey(Vec<u8>);

        impl TryToBytes for FixedBytesVerificationKey {
            fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
                Ok(self.0.clone())
            }
        }

        #[test]
        fn golden_digest_of_fixed_verification_key_bytes() {
            let digest = CircuitVerificationKeyDigest::try_from_verification_key(
                &FixedBytesVerificationKey(vec![42u8; 64]),
            )
            .unwrap();

            assert_eq!(
                "5cfbcf921d5b29e3d449c5ecd707dd78924612790a27a68610c1cf0af3b7cc52",
                digest.to_string(),
                "golden circuit verification key digest changed for a fixed input, this alters the digest computation and breaks published circuit verification key registries"
            );
        }

        #[test]
        fn golden_digests_of_production_circuit_keys() {
            let (certificate_circuit_digest, ivc_circuit_digest) =
                CircuitVerificationKeyDigest::compute_for_production_circuits();

            assert_eq!(
                "1264305828d13c48a7b85b0cf472198d5a8014d8c06b50e9f4dd9c586249355c",
                certificate_circuit_digest.to_string(),
                "golden production certificate circuit verification key digest changed, either the digest computation or the embedded production key changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "e2077c751852ee5a4e0908b7b963e037bac64f6fd0bf1af2ff1f012e0aa57e57",
                ivc_circuit_digest.to_string(),
                "golden production IVC circuit verification key digest changed, either the digest computation or the embedded production key changed, which breaks published circuit verification key registries"
            );
        }

        #[test]
        fn production_digests_match_the_deserialized_embedded_production_keys() {
            let certificate_verifying_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            )
            .unwrap();
            let recursive_verifying_key = RecursiveCircuitVerifyingKey::try_from_bytes(
                RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            )
            .unwrap();

            assert_eq!(
                (
                    CircuitVerificationKeyDigest::try_from_verification_key(
                        &certificate_verifying_key
                    )
                    .unwrap(),
                    CircuitVerificationKeyDigest::try_from_verification_key(
                        &recursive_verifying_key
                    )
                    .unwrap(),
                ),
                CircuitVerificationKeyDigest::compute_for_production_circuits(),
                "the embedded production key constants must stay the canonical key serializations"
            );
        }

        #[test]
        fn golden_digests_of_embedded_verification_context_keys() {
            let context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");

            let certificate_key_digest = CircuitVerificationKeyDigest::try_from_verification_key(
                &context.certificate_verifying_key,
            )
            .unwrap();
            let recursive_key_digest = CircuitVerificationKeyDigest::try_from_verification_key(
                &context.recursive_verifying_key,
            )
            .unwrap();

            assert_eq!(
                "1ecb40d6ba62504520a904ae053f7ad6747ce2ebafd7facef3fb4009d52b6336",
                certificate_key_digest.to_string(),
                "golden certificate circuit verification key digest changed, either the digest computation or the canonical key serialization changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "08174d68b60d5655d0def90e6d3680f8bd6216a1c714bc3c6111d7c1d8472a28",
                recursive_key_digest.to_string(),
                "golden IVC circuit verification key digest changed, either the digest computation or the canonical key serialization changed, which breaks published circuit verification key registries"
            );
        }
    }
}
