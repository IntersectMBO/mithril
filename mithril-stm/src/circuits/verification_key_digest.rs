//! Opaque digest identifying a circuit verification key.
//!
//! The digest is computed as a Poseidon hash over the SHA-256 hash of the canonical byte
//! serialization of a verifying key, so the Poseidon hasher absorbs a single field element, as
//! byte strings are fed to it elsewhere in the crate. Poseidon is SNARK-friendly and native to
//! the scalar field of the circuits, so the digest computation stays cheap if the registry check
//! is ever proven in-circuit. It lets callers reference a circuit verification key, for example
//! in a signed registry, without carrying the key itself or depending on its internal structure.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Context, anyhow};
use digest::Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;

use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::hash::poseidon::MidnightPoseidonDigest;
use crate::proof_system::{NonDeterministicSnarkProverFactory, SnarkProverFactory};
use crate::{MithrilMembershipDigest, Parameters, StmError, StmResult, codec::TryToBytes};

/// Byte length of a circuit verification key digest.
pub const CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE: usize = 32;

/// Poseidon digest of the SHA-256 hash of the canonical byte serialization of a circuit
/// verification key.
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

    /// Compute the digest of a verifying key already in its canonical byte serialization, hashing
    /// the bytes with SHA-256 first so the Poseidon hasher absorbs a single field element.
    fn from_canonical_key_bytes(canonical_key_bytes: &[u8]) -> Self {
        let canonical_key_bytes_hash: [u8; 32] = Sha256::digest(canonical_key_bytes).into();
        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(canonical_key_bytes_hash);
        Self(hasher.finalize().into())
    }

    /// Digest of the IVC circuit verification key.
    ///
    /// The IVC circuit does not depend on the protocol parameters, so its verification key is the
    /// embedded production constant for every deployment.
    pub fn for_ivc_circuit() -> Self {
        Self::from_canonical_key_bytes(RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION)
    }

    /// Digest of the embedded certificate circuit verification key generated for the production
    /// protocol parameters.
    ///
    /// The certificate circuit depends on the protocol parameters, so this digest only covers
    /// deployments running with the production parameters.
    pub fn for_production_certificate_circuit() -> Self {
        Self::from_canonical_key_bytes(NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION)
    }

    /// Compute the digest of the certificate circuit verification key for the given protocol
    /// parameters, deriving the key from the trusted setup when it is not cached yet.
    ///
    /// The key is derived through the same prover the clerk uses to aggregate signatures, so the
    /// digest matches the one carried by the certificates produced with these parameters.
    pub fn compute_for_certificate_circuit(parameters: &Parameters) -> StmResult<Self> {
        let prover =
            SnarkProverFactory::<MithrilMembershipDigest>::snark_aggregate_signature_prover(
                &NonDeterministicSnarkProverFactory,
                parameters,
            )?;

        Self::try_from_verification_key(prover.verifying_key())
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

    fn from_str(s: &str) -> StmResult<Self> {
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
        println!(
            "certificate-circuit (production protocol parameters): {}",
            CircuitVerificationKeyDigest::for_production_certificate_circuit()
        );
        println!(
            "ivc-circuit: {}",
            CircuitVerificationKeyDigest::for_ivc_circuit()
        );
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
    fn digest_is_poseidon_hash_of_the_sha256_hash_of_canonical_key_bytes() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let digest = CircuitVerificationKeyDigest::try_from_verification_key(
            &context.certificate_verifying_key,
        )
        .unwrap();

        let canonical_key_bytes_hash: [u8; 32] =
            Sha256::digest(context.certificate_verifying_key.to_bytes_vec().unwrap()).into();
        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(canonical_key_bytes_hash);
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
                "9e68083f22b192e8c0ec6a62c2904ec546128a7bf4bb45138be8fa1a114e1f00",
                digest.to_string(),
                "golden circuit verification key digest changed for a fixed input, this alters the digest computation and breaks published circuit verification key registries"
            );
        }

        #[test]
        fn golden_digests_of_production_circuit_keys() {
            assert_eq!(
                "beca1c3e5b14ba8b74bad0177e1d762078473b33aaacb7017dd7425c53f61d25",
                CircuitVerificationKeyDigest::for_production_certificate_circuit().to_string(),
                "golden production certificate circuit verification key digest changed, either the digest computation or the embedded production key changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "cf0e9d63b167d81431b96bdf71bdaa7d0d947f134329cfacaa9d4e31794c3069",
                CircuitVerificationKeyDigest::for_ivc_circuit().to_string(),
                "golden IVC circuit verification key digest changed, either the digest computation or the embedded production key changed, which breaks published circuit verification key registries"
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
                CircuitVerificationKeyDigest::try_from_verification_key(&certificate_verifying_key)
                    .unwrap(),
                CircuitVerificationKeyDigest::for_production_certificate_circuit(),
                "the embedded production certificate key constant must stay the canonical key serialization"
            );
            assert_eq!(
                CircuitVerificationKeyDigest::try_from_verification_key(&recursive_verifying_key)
                    .unwrap(),
                CircuitVerificationKeyDigest::for_ivc_circuit(),
                "the embedded IVC key constant must stay the canonical key serialization"
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
                "653471392ada496934d7752f9b483efd92ae6c3271af636945c4b4ce74ae316c",
                certificate_key_digest.to_string(),
                "golden certificate circuit verification key digest changed, either the digest computation or the canonical key serialization changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "770a223fac0f319f0a76990b2c71a6faa7e3525c29d37eb80bf9fe5d5406b221",
                recursive_key_digest.to_string(),
                "golden IVC circuit verification key digest changed, either the digest computation or the canonical key serialization changed, which breaks published circuit verification key registries"
            );
        }
    }
}
