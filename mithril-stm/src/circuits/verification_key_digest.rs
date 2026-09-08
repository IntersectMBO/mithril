//! Opaque digest identifying a circuit verification key.
//!
//! The digest is computed as a Poseidon hash over the transcript representation of a verifying
//! key: the field element Halo2 derives from the pinned constraint system, the evaluation domain
//! and the fixed and permutation commitments. The serialized key bytes are not enough to identify
//! a circuit, as the recursive key serialization omits the constraint system, reconstructed from
//! the circuit code when the key is read, so two circuits with different gates can share the same
//! bytes. Poseidon is SNARK-friendly and native to the scalar field of the circuits, so the digest
//! computation stays cheap if the registry check is ever proven in-circuit. It lets callers
//! reference a circuit verification key, for example in a signed registry, without carrying the
//! key itself or depending on its internal structure.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Context, anyhow};
use digest::Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::halo2_ivc::keys::RecursiveCircuitVerifyingKey;
use crate::circuits::halo2_ivc::{
    KZGCommitmentScheme, NativeField, PairingEngine,
    RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, VerifyingKey,
};
use crate::hash::poseidon::MidnightPoseidonDigest;
use crate::proof_system::{NonDeterministicSnarkProverFactory, SnarkProverFactory};
use crate::{MithrilMembershipDigest, Parameters, StmError, StmResult, codec::TryFromBytes};

/// Byte length of a circuit verification key digest.
pub const CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE: usize = 32;

/// Poseidon digest of the transcript representation of a circuit verification key.
///
/// Serialized as a lowercase hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CircuitVerificationKeyDigest([u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE]);

impl CircuitVerificationKeyDigest {
    /// Compute the digest of a verifying key from its transcript representation.
    pub(crate) fn from_verification_key<
        K: AsRef<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>>,
    >(
        verification_key: &K,
    ) -> Self {
        Self::from_transcript_representation(verification_key.as_ref().transcript_repr())
    }

    /// Compute the digest of the transcript representation of a verifying key, a field element
    /// the Poseidon hasher absorbs as is.
    fn from_transcript_representation(transcript_representation: NativeField) -> Self {
        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(transcript_representation.to_bytes_le());
        Self(hasher.finalize().into())
    }

    /// Digest of the IVC circuit verification key.
    ///
    /// The IVC circuit does not depend on the protocol parameters, so its verification key is the
    /// embedded production constant for every deployment.
    pub fn for_ivc_circuit() -> StmResult<Self> {
        Ok(Self::from_verification_key(
            &RecursiveCircuitVerifyingKey::try_from_bytes(
                RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            )?,
        ))
    }

    /// Digest of the embedded certificate circuit verification key generated for the production
    /// protocol parameters.
    ///
    /// The certificate circuit depends on the protocol parameters, so this digest only covers
    /// deployments running with the production parameters.
    pub fn for_production_certificate_circuit() -> StmResult<Self> {
        Ok(Self::from_verification_key(
            &NonRecursiveCircuitVerifyingKey::try_from_bytes(
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            )?,
        ))
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

        Ok(Self::from_verification_key(prover.verifying_key()))
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
            CircuitVerificationKeyDigest::for_production_certificate_circuit().unwrap()
        );
        println!(
            "ivc-circuit: {}",
            CircuitVerificationKeyDigest::for_ivc_circuit().unwrap()
        );
    }

    #[test]
    fn digest_is_deterministic_and_separates_different_keys() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let certificate_key_digest =
            CircuitVerificationKeyDigest::from_verification_key(&context.certificate_verifying_key);
        let certificate_key_digest_again =
            CircuitVerificationKeyDigest::from_verification_key(&context.certificate_verifying_key);
        let recursive_key_digest =
            CircuitVerificationKeyDigest::from_verification_key(&context.recursive_verifying_key);

        assert_eq!(certificate_key_digest, certificate_key_digest_again);
        assert_ne!(certificate_key_digest, recursive_key_digest);
    }

    #[test]
    fn digest_is_poseidon_hash_of_the_verification_key_transcript_representation() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let digest =
            CircuitVerificationKeyDigest::from_verification_key(&context.certificate_verifying_key);

        let mut hasher = MidnightPoseidonDigest::new();
        hasher.update(
            context
                .certificate_verifying_key
                .as_ref()
                .transcript_repr()
                .to_bytes_le(),
        );
        let expected: [u8; CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE] = hasher.finalize().into();

        assert_eq!(&expected, digest.as_bytes());
    }

    #[test]
    fn digest_round_trips_through_hex_string() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let digest =
            CircuitVerificationKeyDigest::from_verification_key(&context.certificate_verifying_key);

        let hex_string = digest.to_string();
        let restored: CircuitVerificationKeyDigest = hex_string.parse().unwrap();

        assert_eq!(digest, restored);
    }

    #[test]
    fn digest_round_trips_through_serde_json() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let digest =
            CircuitVerificationKeyDigest::from_verification_key(&context.certificate_verifying_key);

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
        use super::*;

        #[test]
        fn golden_digest_of_fixed_transcript_representation() {
            let digest = CircuitVerificationKeyDigest::from_transcript_representation(
                NativeField::from(42u64),
            );

            assert_eq!(
                "ea21d013415b00dc1a74ea17cd305efc640a941fb3aa662a059923ea6aaece36",
                digest.to_string(),
                "golden circuit verification key digest changed for a fixed transcript representation, this alters the digest computation and breaks published circuit verification key registries"
            );
        }

        #[test]
        fn golden_digests_of_production_circuit_keys() {
            assert_eq!(
                "23109dde1bbcc5293159e1299434761221bc3131d4476ddf67155edccf06c219",
                CircuitVerificationKeyDigest::for_production_certificate_circuit()
                    .unwrap()
                    .to_string(),
                "golden production certificate circuit verification key digest changed, either the digest computation, the embedded production key or the certificate circuit changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "91e3fa784a720632b294f0becc2cbc1262274c6b36e2d2da1b716031751ec369",
                CircuitVerificationKeyDigest::for_ivc_circuit().unwrap().to_string(),
                "golden IVC circuit verification key digest changed, either the digest computation, the embedded production key or the IVC circuit changed, which breaks published circuit verification key registries"
            );
        }

        #[test]
        fn golden_digests_of_embedded_verification_context_keys() {
            let context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");

            let certificate_key_digest = CircuitVerificationKeyDigest::from_verification_key(
                &context.certificate_verifying_key,
            );
            let recursive_key_digest = CircuitVerificationKeyDigest::from_verification_key(
                &context.recursive_verifying_key,
            );

            assert_eq!(
                "ddbcb7ac2fc177e397166cc49314c73f9638787db6db90f287d3490451378159",
                certificate_key_digest.to_string(),
                "golden certificate circuit verification key digest changed, either the digest computation or the circuit changed, which breaks published circuit verification key registries"
            );
            assert_eq!(
                "af6087f9a37517c1024d67685b34f052bb534830a772f81117a85b75ae59b20a",
                recursive_key_digest.to_string(),
                "golden IVC circuit verification key digest changed, either the digest computation or the circuit changed, which breaks published circuit verification key registries"
            );
        }
    }
}
