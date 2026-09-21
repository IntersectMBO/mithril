//! Schnorr cryptographic helpers (Schnorr over Jubjub).
//!
//! SNARK-friendly primitives provable inside the Halo2 IVC circuit. Mirrors the legacy
//! [ed25519](super::ed25519) family and is gated behind the `future_snark` feature so
//! non-SNARK builds compile unchanged.

use anyhow::{Context, anyhow};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use mithril_stm::{BaseFieldElement, SchnorrSigningKey, StandardSchnorrSignature};

use crate::{StdError, StdResult};

/// A protocol Schnorr Genesis verifier secret key
pub type SchnorrSecretKey = SchnorrSigningKey;
/// A protocol Schnorr Genesis verification key
pub type SchnorrVerificationKey = mithril_stm::SchnorrVerificationKey;
/// A protocol Schnorr Genesis signature (standard Schnorr signature over Jubjub)
pub type SchnorrSignature = StandardSchnorrSignature;

/// The exact byte size of the rigid protocol-message preimage signed under Lagrange.
///
/// Mirrors the in-circuit `PREIMAGE_SIZE` constant pinned by the IVC witness layout
/// in `mithril-stm/src/circuits/halo2_ivc/mod.rs`. The genesis signer enforces this invariant
/// before signing so layout drift surfaces at signing time, not deep inside the SNARK gadget.
pub const PREIMAGE_SIZE: usize = 190;

/// Errors raised by [SchnorrSigner] (signing) and [SchnorrVerifier]
/// (verification).
#[derive(Error, Debug)]
pub enum SchnorrError {
    /// SHA-256 digest passed to the signer or verifier is not exactly 32 bytes.
    #[error("SNARK genesis expected a 32-byte SHA-256 digest, got {actual} bytes")]
    InvalidDigestLength {
        /// Actual byte length of the digest received.
        actual: usize,
    },

    /// Reducing the SHA-256 digest into the Jubjub base field failed.
    #[error("SNARK genesis failed to reduce SHA-256 digest into the Jubjub base field")]
    FieldReduction(#[source] StdError),

    /// Producing a Schnorr signature over the digest failed.
    #[error("SNARK genesis signing failed")]
    Sign(#[source] StdError),

    /// Verifying a Schnorr signature against the digest failed.
    #[error("SNARK genesis verification failed")]
    Verify(#[source] StdError),
}

/// A SNARK-friendly signer responsible for signing the genesis attestation that is provable inside
/// the Halo2 IVC circuit.
///
/// The signer expects the SHA-256 digest of the protocol-message preimage (32 raw bytes). It feeds
/// the digest to the same `from_raw` reduction that the in-circuit `is_genesis_sig_valid` gadget
/// uses to recover the witness field element, so on-circuit and off-circuit verification share the
/// exact same message encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrSigner {
    secret_key: SchnorrSecretKey,
}

impl SchnorrSigner {
    /// Build a signer from a pre-generated [SchnorrSecretKey].
    pub fn from_secret_key(secret_key: SchnorrSecretKey) -> Self {
        Self { secret_key }
    }

    /// Generate a fresh signer from a [CryptoRng]/[RngCore] source.
    ///
    /// Callers MUST use [`rand_core::OsRng`] for any long-lived genesis key (see the
    /// `upgrade-key-to-dual` subcommand).
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self::from_secret_key(SchnorrSecretKey::generate(rng))
    }

    /// Generate a fixed-seed deterministic signer for non-production use (devnet, tests).
    ///
    /// Mirrors [`crate::crypto_helper::ed25519::Ed25519Signer::create_deterministic_signer`]: the fixed seed
    /// makes independently built signers reproduce the same key. Never use it for a long-lived
    /// genesis key.
    pub fn create_deterministic_signer() -> Self {
        Self::generate(&mut ChaCha20Rng::from_seed([0u8; 32]))
    }

    /// Generate a fresh signer using the OS-backed CSPRNG ([`rand_core::OsRng`]).
    ///
    /// Mirrors [`crate::crypto_helper::ed25519::Ed25519Signer::create_non_deterministic_signer`] so callers
    /// in security-critical paths (e.g. the genesis-key migration) do not need to reach for an
    /// RNG dependency themselves.
    pub fn create_non_deterministic_signer() -> Self {
        Self::generate(&mut rand_core::OsRng)
    }

    /// Get the underlying secret key.
    pub fn secret_key(&self) -> SchnorrSecretKey {
        self.secret_key.clone()
    }

    /// Get the [SchnorrVerificationKey] derived from this signer's secret.
    pub fn verification_key(&self) -> SchnorrVerificationKey {
        SchnorrVerificationKey::new_from_signing_key(self.secret_key.clone())
    }

    /// Sign a SHA-256 digest of the genesis protocol-message preimage.
    ///
    /// The slice must be exactly 32 bytes (the raw SHA-256 output). It is reduced into a single
    /// [BaseFieldElement] via [`BaseFieldElement::from_raw`], matching the encoding
    /// pinned by the IVC genesis-signature gadget.
    ///
    /// Visibility is `pub(crate)` so external callers cannot reach for a deterministic RNG:
    /// production code must use [`Self::sign_non_deterministic`] which threads
    /// [`rand_core::OsRng`]. The Schnorr scheme generates a per-signature nonce from this rng,
    /// and a predictable nonce leaks the secret key. Deterministic RNGs are only acceptable in
    /// tests, all of which live inside this crate.
    pub(crate) fn sign<R>(&self, sha256_digest: &[u8], rng: &mut R) -> StdResult<SchnorrSignature>
    where
        R: CryptoRng + RngCore,
    {
        let field_element = SchnorrVerifier::digest_to_field_element(sha256_digest)?;
        self.secret_key
            .sign_standard(&[field_element], rng)
            .map_err(|e| anyhow!(SchnorrError::Sign(e)))
            .with_context(|| "SNARK genesis signer failed to produce a standard Schnorr signature")
    }

    /// Sign a SHA-256 digest using the OS-backed CSPRNG ([`rand_core::OsRng`]).
    ///
    /// Mirrors [`Self::create_non_deterministic_signer`] so callers in security-critical paths
    /// do not need to reach for an RNG dependency themselves.
    pub fn sign_non_deterministic(&self, sha256_digest: &[u8]) -> StdResult<SchnorrSignature> {
        self.sign(sha256_digest, &mut rand_core::OsRng)
    }

    /// Build a [SchnorrVerifier] for this signer.
    pub fn create_verifier(&self) -> SchnorrVerifier {
        SchnorrVerifier::from_verification_key(self.verification_key())
    }
}

/// SNARK-friendly verifier for the genesis attestation (paired with [SchnorrSigner]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrVerifier {
    verification_key: SchnorrVerificationKey,
}

impl SchnorrVerifier {
    /// Build a verifier from a [SchnorrVerificationKey].
    pub fn from_verification_key(verification_key: SchnorrVerificationKey) -> Self {
        Self { verification_key }
    }

    /// Get the underlying verification key.
    pub fn to_verification_key(&self) -> SchnorrVerificationKey {
        self.verification_key
    }

    /// Verify a SNARK genesis signature against a SHA-256 digest of the protocol-message preimage.
    ///
    /// The slice must be exactly 32 bytes (the raw SHA-256 output), encoded into the field via the
    /// same reduction used by the signer.
    pub fn verify(&self, sha256_digest: &[u8], signature: &SchnorrSignature) -> StdResult<()> {
        let field_element = Self::digest_to_field_element(sha256_digest)?;
        signature
            .verify(&[field_element], &self.verification_key)
            .map_err(|e| anyhow!(SchnorrError::Verify(e)))
            .with_context(|| "SNARK genesis verifier failed to verify a standard Schnorr signature")
    }

    /// Convert a 32-byte SHA-256 digest into the [BaseFieldElement] the SNARK signer / verifier
    /// expect.
    ///
    /// Rejects inputs that are not exactly 32 bytes; otherwise the modulus reduction is
    /// deterministic on both sides.
    pub fn digest_to_field_element(sha256_digest: &[u8]) -> StdResult<BaseFieldElement> {
        if sha256_digest.len() != 32 {
            return Err(SchnorrError::InvalidDigestLength {
                actual: sha256_digest.len(),
            }
            .into());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(sha256_digest);
        BaseFieldElement::from_raw(&bytes)
            .map_err(|e| anyhow!(SchnorrError::FieldReduction(e)))
            .with_context(|| "Failed to reduce SHA-256 digest into the Jubjub base field")
    }
}

/// Hash an arbitrary message into the 32-byte SHA-256 digest the signer / verifier consume.
///
/// Centralized so producers and verifiers cannot drift on the digest computation.
pub fn sha256_digest(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

/// Compute the `signed_message` field for a Lagrange-era genesis certificate (hex of the rigid
/// preimage digest).
///
/// Centralized so the offline ceremony does not need to depend on the [`hex`] crate directly.
pub fn signed_message_from_digest(sha256_digest: &[u8]) -> String {
    hex::encode(sha256_digest)
}

/// Hex-encode a SNARK genesis signature (128 hex characters from the 64 raw bytes).
pub fn schnorr_signature_to_hex(signature: &SchnorrSignature) -> String {
    hex::encode(signature.to_raw_bytes())
}

/// Decode a hex-encoded SNARK genesis signature.
pub fn schnorr_signature_from_hex(raw: &str) -> StdResult<SchnorrSignature> {
    let bytes = hex::decode(raw).with_context(|| "Failed to hex-decode SNARK genesis signature")?;
    SchnorrSignature::from_raw_bytes(&bytes)
        .with_context(|| "Failed to deserialise SNARK genesis signature from bytes")
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn new_signer() -> SchnorrSigner {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        SchnorrSigner::generate(&mut rng)
    }

    #[test]
    fn sign_and_verify_a_random_digest() {
        let signer = new_signer();
        let verifier = signer.create_verifier();
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let digest = [123u8; 32];

        let signature = signer.sign(&digest, &mut rng).unwrap();

        verifier.verify(&digest, &signature).expect("Signature should verify");
    }

    #[test]
    fn schnorr_signature_from_hex_rejects_non_hex_input() {
        schnorr_signature_from_hex("not-hex").expect_err("a non-hex string must fail to decode");
    }

    #[test]
    fn schnorr_signature_from_hex_rejects_wrong_length() {
        let wrong_length = hex::encode([0u8; 16]);

        schnorr_signature_from_hex(&wrong_length)
            .expect_err("a wrong-length payload must fail to deserialise");
    }

    #[test]
    fn verification_fails_on_tampered_digest() {
        let signer = new_signer();
        let verifier = signer.create_verifier();
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let digest = [0xABu8; 32];

        let signature = signer.sign(&digest, &mut rng).unwrap();
        let mut tampered = digest;
        tampered[0] ^= 0xFF;

        verifier
            .verify(&tampered, &signature)
            .expect_err("Tampered digest should not verify");
    }

    #[test]
    fn signer_rejects_non_32_byte_input() {
        let signer = new_signer();
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        signer
            .sign(&[0u8; 16], &mut rng)
            .expect_err("Signer must reject digests that are not 32 bytes");
        signer
            .sign(&[0u8; 64], &mut rng)
            .expect_err("Signer must reject digests that are not 32 bytes");
    }

    #[test]
    fn digest_above_field_modulus_round_trips_deterministically() {
        let signer = new_signer();
        let verifier = signer.create_verifier();
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let high_bits_digest = [0xFFu8; 32];

        let signature = signer.sign(&high_bits_digest, &mut rng).unwrap();
        verifier
            .verify(&high_bits_digest, &signature)
            .expect("Digest above modulus must round-trip via reduction");
    }

    #[test]
    fn verification_key_matches_signer_secret() {
        let signer = new_signer();
        let derived = SchnorrVerificationKey::new_from_signing_key(signer.secret_key());

        assert_eq!(signer.verification_key(), derived);
    }

    #[test]
    fn sha256_digest_matches_direct_sha256() {
        let payload = b"genesis-preimage";

        assert_eq!(
            sha256_digest(payload),
            <[u8; 32]>::from(Sha256::digest(payload))
        );
    }

    #[test]
    fn two_signatures_of_same_digest_under_distinct_rngs_differ() {
        let signer = new_signer();
        let verifier = signer.create_verifier();
        let digest = [0x99u8; 32];

        let mut rng_a = ChaCha20Rng::from_seed([10u8; 32]);
        let mut rng_b = ChaCha20Rng::from_seed([11u8; 32]);
        let signature_a = signer.sign(&digest, &mut rng_a).unwrap();
        let signature_b = signer.sign(&digest, &mut rng_b).unwrap();

        verifier
            .verify(&digest, &signature_a)
            .expect("Signature A must verify");
        verifier
            .verify(&digest, &signature_b)
            .expect("Signature B must verify");
        assert_ne!(
            schnorr_signature_to_hex(&signature_a),
            schnorr_signature_to_hex(&signature_b),
            "Schnorr signatures of the same digest under distinct CSPRNG states must differ; \
             a collision here means the per-signature nonce is not actually random and the \
             secret key is at risk of algebraic recovery"
        );
    }

    #[test]
    fn two_sign_non_deterministic_invocations_produce_distinct_signatures() {
        let signer = new_signer();
        let verifier = signer.create_verifier();
        let digest = [0x55u8; 32];

        let signature_a = signer.sign_non_deterministic(&digest).unwrap();
        let signature_b = signer.sign_non_deterministic(&digest).unwrap();

        verifier
            .verify(&digest, &signature_a)
            .expect("OS-RNG signature A must verify");
        verifier
            .verify(&digest, &signature_b)
            .expect("OS-RNG signature B must verify");
        assert_ne!(
            schnorr_signature_to_hex(&signature_a),
            schnorr_signature_to_hex(&signature_b),
            "sign_non_deterministic must draw a fresh per-signature nonce from OsRng on each call"
        );
    }
}
