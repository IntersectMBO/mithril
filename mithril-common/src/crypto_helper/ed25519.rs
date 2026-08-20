//! Ed25519 cryptographic helpers

use anyhow::anyhow;
use ed25519_dalek::rand_core::{CryptoRng, UnwrapErr};
use ed25519_dalek::{Signer, SigningKey};
use getrandom::SysRng;
use rand_chacha_ed25519::{ChaCha20Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{StdError, StdResult};

use super::ProtocolKey;

/// Wrapper of [Ed25519:PublicKey](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html).
pub type Ed25519VerificationKey = ProtocolKey<ed25519_dalek::VerifyingKey>;

/// Wrapper of [Ed25519:SigningKey](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.SigningKey.html).
pub type Ed25519SecretKey = ProtocolKey<ed25519_dalek::SigningKey>;

/// Wrapper of [Ed25519:Signature](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.Signature.html).
pub type Ed25519Signature = ProtocolKey<ed25519_dalek::Signature>;

#[derive(Error, Debug)]
/// [Ed25519Signer] and [Ed25519Verifier] related errors.
#[error("Ed25519 signature verification error")]
pub struct Ed25519VerifierError(#[source] StdError);

/// A cryptographic signer that is responsible for signing messages using Ed25519 signature scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Signer {
    pub(crate) secret_key: Ed25519SecretKey,
}

impl Ed25519Signer {
    /// [Ed25519Signer] factory
    pub fn create_test_signer<R>(mut rng: R) -> Self
    where
        R: CryptoRng,
    {
        let secret_key = SigningKey::generate(&mut rng);
        Self::from_secret_key(secret_key.into())
    }

    /// [Ed25519Signer] deterministic
    pub fn create_deterministic_signer() -> Self {
        let rng = ChaCha20Rng::from_seed([0u8; 32]);
        Self::create_test_signer(rng)
    }

    /// [Ed25519Signer] non deterministic
    pub fn create_non_deterministic_signer() -> Self {
        // `rand_core`'s `OsRng` was removed and replaced by `getrandom::SysRng`. `OsRng` was
        // a wrapper around `getrandom` internally so the functionality does not change.
        // `SysRng` reads from the same OS entropy sources as before (e.g. the `getrandom`
        // syscall on Linux, `ProcessPrng` on Windows, `getentropy` on macOS) under
        // the same documented security guarantee.
        //
        // `SysRng` only implements the fallible `TryRng`/`TryCryptoRng` (an OS entropy call can,
        // in principle, fail). `UnwrapErr` makes `SysRng` Infallible to fit the `generate` bounds.
        // It can panic on failure in the same way `OsRng` did so the chance of failure stays the
        // same.
        let rng = UnwrapErr(SysRng);
        Self::create_test_signer(rng)
    }

    /// Get the [Ed25519SecretKey]
    pub fn secret_key(&self) -> Ed25519SecretKey {
        self.secret_key.clone()
    }

    /// Get the [Ed25519VerificationKey]
    pub fn verification_key(&self) -> Ed25519VerificationKey {
        self.secret_key.verifying_key().into()
    }

    /// [Ed25519Signer] from [Ed25519SecretKey]
    pub fn from_secret_key(secret_key: Ed25519SecretKey) -> Self {
        Self { secret_key }
    }

    /// Create a [Ed25519Verifier]
    pub fn create_verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier::from_verification_key(self.secret_key.verifying_key().into())
    }

    /// Signs a message and returns a [Ed25519Signature]
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(message).into()
    }
}

/// Ed25519 verifier that checks the authenticity of Ed25519 signatures
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ed25519Verifier {
    pub(crate) verification_key: Ed25519VerificationKey,
}

impl Ed25519Verifier {
    /// [Ed25519Verifier] from [Ed25519VerificationKey]
    pub fn from_verification_key(verification_key: Ed25519VerificationKey) -> Self {
        Self { verification_key }
    }

    /// [Ed25519Verifier] to [Ed25519VerificationKey]
    pub fn to_verification_key(&self) -> Ed25519VerificationKey {
        self.verification_key
    }

    /// Verifies the signature of a message
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> StdResult<()> {
        self.verification_key.verify(message, signature)
    }
}

impl Ed25519VerificationKey {
    /// Verifies the signature of a message
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> StdResult<()> {
        Ok(self
            .verify_strict(message, signature)
            .map_err(|e| Ed25519VerifierError(anyhow!(e)))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_ED25519_VERIFICATION_KEY: &str = "5b32332c32372c3131322c362c35372c38342c3138302c342c3135302c3233322c3233372c3132362c3131392c\
        3231342c33352c35342c38312c3230382c3231372c39392c3137302c3233312c3133392c362c3132322c39342c3\
        9322c3137322c32332c3130322c3135372c3136375d";
    const GOLDEN_ED25519_SECRET_KEY: &str = "5b34332c3133322c3232312c3138382c3235332c3132372c3235352c38362c3136322c3133312c3233332c3131\
        362c3134322c3233352c3131312c3133332c3134312c3138332c302c33392c3132302c3139372c39322c3133302\
        c3233342c34362c3135372c32352c3133322c31352c3234312c3235345d";

    #[test]
    fn golden_master() {
        Ed25519VerificationKey::from_json_hex(GOLDEN_ED25519_VERIFICATION_KEY)
            .expect("Decoding golden verification key should not fail");

        Ed25519SecretKey::from_json_hex(GOLDEN_ED25519_SECRET_KEY)
            .expect("Decoding golden secret key should not fail");
    }

    #[test]
    fn test_generate_test_deterministic_keypair() {
        let signer = Ed25519Signer::create_deterministic_signer();
        let verifier = signer.create_verifier();
        let signer_2 = Ed25519Signer::create_deterministic_signer();
        let verifier_2 = signer.create_verifier();
        assert_eq!(signer.secret_key.to_bytes(), signer_2.secret_key.to_bytes());
        assert_eq!(
            verifier.verification_key.as_bytes(),
            verifier_2.verification_key.as_bytes()
        );

        println!(
            "Deterministic Verification Key={}",
            verifier.verification_key.to_json_hex().unwrap()
        );
        println!(
            "Deterministic Secret Key=={}",
            signer.secret_key.to_json_hex().unwrap()
        );
    }

    #[test]
    fn test_generate_test_non_deterministic_keypair() {
        let signer = Ed25519Signer::create_non_deterministic_signer();
        let verifier = signer.create_verifier();

        println!(
            "Non Deterministic Verification Key={}",
            verifier.verification_key.to_json_hex().unwrap()
        );
        println!(
            "Non Deterministic Secret Key=={}",
            signer.secret_key.to_json_hex().unwrap()
        );
    }

    #[test]
    fn test_codec_keypair() {
        let signer = Ed25519Signer::create_deterministic_signer();
        let verifier = signer.create_verifier();
        let secret_key_encoded = signer.secret_key.to_json_hex().unwrap();
        let verification_key_encoded = verifier.verification_key.to_json_hex().unwrap();
        let secret_key_decoded: Ed25519SecretKey = secret_key_encoded.try_into().unwrap();
        let verification_key_decoded: Ed25519VerificationKey =
            verification_key_encoded.try_into().unwrap();
        let signer_decoded = Ed25519Signer::from_secret_key(secret_key_decoded);
        let verifier_decoded = Ed25519Verifier::from_verification_key(verification_key_decoded);

        let message: &[u8] = b"some message.";
        let signature = signer_decoded.sign(message);
        let verify_signature = verifier_decoded.verify(message, &signature);
        assert!(
            verify_signature.is_ok(),
            "signature verification should not fail"
        );
    }
}
