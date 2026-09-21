//! Wrapped genesis verifier pairing the ed25519 Ed25519 verifier with an optional
//! SNARK-friendly Schnorr verifier.

use std::path::Path;

use anyhow::anyhow;

use crate::StdResult;
#[cfg(feature = "future_snark")]
use crate::crypto_helper::{
    BUNDLE_FIRST_HEX_CHAR, GenesisSchnorrSignature, GenesisSchnorrVerificationKey,
    GenesisSchnorrVerifier, GenesisVerificationKeyBundle,
};
use crate::crypto_helper::{
    GenesisEd25519Signature, GenesisEd25519VerificationKey, GenesisEd25519Verifier, GenesisSigner,
};

/// First hex character of the legacy single-Ed25519 file (`5` from the JSON `[` array opener).
pub const LEGACY_FIRST_HEX_CHAR: u8 = b'5';

/// Wraps the two genesis verifiers required to verify a genesis certificate across legacy and
/// dual-signature eras. The optional Schnorr half carries the legacy/dual distinction: it is
/// `None` when the operator loaded a legacy single-Ed25519 verification key.
#[derive(Debug, Clone)]
pub struct GenesisVerifier {
    /// Ed25519-genesis verifier (legacy Ed25519).
    pub ed25519: GenesisEd25519Verifier,

    /// Schnorr-genesis verifier (Schnorr over Jubjub). `None` when the operator loaded a legacy
    /// single-Ed25519 verification key.
    #[cfg(feature = "future_snark")]
    pub schnorr: Option<GenesisSchnorrVerifier>,
}

impl GenesisVerifier {
    /// Build a verifier wrapper from the ed25519 half only.
    pub fn from_ed25519(verification_key: GenesisEd25519VerificationKey) -> Self {
        Self {
            ed25519: GenesisEd25519Verifier::from_verification_key(verification_key),
            #[cfg(feature = "future_snark")]
            schnorr: None,
        }
    }

    /// Build a fixed-seed deterministic verifier wrapper for non-production use (devnet, tests).
    ///
    /// Mirrors [`GenesisSigner::create_deterministic_signer`] and reproduces that signer's
    /// verification keys, so a deterministically signed genesis certificate verifies. Never use it
    /// for a long-lived genesis key.
    pub fn create_deterministic_verifier() -> Self {
        GenesisSigner::create_deterministic_signer().create_verifier()
    }

    /// Build a verifier wrapper from a dual verification-key bundle.
    #[cfg(feature = "future_snark")]
    pub fn from_bundle(bundle: GenesisVerificationKeyBundle) -> Self {
        Self {
            ed25519: GenesisEd25519Verifier::from_verification_key(bundle.ed25519),
            schnorr: Some(GenesisSchnorrVerifier::from_verification_key(
                bundle.schnorr,
            )),
        }
    }

    /// Parse a verification-key hex string, auto-detecting a dual bundle vs the legacy single-Ed25519
    /// file via the first hex character. Legacy inputs yield an ed25519-only verifier.
    pub fn try_from_hex(raw: &str) -> StdResult<Self> {
        let trimmed = raw.trim();
        match trimmed.as_bytes().first() {
            None => Err(anyhow!("genesis verification key input is empty")),
            #[cfg(feature = "future_snark")]
            Some(&BUNDLE_FIRST_HEX_CHAR) => Ok(Self::from_bundle(
                GenesisVerificationKeyBundle::try_from_hex(trimmed)?,
            )),
            Some(&LEGACY_FIRST_HEX_CHAR) => Ok(Self::from_ed25519(
                GenesisEd25519VerificationKey::try_from(trimmed)?,
            )),
            _ => Err(anyhow!(
                "unrecognised genesis verification key format: expected the legacy Ed25519-only file (first hex character `5`) or a dual-signature bundle (first hex character `0`, version 1)"
            )),
        }
    }

    /// Read [Self::try_from_hex] from disk.
    pub fn read_from_file(path: &Path) -> StdResult<Self> {
        let raw = std::fs::read_to_string(path)?;
        Self::try_from_hex(&raw)
    }

    /// Verify the ed25519 (Ed25519) signature carried by a genesis certificate.
    pub fn verify_ed25519(
        &self,
        message: &[u8],
        signature: &GenesisEd25519Signature,
    ) -> StdResult<()> {
        self.ed25519.verify(message, signature)
    }

    /// Verify the SNARK-friendly (Schnorr) signature carried by a dual genesis certificate against
    /// the SHA-256 digest of the protocol-message rigid preimage.
    ///
    /// Errors when the verifier holds no SNARK verification key (legacy single-Ed25519 input).
    #[cfg(feature = "future_snark")]
    pub fn verify_schnorr(
        &self,
        sha256_digest: &[u8],
        signature: &GenesisSchnorrSignature,
    ) -> StdResult<()> {
        self.schnorr
            .as_ref()
            .ok_or_else(|| anyhow!("the genesis verifier holds no SNARK verification key"))?
            .verify(sha256_digest, signature)
    }

    /// Return the ed25519 (Ed25519) verification key.
    pub fn to_ed25519_verification_key(&self) -> GenesisEd25519VerificationKey {
        self.ed25519.to_verification_key()
    }

    /// Return the SNARK-friendly (Schnorr) genesis verification key, absent for a legacy
    /// single-Ed25519 verifier.
    #[cfg(feature = "future_snark")]
    pub fn to_schnorr_verification_key(&self) -> Option<GenesisSchnorrVerificationKey> {
        self.schnorr.as_ref().map(|schnorr| schnorr.to_verification_key())
    }

    /// Derive the matching dual verification-key bundle, suitable for serialisation to disk by the
    /// genesis import and `upgrade-key-to-dual` aggregator subcommands. Returns `None` for a legacy
    /// single-Ed25519 verifier, which has no Schnorr half to bundle.
    #[cfg(feature = "future_snark")]
    pub fn verification_key_bundle(&self) -> Option<GenesisVerificationKeyBundle> {
        self.schnorr.as_ref().map(|schnorr| GenesisVerificationKeyBundle {
            ed25519: self.ed25519.to_verification_key(),
            schnorr: schnorr.to_verification_key(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_helper::GenesisEd25519Signer;
    #[cfg(feature = "future_snark")]
    use crate::crypto_helper::GenesisSchnorrSigner;
    use crate::temp_dir_create;

    fn deterministic_signer() -> GenesisEd25519Signer {
        GenesisEd25519Signer::create_deterministic_signer()
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn verify_schnorr_errors_when_verifier_holds_no_schnorr_key() {
        let signer = deterministic_signer();
        let verifier = GenesisVerifier::from_ed25519(signer.verification_key());
        let schnorr_signature = GenesisSchnorrSigner::create_non_deterministic_signer()
            .sign_non_deterministic(&[0u8; 32])
            .unwrap();

        verifier
            .verify_schnorr(&[0u8; 32], &schnorr_signature)
            .expect_err("verify_schnorr must error when the verifier holds no SNARK key");
    }

    #[test]
    fn from_ed25519_yields_no_schnorr_half() {
        let signer = deterministic_signer();
        let verifier = GenesisVerifier::from_ed25519(signer.verification_key());

        assert_eq!(
            verifier.ed25519.to_verification_key().as_bytes(),
            signer.verification_key().as_bytes()
        );
        #[cfg(feature = "future_snark")]
        assert!(verifier.schnorr.is_none());
    }

    #[test]
    fn try_from_hex_accepts_legacy_single_ed25519() {
        let signer = deterministic_signer();
        let legacy_hex = signer.verification_key().to_json_hex().unwrap();

        let verifier = GenesisVerifier::try_from_hex(&legacy_hex).unwrap();

        assert_eq!(
            verifier.ed25519.to_verification_key().as_bytes(),
            signer.verification_key().as_bytes()
        );
        #[cfg(feature = "future_snark")]
        assert!(verifier.schnorr.is_none());
    }

    #[test]
    fn try_from_hex_rejects_empty_input() {
        GenesisVerifier::try_from_hex("   ").expect_err("empty input must be rejected");
    }

    #[test]
    fn try_from_hex_rejects_unrecognised_format() {
        GenesisVerifier::try_from_hex("abc").expect_err("unrecognised format must be rejected");
    }

    #[test]
    fn read_from_file_round_trips_legacy() {
        let temp = temp_dir_create!();
        let signer = deterministic_signer();
        let path = temp.join("genesis.vk");
        signer.verification_key().write_json_hex_to_file(&path).unwrap();

        let verifier = GenesisVerifier::read_from_file(&path).unwrap();

        assert_eq!(
            verifier.ed25519.to_verification_key().as_bytes(),
            signer.verification_key().as_bytes()
        );
    }

    #[test]
    fn verify_ed25519_accepts_valid_signature() {
        let signer = deterministic_signer();
        let message = b"genesis-message";
        let signature = signer.sign(message);
        let verifier = GenesisVerifier::from_ed25519(signer.verification_key());

        verifier
            .verify_ed25519(message, &signature)
            .expect("valid signature must verify");
    }

    #[test]
    fn verify_ed25519_rejects_tampered_message() {
        let signer = deterministic_signer();
        let signature = signer.sign(b"genesis-message");
        let verifier = GenesisVerifier::from_ed25519(signer.verification_key());

        verifier
            .verify_ed25519(b"tampered-message", &signature)
            .expect_err("tampered message must be rejected");
    }

    #[cfg(feature = "future_snark")]
    mod schnorr {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::*;

        fn build_bundle() -> GenesisVerificationKeyBundle {
            let ed25519 = deterministic_signer().verification_key();
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let schnorr = GenesisSchnorrSigner::generate(&mut rng).verification_key();
            GenesisVerificationKeyBundle::new(ed25519, schnorr)
        }

        #[test]
        fn from_bundle_pairs_both_halves() {
            let bundle = build_bundle();
            let expected_ed25519 = bundle.ed25519.as_bytes().to_vec();
            let expected_schnorr = bundle.schnorr.to_raw_bytes();

            let verifier = GenesisVerifier::from_bundle(bundle);

            assert_eq!(
                verifier.ed25519.to_verification_key().as_bytes(),
                expected_ed25519.as_slice()
            );
            assert_eq!(
                verifier
                    .schnorr
                    .as_ref()
                    .unwrap()
                    .to_verification_key()
                    .to_raw_bytes(),
                expected_schnorr
            );
        }

        #[test]
        fn try_from_hex_accepts_dual_bundle() {
            let bundle = build_bundle();
            let expected_schnorr = bundle.schnorr.to_raw_bytes();
            let hex_string = crate::crypto_helper::ProtocolKey::new(bundle).to_bytes_hex().unwrap();

            let verifier = GenesisVerifier::try_from_hex(&hex_string).unwrap();

            assert_eq!(
                verifier
                    .schnorr
                    .as_ref()
                    .unwrap()
                    .to_verification_key()
                    .to_raw_bytes(),
                expected_schnorr
            );
        }

        #[test]
        fn verify_schnorr_accepts_valid_signature() {
            let ed25519 = deterministic_signer().verification_key();
            let schnorr_signer = GenesisSchnorrSigner::create_deterministic_signer();
            let bundle =
                GenesisVerificationKeyBundle::new(ed25519, schnorr_signer.verification_key());
            let verifier = GenesisVerifier::from_bundle(bundle);
            let digest = [123u8; 32];
            let signature = schnorr_signer.sign_non_deterministic(&digest).unwrap();

            verifier
                .verify_schnorr(&digest, &signature)
                .expect("a valid SNARK signature must verify through the wrapper");
        }

        #[test]
        fn verification_key_bundle_mirrors_verifier_halves() {
            let verifier = GenesisVerifier::from_bundle(build_bundle());
            let expected_schnorr = verifier
                .schnorr
                .as_ref()
                .unwrap()
                .to_verification_key()
                .to_raw_bytes();

            let bundle = verifier.verification_key_bundle().unwrap();

            assert_eq!(
                bundle.ed25519.as_bytes(),
                verifier.ed25519.to_verification_key().as_bytes()
            );
            assert_eq!(bundle.schnorr.to_raw_bytes(), expected_schnorr);
        }

        #[test]
        fn to_schnorr_verification_key_returns_the_schnorr_half_for_a_dual_verifier() {
            let bundle = build_bundle();
            let expected_schnorr = bundle.schnorr.to_raw_bytes();

            let verifier = GenesisVerifier::from_bundle(bundle);

            assert_eq!(
                verifier.to_schnorr_verification_key().unwrap().to_raw_bytes(),
                expected_schnorr
            );
        }

        #[test]
        fn to_schnorr_verification_key_is_none_for_a_legacy_verifier() {
            let verifier = GenesisVerifier::from_ed25519(deterministic_signer().verification_key());

            assert!(verifier.to_schnorr_verification_key().is_none());
        }
    }
}
