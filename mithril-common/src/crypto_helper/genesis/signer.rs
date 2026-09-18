//! Wrapped genesis signer pairing the ed25519 Ed25519 signer with an optional
//! SNARK-friendly Schnorr signer.

use std::path::Path;

use anyhow::anyhow;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::StdResult;
use crate::crypto_helper::GenesisEd25519SecretKey;
use crate::crypto_helper::GenesisEd25519Signer;
use crate::crypto_helper::GenesisVerifier;
#[cfg(feature = "future_snark")]
use crate::crypto_helper::{
    BUNDLE_FIRST_HEX_CHAR, GenesisBundleError, GenesisSchnorrSigner, GenesisSigningKeyBundle,
    GenesisVerificationKeyBundle, LEGACY_FIRST_HEX_CHAR, PREIMAGE_SIZE, ProtocolKey, sha256_digest,
};
use crate::entities::{CertificateSignature, ProtocolMessage, SupportedEra};
use crate::protocol::ToMessage;

/// Wraps the two genesis signers and the bundle plumbing required by the offline ceremony.
#[derive(Debug, Clone)]
pub struct GenesisSigner {
    /// Ed25519-genesis signer (legacy Ed25519).
    pub ed25519: GenesisEd25519Signer,

    /// Schnorr-genesis signer (Schnorr over Jubjub). `None` when the operator loaded a legacy
    /// single-Ed25519 file.
    #[cfg(feature = "future_snark")]
    pub schnorr: Option<GenesisSchnorrSigner>,
}

impl GenesisSigner {
    /// Build a signer wrapper from the ed25519 half only.
    pub fn from_ed25519(ed25519: GenesisEd25519Signer) -> Self {
        Self {
            ed25519,
            #[cfg(feature = "future_snark")]
            schnorr: None,
        }
    }

    /// Build a fixed-seed deterministic signer wrapper for non-production use (devnet, tests).
    ///
    /// Both halves use their deterministic constructor so independently built signers and
    /// verifiers reproduce the same keys. Never use it for a long-lived genesis key.
    pub fn create_deterministic_signer() -> Self {
        Self {
            ed25519: GenesisEd25519Signer::create_deterministic_signer(),
            #[cfg(feature = "future_snark")]
            schnorr: Some(GenesisSchnorrSigner::create_deterministic_signer()),
        }
    }

    /// Build a signer wrapper from a dual signing-key bundle.
    #[cfg(feature = "future_snark")]
    pub fn from_bundle(bundle: GenesisSigningKeyBundle) -> Self {
        Self {
            ed25519: GenesisEd25519Signer::from_secret_key(bundle.ed25519),
            schnorr: Some(GenesisSchnorrSigner::from_secret_key(bundle.schnorr)),
        }
    }

    /// Build the matching [GenesisVerifier] for this signer, pairing each present half.
    pub fn create_verifier(&self) -> GenesisVerifier {
        GenesisVerifier {
            ed25519: self.ed25519.create_verifier(),
            #[cfg(feature = "future_snark")]
            schnorr: self.schnorr.as_ref().map(|schnorr| schnorr.create_verifier()),
        }
    }

    /// Parse a hex blob, preferring the dual signing-key bundle and falling back to the legacy
    /// single-Ed25519 JSON-hex format.
    pub fn try_from_hex(raw: &str) -> StdResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("genesis signer input is empty"));
        }
        #[cfg(feature = "future_snark")]
        {
            match trimmed.as_bytes().first() {
                Some(&BUNDLE_FIRST_HEX_CHAR) => {
                    let bundle = GenesisSigningKeyBundle::try_from_hex(trimmed)?;
                    Ok(Self::from_bundle(bundle))
                }
                Some(&LEGACY_FIRST_HEX_CHAR) => {
                    let secret_key = GenesisEd25519SecretKey::from_json_hex(trimmed)?;
                    Ok(Self::from_ed25519(GenesisEd25519Signer::from_secret_key(
                        secret_key,
                    )))
                }
                _ => Err(anyhow!(
                    "unrecognised genesis signing key format: expected dual bundle or legacy Ed25519 hex"
                )),
            }
        }
        #[cfg(not(feature = "future_snark"))]
        {
            let secret_key = GenesisEd25519SecretKey::from_json_hex(trimmed)?;
            Ok(Self::from_ed25519(GenesisEd25519Signer::from_secret_key(
                secret_key,
            )))
        }
    }

    /// Read [Self::try_from_hex] from disk.
    pub fn read_from_file(path: &Path) -> StdResult<Self> {
        let raw = std::fs::read_to_string(path)?;
        Self::try_from_hex(&raw)
    }

    /// Sign a genesis protocol message, producing the era-appropriate [CertificateSignature].
    ///
    /// Pythagoras yields a single Ed25519 signature; Lagrange yields a dual signature pairing the
    /// Ed25519 half with a SNARK-friendly Schnorr signature over the rigid preimage digest. The
    /// `rng` seeds the Schnorr per-signature nonce (unused under Pythagoras).
    pub fn sign<R: CryptoRng + RngCore>(
        &self,
        protocol_message: &ProtocolMessage,
        mithril_era: SupportedEra,
        #[cfg_attr(not(feature = "future_snark"), allow(unused_variables))] rng: &mut R,
    ) -> StdResult<CertificateSignature> {
        let ed25519_signature = self.ed25519.sign(protocol_message.to_message().as_bytes());
        match mithril_era {
            SupportedEra::Pythagoras => {
                Ok(CertificateSignature::GenesisSignature(ed25519_signature))
            }
            #[cfg(feature = "future_snark")]
            SupportedEra::Lagrange => {
                let schnorr_signer =
                    self.schnorr.as_ref().ok_or(GenesisBundleError::LegacySigningKey)?;
                if !protocol_message.is_rigid() {
                    return Err(anyhow!(
                        "Lagrange genesis signing requires a rigid protocol message"
                    ));
                }
                protocol_message.check_rigid_integrity()?;
                let preimage = protocol_message.rigid_preimage();
                if preimage.len() != PREIMAGE_SIZE {
                    return Err(anyhow!(
                        "rigid protocol-message preimage must be exactly {PREIMAGE_SIZE} bytes (got {})",
                        preimage.len()
                    ));
                }
                let schnorr_signature = schnorr_signer.sign(&sha256_digest(&preimage), rng)?;
                Ok(CertificateSignature::GenesisDualSignature(
                    ed25519_signature,
                    schnorr_signature,
                ))
            }
            #[cfg(not(feature = "future_snark"))]
            SupportedEra::Lagrange => Ok(CertificateSignature::GenesisSignature(ed25519_signature)),
        }
    }

    /// Sign with a fixed-seed deterministic RNG, for non-production use (devnet, tests).
    pub(crate) fn sign_deterministic(
        &self,
        protocol_message: &ProtocolMessage,
        mithril_era: SupportedEra,
    ) -> StdResult<CertificateSignature> {
        self.sign(
            protocol_message,
            mithril_era,
            &mut ChaCha20Rng::from_seed([0u8; 32]),
        )
    }

    /// Sign with the OS-backed CSPRNG ([rand_core::OsRng]).
    pub fn sign_non_deterministic(
        &self,
        protocol_message: &ProtocolMessage,
        mithril_era: SupportedEra,
    ) -> StdResult<CertificateSignature> {
        self.sign(protocol_message, mithril_era, &mut rand_core::OsRng)
    }

    /// Derive the matching dual verification-key bundle. Returns `None` for a legacy single-Ed25519
    /// signer, which has no Schnorr half to bundle.
    #[cfg(feature = "future_snark")]
    pub fn verification_key_bundle(&self) -> Option<GenesisVerificationKeyBundle> {
        self.schnorr.as_ref().map(|schnorr| GenesisVerificationKeyBundle {
            ed25519: self.ed25519.verification_key(),
            schnorr: schnorr.verification_key(),
        })
    }

    /// Write the wrapped signer to disk in its native hex form (bundle bytes-hex when the SNARK
    /// half is present, legacy JSON-hex otherwise).
    pub fn write_to_file(&self, path: &Path) -> StdResult<()> {
        #[cfg(feature = "future_snark")]
        {
            if let Some(schnorr) = self.schnorr.as_ref() {
                let bundle =
                    GenesisSigningKeyBundle::new(self.ed25519.secret_key(), schnorr.secret_key());
                let hex_string = ProtocolKey::new(bundle).to_bytes_hex()?;
                std::fs::write(path, hex_string)?;
                return Ok(());
            }
        }
        self.ed25519.secret_key().write_json_hex_to_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::temp_dir_create;

    #[test]
    fn try_from_hex_accepts_legacy_single_ed25519() {
        let signer = GenesisEd25519Signer::create_deterministic_signer();
        let legacy_hex = signer.secret_key().to_json_hex().unwrap();

        let parsed = GenesisSigner::try_from_hex(&legacy_hex).unwrap();

        assert_eq!(
            parsed.ed25519.secret_key().to_bytes(),
            signer.secret_key().to_bytes()
        );
        #[cfg(feature = "future_snark")]
        assert!(parsed.schnorr.is_none());
    }

    #[test]
    fn create_deterministic_signer_is_reproducible() {
        let first = GenesisSigner::create_deterministic_signer();
        let second = GenesisSigner::create_deterministic_signer();

        assert_eq!(
            first.ed25519.secret_key().to_bytes(),
            second.ed25519.secret_key().to_bytes()
        );
    }

    #[test]
    fn create_verifier_verifies_an_ed25519_signature() {
        let signer = GenesisSigner::create_deterministic_signer();
        let message = b"genesis-message";
        let signature = signer.ed25519.sign(message);

        signer
            .create_verifier()
            .verify_ed25519(message, &signature)
            .expect("the derived verifier must accept a signature from its signer");
    }

    #[test]
    fn try_from_hex_rejects_empty_input() {
        GenesisSigner::try_from_hex("   ").expect_err("empty input must be rejected");
    }

    #[test]
    fn read_from_file_round_trips_legacy() {
        let temp = temp_dir_create!();
        let signer = GenesisEd25519Signer::create_deterministic_signer();
        let path = temp.join("genesis.sk");
        signer.secret_key().write_json_hex_to_file(&path).unwrap();

        let restored = GenesisSigner::read_from_file(&path).unwrap();

        assert_eq!(
            restored.ed25519.secret_key().to_bytes(),
            signer.secret_key().to_bytes()
        );
    }

    #[cfg(feature = "future_snark")]
    mod schnorr {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::*;

        fn build_bundle() -> GenesisSigningKeyBundle {
            let ed25519 = GenesisEd25519Signer::create_deterministic_signer();
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let schnorr = GenesisSchnorrSigner::generate(&mut rng);
            GenesisSigningKeyBundle::new(ed25519.secret_key(), schnorr.secret_key())
        }

        #[test]
        fn sign_lagrange_rejects_a_non_rigid_protocol_message() {
            let signer = GenesisSigner::from_bundle(build_bundle());
            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

            let error = signer
                .sign(&ProtocolMessage::new(), SupportedEra::Lagrange, &mut rng)
                .expect_err("Lagrange signing must reject a non-rigid protocol message");

            assert!(error.to_string().contains("rigid protocol message"));
        }

        #[test]
        fn from_bundle_pairs_both_halves() {
            let bundle = build_bundle();
            let expected_ed25519 = bundle.ed25519.to_bytes();
            let expected_schnorr = bundle.schnorr.to_bytes();

            let signer = GenesisSigner::from_bundle(bundle);

            assert_eq!(signer.ed25519.secret_key().to_bytes(), expected_ed25519);
            assert_eq!(
                signer.schnorr.as_ref().unwrap().secret_key().to_bytes(),
                expected_schnorr
            );
        }

        #[test]
        fn try_from_hex_accepts_dual_bundle() {
            let bundle = build_bundle();
            let expected_schnorr = bundle.schnorr.to_bytes();
            let hex_string = ProtocolKey::new(bundle).to_bytes_hex().unwrap();

            let parsed = GenesisSigner::try_from_hex(&hex_string).unwrap();

            assert_eq!(
                parsed.schnorr.as_ref().unwrap().secret_key().to_bytes(),
                expected_schnorr
            );
        }

        #[test]
        fn verification_key_bundle_mirrors_signer_halves() {
            let signer = GenesisSigner::from_bundle(build_bundle());
            let expected_schnorr = signer.schnorr.as_ref().unwrap().verification_key().to_raw_bytes();

            let bundle = signer.verification_key_bundle().unwrap();

            assert_eq!(
                bundle.ed25519.as_bytes(),
                signer.ed25519.verification_key().as_bytes()
            );
            assert_eq!(bundle.schnorr.to_raw_bytes(), expected_schnorr);
        }

        #[test]
        fn write_to_file_round_trips_bundle() {
            let temp = temp_dir_create!();
            let signer = GenesisSigner::from_bundle(build_bundle());
            let path = temp.join("genesis.sk");

            signer.write_to_file(&path).unwrap();
            let restored = GenesisSigner::read_from_file(&path).unwrap();

            assert_eq!(
                restored.ed25519.secret_key().to_bytes(),
                signer.ed25519.secret_key().to_bytes()
            );
            assert_eq!(
                restored.schnorr.as_ref().unwrap().secret_key().to_bytes(),
                signer.schnorr.as_ref().unwrap().secret_key().to_bytes()
            );
        }
    }
}
