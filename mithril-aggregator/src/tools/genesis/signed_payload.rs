//! Versioned envelope carrying the dual genesis signature (Ed25519 + Schnorr) produced by the
//! offline sign ceremony under the Lagrange era.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mithril_common::StdResult;
use mithril_common::crypto_helper::{GenesisEd25519Signature, GenesisSchnorrSignature};

/// Current envelope version.
pub const GENESIS_SIGNED_PAYLOAD_VERSION: u8 = 1;

/// Errors raised when parsing a dual genesis signed payload.
#[derive(Error, Debug)]
pub enum GenesisSignedPayloadError {
    /// The envelope is empty and carries no version byte.
    #[error("empty genesis signed payload")]
    Empty,

    /// The envelope declares a version other than [GENESIS_SIGNED_PAYLOAD_VERSION].
    #[error("unsupported genesis signed payload version: {version} (only version 1 is supported)")]
    UnsupportedVersion {
        /// Version byte read from the envelope.
        version: u8,
    },
}

/// Dual genesis signed payload: a legacy Ed25519 signature paired with a SNARK-friendly Schnorr
/// signature.
///
/// Serialised as a single version byte followed by the CBOR encoding of the two signatures, so the
/// envelope can evolve without a hand-written byte parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisSignedPayload {
    /// Ed25519 signature produced by the ed25519 signer.
    pub ed25519: GenesisEd25519Signature,

    /// Schnorr signature produced by the SNARK signer.
    pub schnorr: GenesisSchnorrSignature,
}

impl GenesisSignedPayload {
    /// Build a fresh envelope from the two signatures.
    pub fn new(ed25519: GenesisEd25519Signature, schnorr: GenesisSchnorrSignature) -> Self {
        Self { ed25519, schnorr }
    }

    /// Encode the envelope as a version-prefixed CBOR payload.
    pub fn to_bytes(&self) -> StdResult<Vec<u8>> {
        let mut bytes = vec![GENESIS_SIGNED_PAYLOAD_VERSION];
        ciborium::ser::into_writer(self, &mut bytes)
            .with_context(|| "Failed to encode genesis signed payload to CBOR")?;
        Ok(bytes)
    }

    /// Decode a version-prefixed CBOR envelope.
    pub fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
        let (version, payload) = bytes.split_first().ok_or(GenesisSignedPayloadError::Empty)?;
        if *version != GENESIS_SIGNED_PAYLOAD_VERSION {
            return Err(GenesisSignedPayloadError::UnsupportedVersion { version: *version }.into());
        }

        ciborium::de::from_reader(payload)
            .with_context(|| "Failed to decode genesis signed payload from CBOR")
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSchnorrSigner};

    use super::*;

    fn deterministic_payload() -> GenesisSignedPayload {
        let ed_signer = GenesisEd25519Signer::create_deterministic_signer();
        let ed25519 = ed_signer.sign(b"genesis-signed-message");

        let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
        let schnorr = schnorr_signer.sign_non_deterministic(&[0x42u8; 32]).unwrap();

        GenesisSignedPayload::new(ed25519, schnorr)
    }

    #[test]
    fn round_trips_through_bytes() {
        let payload = deterministic_payload();
        let bytes = payload.to_bytes().unwrap();

        assert_eq!(bytes[0], GENESIS_SIGNED_PAYLOAD_VERSION);

        let restored = GenesisSignedPayload::try_from_bytes(&bytes).unwrap();

        assert_eq!(restored.ed25519.to_bytes(), payload.ed25519.to_bytes());
        assert_eq!(
            restored.schnorr.to_raw_bytes(),
            payload.schnorr.to_raw_bytes()
        );
    }

    #[test]
    fn rejects_empty_payload() {
        let error = GenesisSignedPayload::try_from_bytes(&[]).unwrap_err();

        assert!(matches!(
            error.downcast_ref::<GenesisSignedPayloadError>(),
            Some(GenesisSignedPayloadError::Empty)
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = deterministic_payload().to_bytes().unwrap();
        bytes[0] = 2;

        let error = GenesisSignedPayload::try_from_bytes(&bytes).unwrap_err();

        assert!(matches!(
            error.downcast_ref::<GenesisSignedPayloadError>(),
            Some(GenesisSignedPayloadError::UnsupportedVersion { version: 2 })
        ));
    }

    #[test]
    fn rejects_corrupted_cbor_body() {
        let bytes = deterministic_payload().to_bytes().unwrap();
        let truncated = &bytes[..bytes.len() - 1];

        GenesisSignedPayload::try_from_bytes(truncated).unwrap_err();
    }

    mod golden {
        use super::*;

        const GOLDEN_MESSAGE: &[u8] = b"genesis-signed-message";

        const GOLDEN_ED25519_HEX: &str = "1191eb0dcad9ad33b5f7b4af635090caa35413d24ff714c828d91d616665541d108b104a594a04c59b8b097aba6a74b900eb082f527d656681fca4e708cc2d08";

        const GOLDEN_SCHNORR_HEX: &str = "35b28d59bd557a7a2d8ae3c72683d4b6e77aa1d5d978c515b3fe3bb42466a20cc4837e0dd0861abae347b0aa7b56477cd9368b3a351c3f60623698d2f4ab5e68";

        const GOLDEN_BYTES: &[u8; 297] = &[
            1, 162, 103, 101, 100, 50, 53, 53, 49, 57, 120, 128, 49, 49, 57, 49, 101, 98, 48, 100,
            99, 97, 100, 57, 97, 100, 51, 51, 98, 53, 102, 55, 98, 52, 97, 102, 54, 51, 53, 48, 57,
            48, 99, 97, 97, 51, 53, 52, 49, 51, 100, 50, 52, 102, 102, 55, 49, 52, 99, 56, 50, 56,
            100, 57, 49, 100, 54, 49, 54, 54, 54, 53, 53, 52, 49, 100, 49, 48, 56, 98, 49, 48, 52,
            97, 53, 57, 52, 97, 48, 52, 99, 53, 57, 98, 56, 98, 48, 57, 55, 97, 98, 97, 54, 97, 55,
            52, 98, 57, 48, 48, 101, 98, 48, 56, 50, 102, 53, 50, 55, 100, 54, 53, 54, 54, 56, 49,
            102, 99, 97, 52, 101, 55, 48, 56, 99, 99, 50, 100, 48, 56, 103, 115, 99, 104, 110, 111,
            114, 114, 162, 104, 114, 101, 115, 112, 111, 110, 115, 101, 152, 32, 24, 53, 24, 178,
            24, 141, 24, 89, 24, 189, 24, 85, 24, 122, 24, 122, 24, 45, 24, 138, 24, 227, 24, 199,
            24, 38, 24, 131, 24, 212, 24, 182, 24, 231, 24, 122, 24, 161, 24, 213, 24, 217, 24,
            120, 24, 197, 21, 24, 179, 24, 254, 24, 59, 24, 180, 24, 36, 24, 102, 24, 162, 12, 105,
            99, 104, 97, 108, 108, 101, 110, 103, 101, 152, 32, 24, 196, 24, 131, 24, 126, 13, 24,
            208, 24, 134, 24, 26, 24, 186, 24, 227, 24, 71, 24, 176, 24, 170, 24, 123, 24, 86, 24,
            71, 24, 124, 24, 217, 24, 54, 24, 139, 24, 58, 24, 53, 24, 28, 24, 63, 24, 96, 24, 98,
            24, 54, 24, 152, 24, 210, 24, 244, 24, 171, 24, 94, 24, 104,
        ];

        #[test]
        fn golden_bytes_decode_to_expected_signatures() {
            let payload = GenesisSignedPayload::try_from_bytes(GOLDEN_BYTES)
                .expect("Golden genesis signed payload should decode");

            assert_eq!(GOLDEN_ED25519_HEX, hex::encode(payload.ed25519.to_bytes()));
            assert_eq!(
                GOLDEN_SCHNORR_HEX,
                hex::encode(payload.schnorr.to_raw_bytes())
            );
        }

        #[test]
        fn golden_encoding_is_stable() {
            let payload = GenesisSignedPayload::try_from_bytes(GOLDEN_BYTES)
                .expect("Golden genesis signed payload should decode");
            let reencoded = payload.to_bytes().expect("Golden payload should re-encode");

            assert_eq!(GOLDEN_BYTES.as_slice(), reencoded.as_slice());
        }

        #[test]
        fn golden_ed25519_signature_is_reproducible() {
            let ed25519 = GenesisEd25519Signer::create_deterministic_signer().sign(GOLDEN_MESSAGE);

            assert_eq!(GOLDEN_ED25519_HEX, hex::encode(ed25519.to_bytes()));
        }
    }
}
