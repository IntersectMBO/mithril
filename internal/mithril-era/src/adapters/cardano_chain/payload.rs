use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mithril_common::crypto_helper::{
    EraMarkersSigner, EraMarkersVerifier, EraMarkersVerifierSignature,
    EraMarkersVerifierVerificationKey, key_decode_hex, key_encode_hex,
};
use mithril_common::{StdError, StdResult};

use crate::EraMarker;

/// Era markers payloads related errors.
#[derive(Debug, Error)]
pub enum EraMarkersPayloadError {
    /// Error raised when the message serialization fails
    #[error("could not serialize message")]
    SerializeMessage(#[source] StdError),

    /// Error raised when the signature deserialization fails
    #[error("could not deserialize signature")]
    DeserializeSignature(#[source] StdError),

    /// Error raised when the signature is missing
    #[error("could not verify signature: signature is missing")]
    MissingSignature,

    /// Error raised when the signature is invalid
    #[error("could not verify signature")]
    VerifySignature(#[source] StdError),

    /// Error raised when the signing the markers
    #[error("could not create signature")]
    CreateSignature(#[source] StdError),
}

/// Era markers payload
///
/// The signature covers the markers and the sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EraMarkersPayload {
    /// List of Era markers
    pub markers: Vec<EraMarker>,

    /// Sequence number of the era markers, incremented at each publication
    pub sequence_number: u64,

    /// Era markers signature
    pub signature: Option<EraMarkersVerifierSignature>,
}

impl EraMarkersPayload {
    fn message_to_bytes(&self) -> Result<Vec<u8>, EraMarkersPayloadError> {
        serde_json::to_vec(&EraMarkersSignedMessage {
            markers: self.markers.clone(),
            sequence_number: self.sequence_number,
        })
        .map_err(|e| EraMarkersPayloadError::SerializeMessage(e.into()))
    }

    /// Encode this payload to a json hex string
    pub fn to_json_hex(&self) -> StdResult<String> {
        key_encode_hex(self).with_context(|| "era markers payload could not be json hex encoded")
    }

    /// Decode a [EraMarkersPayload] from a json hex string
    pub fn from_json_hex(payload: &str) -> StdResult<Self> {
        key_decode_hex(payload)
            .with_context(|| "era markers payload could not be decoded from json hex")
    }

    /// Verify the signature of an era markers payload
    pub fn verify_signature(
        &self,
        verification_key: EraMarkersVerifierVerificationKey,
    ) -> Result<(), EraMarkersPayloadError> {
        EraMarkersSignature::verify(&self.message_to_bytes()?, self.signature, verification_key)
    }

    /// Sign an era markers payload
    pub fn sign(self, signer: &EraMarkersSigner) -> Result<Self, EraMarkersPayloadError> {
        let signature = signer.sign(
            &self
                .message_to_bytes()
                .map_err(|e| EraMarkersPayloadError::CreateSignature(e.into()))?,
        );

        Ok(Self {
            signature: Some(signature),
            ..self
        })
    }
}

/// Message signed in an [EraMarkersPayload]
#[derive(Serialize)]
struct EraMarkersSignedMessage {
    /// List of Era markers
    markers: Vec<EraMarker>,

    /// Sequence number of the era markers
    sequence_number: u64,
}

/// Signature of the message of an era markers payload
pub(super) struct EraMarkersSignature;

impl EraMarkersSignature {
    /// Verify the signature of the bytes of a signed message
    pub(super) fn verify(
        message: &[u8],
        signature: Option<EraMarkersVerifierSignature>,
        verification_key: EraMarkersVerifierVerificationKey,
    ) -> Result<(), EraMarkersPayloadError> {
        let signature = signature.ok_or(EraMarkersPayloadError::MissingSignature)?;
        let markers_verifier: EraMarkersVerifier =
            EraMarkersVerifier::from_verification_key(verification_key);

        markers_verifier
            .verify(message, &signature)
            .with_context(|| "era markers payload could not verify signature")
            .map_err(EraMarkersPayloadError::VerifySignature)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{pythagoras_markers, sequenced_payload, thales_markers};
    use super::*;

    const GOLDEN_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE: &str = "7b226d61726b657273223a5b7b226e616d65223a227468616c6573222c2265706f6368223a317d2c7b226e616d65\
        223a227079746861676f726173222c2265706f6368223a327d5d2c2273657175656e63655f6e756d626572223a33\
        2c227369676e6174757265223a223866386366336237623031346432353532653864663737666366306334306338\
        38623638306336363138326231643332386238316232333261386364316466613438613630333266626435623231\
        35633033346638626138326631383538323239633461613162636132613563323031303066343538356330303466\
        66623062227d";

    #[test]
    fn golden_markers_payload_with_signature() {
        let payload = EraMarkersPayload::from_json_hex(GOLDEN_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE)
            .expect("Decoding golden markers payload should not fail");

        assert_eq!(pythagoras_markers(Some(2)), payload.markers);
        assert_eq!(3, payload.sequence_number);
        payload
            .verify_signature(
                EraMarkersSigner::create_deterministic_signer()
                    .create_verifier()
                    .to_verification_key(),
            )
            .expect("Golden markers payload signature should be valid");
    }

    #[test]
    fn markers_payload_signature_is_valid_for_its_verification_key_only() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let payload = sequenced_payload(&thales_markers(), 1, &era_markers_signer);

        payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect("Signature should be valid");
        let error = payload
            .verify_signature(
                EraMarkersSigner::create_non_deterministic_signer()
                    .create_verifier()
                    .to_verification_key(),
            )
            .expect_err("Signature should be invalid for another key");
        assert!(matches!(error, EraMarkersPayloadError::VerifySignature(_)));
    }

    #[test]
    fn markers_payload_signature_is_invalid_when_the_sequence_number_changes() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let payload = EraMarkersPayload {
            sequence_number: 2,
            ..sequenced_payload(&thales_markers(), 1, &era_markers_signer)
        };

        let error = payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect_err("Signature should be invalid");

        assert!(matches!(error, EraMarkersPayloadError::VerifySignature(_)));
    }

    #[test]
    fn markers_payload_without_signature_is_not_verified() {
        let payload = EraMarkersPayload {
            markers: thales_markers(),
            sequence_number: 1,
            signature: None,
        };

        let error = payload
            .verify_signature(
                EraMarkersSigner::create_deterministic_signer()
                    .create_verifier()
                    .to_verification_key(),
            )
            .expect_err("Missing signature should be rejected");

        assert!(matches!(error, EraMarkersPayloadError::MissingSignature));
    }
}
