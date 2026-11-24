use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mithril_common::crypto_helper::{
    EraMarkersSigner, EraMarkersVerifier, EraMarkersVerifierSignature,
    EraMarkersVerifierVerificationKey, key_decode_hex, key_encode_hex,
};
use mithril_common::{StdError, StdResult};

use crate::EraMarker;

/// [EraMarkersPayload] related errors.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EraMarkersPayload {
    /// List of Era markers
    pub markers: Vec<EraMarker>,

    /// Era markers signature
    pub signature: Option<EraMarkersVerifierSignature>,
}

impl EraMarkersPayload {
    fn message_to_bytes(&self) -> Result<Vec<u8>, EraMarkersPayloadError> {
        serde_json::to_vec(&self.markers)
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

    /// Verify the signature an era markers payload
    pub fn verify_signature(
        &self,
        verification_key: EraMarkersVerifierVerificationKey,
    ) -> Result<(), EraMarkersPayloadError> {
        let signature = self.signature.ok_or(EraMarkersPayloadError::MissingSignature)?;
        let markers_verifier: EraMarkersVerifier =
            EraMarkersVerifier::from_verification_key(verification_key);

        markers_verifier
            .verify(&self.message_to_bytes()?, &signature)
            .with_context(|| "era markers payload could not verify signature")
            .map_err(EraMarkersPayloadError::VerifySignature)
    }

    /// Sign an era markers payload
    pub fn sign(self, signer: &EraMarkersSigner) -> Result<Self, EraMarkersPayloadError> {
        let signature = signer.sign(
            &self
                .message_to_bytes()
                .map_err(|e| EraMarkersPayloadError::CreateSignature(e.into()))?,
        );

        Ok(Self {
            markers: self.markers,
            signature: Some(signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE: &str = "7b226d61726b657273223a5b7b226e616d65223a227468616c6573222c2265706f6368223a317d2c7b226e616d\
        65223a227079746861676f726173222c2265706f6368223a327d5d2c227369676e6174757265223a22633539373\
        9653333663163336234376361306162353239386536353562316264653235656564303866356232653536663361\
        6439623964373638316164663138653164656562623731616135616132636234363564643831323239633637656\
        33030326463396632663563363664663931333164366561633039666565373065227d";

    #[test]
    fn golden_markers_payload_with_signature() {
        EraMarkersPayload::from_json_hex(GOLDEN_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE)
            .expect("Decoding golden markers payload should not fail");
    }
}
