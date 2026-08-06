//! Payload structures and signing utilitaries for Protocol Configuration Datum

use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSignature,
    key_decode_hex, key_encode_hex,
};
use mithril_common::{StdError, StdResult};

use crate::cardano_chain::message::ProtocolConfigurationMarker;

/// [ProtocolConfigurationMarkersPayload] related errors.
#[derive(Debug, Error)]
pub enum ProtocolConfigurationMarkersPayloadError {
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

    /// Error raised when signing the markers
    #[error("could not create signature")]
    CreateSignature(#[source] StdError),
}

/// Protocol Configuration markers payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolConfigurationMarkersPayload {
    /// List of protocol configuration markers
    pub markers: Vec<ProtocolConfigurationMarker>,
}

/// Signed Protocol Configuration markers payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedProtocolConfigurationMarkersPayload {
    /// List of protocol configuration markers
    pub markers: Vec<ProtocolConfigurationMarker>,

    /// Protocol Configuration markers signature
    pub signature: ProtocolConfigurationMarkersVerifierSignature,
}

impl SignedProtocolConfigurationMarkersPayload {
    /// Instanciate a new SignedProtocolConfigurationMarkersPayload with markers and signature
    pub fn new(
        markers: Vec<ProtocolConfigurationMarker>,
        signature: ProtocolConfigurationMarkersVerifierSignature,
    ) -> Self {
        Self { markers, signature }
    }

    /// Encode this payload to a json hex string
    pub fn to_json_hex(&self) -> StdResult<String> {
        key_encode_hex(self).with_context(
            || "SignedProtocolConfigurationMarkersPayload could not be json hex encoded",
        )
    }

    /// Decode a SignedProtocolConfigurationMarkersPayload from a json hex string
    pub fn from_json_hex(payload: &str) -> StdResult<Self> {
        key_decode_hex(payload).with_context(
            || "SignedProtocolConfigurationMarkersPayload could not be decoded from json hex",
        )
    }
}

impl ProtocolConfigurationMarkersPayload {
    /// Instanciate a new ProtocolConfigurationMarkersPayload with markers
    pub fn new(markers: Vec<ProtocolConfigurationMarker>) -> Self {
        Self { markers }
    }

    fn message_to_bytes(&self) -> Result<Vec<u8>, ProtocolConfigurationMarkersPayloadError> {
        serde_json::to_vec(&self.markers)
            .map_err(|e| ProtocolConfigurationMarkersPayloadError::SerializeMessage(e.into()))
    }

    /// Sign an protocol configuration markers payload
    pub fn sign(
        self,
        signer: &ProtocolConfigurationMarkersSigner,
    ) -> Result<SignedProtocolConfigurationMarkersPayload, ProtocolConfigurationMarkersPayloadError>
    {
        let signature =
            signer.sign(&self.message_to_bytes().map_err(|e| {
                ProtocolConfigurationMarkersPayloadError::CreateSignature(e.into())
            })?);

        Ok(SignedProtocolConfigurationMarkersPayload {
            markers: self.markers,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::Epoch;

    use super::*;

    #[test]
    fn golden_master_json_hex_payload() {
        const EXPECTED_JSON_HEX: &str = "7b226d61726b657273223a5b7b2265706f6368223a34322c22636f6e66696775726174696f6e223a2263626f725f70726f746f636f6c5f636f6e66696775726174696f6e227d5d2c227369676e6174757265223a223130646265373563306232333534363136613538313535663632343638663666303736383935303635646362306237356636383735333735653163313164376166656533383962393662663466623466366234636433623130613731346162306133316566636234383562303066343038643161613064393066623366393038227d";

        let markers = vec![ProtocolConfigurationMarker::new(
            Epoch(42),
            "cbor_protocol_configuration".to_string(),
        )];
        let signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let payload = ProtocolConfigurationMarkersPayload::new(markers)
            .sign(&signer)
            .unwrap();

        let payload_from_json_hex =
            SignedProtocolConfigurationMarkersPayload::from_json_hex(EXPECTED_JSON_HEX).unwrap();

        assert_eq!(payload, payload_from_json_hex);
    }

    #[test]
    fn to_json_hex_from_json_hex_conversion() {
        let markers = vec![ProtocolConfigurationMarker::new(
            Epoch(42),
            "cbor_protocol_configuration".to_string(),
        )];
        let signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let payload = ProtocolConfigurationMarkersPayload::new(markers)
            .sign(&signer)
            .unwrap();

        let json_hex = payload.to_json_hex().unwrap();
        let payload_from_json_hex =
            SignedProtocolConfigurationMarkersPayload::from_json_hex(&json_hex).unwrap();

        assert_eq!(payload, payload_from_json_hex);
    }
}
