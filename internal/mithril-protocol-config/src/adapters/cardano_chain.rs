use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSignature,
    key_encode_hex,
};
use mithril_common::{StdError, StdResult};

use crate::ProtocolConfigurationMarker;

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

    /// Error raised when the signing the markers
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
