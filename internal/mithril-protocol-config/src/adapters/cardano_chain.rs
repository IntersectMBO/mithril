use anyhow::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::ChainAddress;
use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSignature,
    ProtocolConfigurationMarkersVerifierVerificationKey, key_encode_hex,
};
use mithril_common::{StdError, StdResult};

use crate::{ProtocolConfigurationMarker, ProtocolConfigurationReaderAdapter};

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

/// Cardano Chain adapter retrieves protocol configuration markers on chain
pub struct CardanoChainAdapter {
    address: ChainAddress,
    chain_observer: Arc<dyn ChainObserver>,
    verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
}

impl CardanoChainAdapter {
    /// CardanoChainAdapter factory
    pub fn new(
        address: ChainAddress,
        chain_observer: Arc<dyn ChainObserver>,
        verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
    ) -> Self {
        Self {
            address,
            chain_observer,
            verification_key,
        }
    }
}

#[async_trait]
impl ProtocolConfigurationReaderAdapter for CardanoChainAdapter {
    async fn read(&self) -> StdResult<Vec<ProtocolConfigurationMarker>> {
        //TODO to implement
        Ok(Vec::new())
    }
}
