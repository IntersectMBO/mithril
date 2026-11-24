//! Legacy era markers payload, kept until all the nodes read the era markers with a sequence
//! number.
#![allow(deprecated)]

use anyhow::Context;
use serde::{Deserialize, Serialize};

use mithril_common::StdResult;
use mithril_common::crypto_helper::{
    EraMarkersSigner, EraMarkersVerifierSignature, EraMarkersVerifierVerificationKey,
    key_decode_hex, key_encode_hex,
};

use crate::EraMarker;

use super::payload::{EraMarkersPayloadError, EraMarkersSignature};

/// Legacy era markers payload
///
/// The signature covers the markers alone, without sequence number. This format is kept for the
/// nodes that can not read the [EraMarkersPayload](super::EraMarkersPayload) yet.
#[deprecated(note = "use `EraMarkersPayload` instead, the legacy format will be removed")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyEraMarkersPayload {
    /// List of Era markers
    pub markers: Vec<EraMarker>,

    /// Era markers signature
    pub signature: Option<EraMarkersVerifierSignature>,
}

impl LegacyEraMarkersPayload {
    fn message_to_bytes(&self) -> Result<Vec<u8>, EraMarkersPayloadError> {
        serde_json::to_vec(&self.markers)
            .map_err(|e| EraMarkersPayloadError::SerializeMessage(e.into()))
    }

    /// Encode this payload to a json hex string
    pub fn to_json_hex(&self) -> StdResult<String> {
        key_encode_hex(self)
            .with_context(|| "legacy era markers payload could not be json hex encoded")
    }

    /// Decode a [LegacyEraMarkersPayload] from a json hex string
    pub fn from_json_hex(payload: &str) -> StdResult<Self> {
        key_decode_hex(payload)
            .with_context(|| "legacy era markers payload could not be decoded from json hex")
    }

    /// Verify the signature of a legacy era markers payload
    pub fn verify_signature(
        &self,
        verification_key: EraMarkersVerifierVerificationKey,
    ) -> Result<(), EraMarkersPayloadError> {
        EraMarkersSignature::verify(&self.message_to_bytes()?, self.signature, verification_key)
    }

    /// Sign a legacy era markers payload
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

#[cfg(test)]
mod tests {
    use super::super::payload::EraMarkersPayload;
    use super::super::test_fixtures::{
        legacy_payload, pythagoras_markers, sequenced_payload, thales_markers,
    };
    use super::*;

    const GOLDEN_LEGACY_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE: &str = "7b226d61726b657273223a5b7b226e616d65223a227468616c6573222c2265706f6368223a317d2c7b226e616d\
        65223a227079746861676f726173222c2265706f6368223a327d5d2c227369676e6174757265223a22633539373\
        9653333663163336234376361306162353239386536353562316264653235656564303866356232653536663361\
        6439623964373638316164663138653164656562623731616135616132636234363564643831323239633637656\
        33030326463396632663563363664663931333164366561633039666565373065227d";

    #[test]
    fn golden_legacy_markers_payload_with_signature() {
        let payload = LegacyEraMarkersPayload::from_json_hex(
            GOLDEN_LEGACY_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE,
        )
        .expect("Decoding golden legacy markers payload should not fail");

        assert_eq!(pythagoras_markers(Some(2)), payload.markers);
        payload
            .verify_signature(
                EraMarkersSigner::create_deterministic_signer()
                    .create_verifier()
                    .to_verification_key(),
            )
            .expect("Golden legacy markers payload signature should be valid");
    }

    #[test]
    fn legacy_markers_payload_does_not_decode_as_markers_payload() {
        EraMarkersPayload::from_json_hex(GOLDEN_LEGACY_ERA_MARKERS_PAYLOAD_WITH_SIGNATURE)
            .expect_err("Decoding a legacy markers payload should fail");
    }

    #[test]
    fn markers_payload_decoded_as_a_legacy_markers_payload_has_an_invalid_signature() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let payload_json_hex = sequenced_payload(&thales_markers(), 1, &era_markers_signer)
            .to_json_hex()
            .unwrap();

        let legacy_payload = LegacyEraMarkersPayload::from_json_hex(&payload_json_hex)
            .expect("Decoding a markers payload as a legacy markers payload should not fail");
        let error = legacy_payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect_err("Signature should be invalid");

        assert!(matches!(error, EraMarkersPayloadError::VerifySignature(_)));
    }

    #[test]
    fn markers_payload_signature_is_invalid_for_a_legacy_markers_payload() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let payload = sequenced_payload(&thales_markers(), 1, &era_markers_signer);
        let legacy_payload = LegacyEraMarkersPayload {
            markers: payload.markers,
            signature: payload.signature,
        };

        let error = legacy_payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect_err("Signature should be invalid");

        assert!(matches!(error, EraMarkersPayloadError::VerifySignature(_)));
    }

    #[test]
    fn legacy_markers_payload_signature_is_invalid_for_a_markers_payload() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let legacy_payload = legacy_payload(&thales_markers(), &era_markers_signer);
        let payload = EraMarkersPayload {
            markers: legacy_payload.markers,
            sequence_number: 1,
            signature: legacy_payload.signature,
        };

        let error = payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect_err("Signature should be invalid");

        assert!(matches!(error, EraMarkersPayloadError::VerifySignature(_)));
    }
}
