//! Ancillary data carried by a certificate for the prover and the verifier.
//!
//! These are proof-system-agnostic carriers whose variants map to the aggregate signature types
//! that need them. They start with no variants and grow as those schemes land.

use serde::{Deserialize, Serialize};

#[cfg(all(test, feature = "future_snark"))]
use rand_chacha::ChaCha20Rng;
#[cfg(all(test, feature = "future_snark"))]
use rand_core::SeedableRng;

#[cfg(all(test, feature = "future_snark"))]
use crate::{BaseFieldElement, SchnorrSigningKey};

#[cfg(feature = "future_snark")]
use crate::{
    SchnorrVerificationKey, StandardSchnorrSignature,
    proof_system::{
        IvcRollingState, SnarkVerifierData, ivc_halo2_snark::verifier_setup::IvcVerifierData,
    },
    protocol::aggregate_signature::GenesisMessagePreimage,
};
use crate::{StmResult, codec};

/// Ancillary data carried by a certificate for the prover.
///
/// Holds the prover-side state needed to produce the next certificate. Carried in the certificate,
/// hashed into the certificate hash and transmitted in the certificate message. Variants map to the
/// aggregate signature types that require prover data.
#[cfg_attr(test, allow(clippy::large_enum_variant))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AncillaryProverData {
    #[cfg(feature = "future_snark")]
    IvcSnark(IvcRollingState),
    #[cfg(all(feature = "future_snark", test))]
    Future,
}

impl AncillaryProverData {
    /// Serialize to versioned CBOR bytes, following `CODEC.md`.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Deserialize from versioned CBOR bytes, following `CODEC.md`.
    ///
    /// With no variants this always fails; it gains meaning once a variant is added.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes(&bytes[1..])
        } else {
            Err(anyhow::anyhow!(
                "AncillaryProverData: unsupported encoding, expected a CBOR v1 prefix"
            ))
        }
    }

    /// Returns the wrapped IvcRollingState of an AncillaryProverData if it exists.
    #[cfg(feature = "future_snark")]
    pub fn as_ivc_rolling_state(&self) -> Option<&IvcRollingState> {
        match self {
            Self::IvcSnark(state) => Some(state),
            #[cfg(test)]
            Self::Future => None,
        }
    }

    /// Returns the wrapped IvcRollingState of an AncillaryProverData if it exists.
    #[cfg(feature = "future_snark")]
    pub fn into_ivc_rolling_state(self) -> Option<IvcRollingState> {
        match self {
            Self::IvcSnark(state) => Some(state),
            #[cfg(test)]
            Self::Future => None,
        }
    }
}

/// Ancillary data carried by a certificate for the verifier.
///
/// Holds the data a verifier needs to verify the certificate. Stored and transmitted in the
/// certificate message. Variants map to the aggregate signature types that require verifier
/// data.
// The recursive `IvcSnark` verifier data is inherently larger than the non-recursive `Snark` one.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AncillaryVerifierData {
    #[cfg(feature = "future_snark")]
    IvcSnark(IvcVerifierData),
    /// Non-recursive SNARK: carries the certificate circuit verifying key, which is fixed for a
    /// given circuit configuration and shared across the proofs it verifies.
    #[cfg(feature = "future_snark")]
    Snark(SnarkVerifierData),
}

impl AncillaryVerifierData {
    /// Serialize to versioned CBOR bytes, following `CODEC.md`.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Deserialize from versioned CBOR bytes, following `CODEC.md`.
    ///
    /// With no variants this always fails; it gains meaning once a variant is added.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes(&bytes[1..])
        } else {
            Err(anyhow::anyhow!(
                "AncillaryVerifierData: unsupported encoding, expected a CBOR v1 prefix"
            ))
        }
    }

    /// Returns the wrapped IvcVerifierData of an AncillaryVerifierData.
    #[cfg(feature = "future_snark")]
    pub fn as_ivc_verifier_data(&self) -> Option<&IvcVerifierData> {
        match self {
            Self::IvcSnark(state) => Some(state),
            Self::Snark(_) => None,
        }
    }

    /// Returns the wrapped SnarkVerifierData of a non-recursive SNARK AncillaryVerifierData.
    #[cfg(feature = "future_snark")]
    pub fn as_snark_verifier_data(&self) -> Option<&SnarkVerifierData> {
        match self {
            Self::Snark(snark_verifier_data) => Some(snark_verifier_data),
            Self::IvcSnark(_) => None,
        }
    }
}

/// Genesis-related data carried into aggregate signature creation.
///
/// Under `future_snark`, holds the genesis message preimage, the genesis Schnorr signature and the
/// genesis Schnorr verification key when the genesis certificate carries them. It is a transient
/// input to proof creation, never stored on a certificate.
#[derive(Clone, Debug)]
pub struct AncillaryGenesisData {
    #[cfg(feature = "future_snark")]
    genesis_message_preimage: GenesisMessagePreimage,
    #[cfg(feature = "future_snark")]
    genesis_schnorr_signature: Option<StandardSchnorrSignature>,
    #[cfg(feature = "future_snark")]
    genesis_schnorr_verification_key: Option<SchnorrVerificationKey>,
}

impl AncillaryGenesisData {
    /// Build the genesis ancillary data. Under `future_snark`, from the genesis message preimage,
    /// the genesis Schnorr signature and the genesis Schnorr verification key (the signature absent
    /// for a legacy, non-dual genesis certificate).
    #[cfg_attr(not(feature = "future_snark"), allow(clippy::new_without_default))]
    pub fn new(
        #[cfg(feature = "future_snark")] genesis_message_preimage: Vec<u8>,
        #[cfg(feature = "future_snark")] genesis_schnorr_signature: Option<
            StandardSchnorrSignature,
        >,
        #[cfg(feature = "future_snark")] genesis_schnorr_verification_key: Option<
            SchnorrVerificationKey,
        >,
    ) -> Self {
        Self {
            #[cfg(feature = "future_snark")]
            genesis_message_preimage: GenesisMessagePreimage(genesis_message_preimage),
            #[cfg(feature = "future_snark")]
            genesis_schnorr_signature,
            #[cfg(feature = "future_snark")]
            genesis_schnorr_verification_key,
        }
    }

    /// Return the genesis message preimage.
    #[cfg(feature = "future_snark")]
    pub fn genesis_message_preimage(&self) -> &GenesisMessagePreimage {
        &self.genesis_message_preimage
    }

    /// Return the genesis Schnorr signature, absent for a legacy (non-dual) genesis certificate.
    #[cfg(feature = "future_snark")]
    pub fn genesis_schnorr_signature(&self) -> Option<&StandardSchnorrSignature> {
        self.genesis_schnorr_signature.as_ref()
    }

    /// Return the genesis Schnorr verification key, absent for a legacy (non-dual) genesis
    /// certificate.
    #[cfg(feature = "future_snark")]
    pub fn genesis_schnorr_verification_key(&self) -> Option<&SchnorrVerificationKey> {
        self.genesis_schnorr_verification_key.as_ref()
    }

    /// Build genesis ancillary data carrying no data, for use in tests.
    #[cfg(all(test, feature = "future_snark"))]
    pub fn dummy() -> Self {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let message = vec![BaseFieldElement::from(1u64)];
        let signature = signing_key.sign_standard(&message, &mut rng).unwrap();
        let verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key);
        Self::new(
            #[cfg(feature = "future_snark")]
            vec![0u8; 190],
            #[cfg(feature = "future_snark")]
            Some(signature),
            #[cfg(feature = "future_snark")]
            Some(verification_key),
        )
    }
}

/// Ancillary input to one aggregate signature creation.
///
/// Carries the prover data from the previous certificate, the genesis data from the genesis
/// certificate and, under `future_snark`, the rigid preimage of the protocol message being
/// aggregated, the state the proof system needs at creation. It is always supplied to the clerk;
/// each proof system decides whether to consume it.
#[derive(Clone, Debug)]
pub struct AncillaryProofInput {
    prover_data: Option<AncillaryProverData>,
    genesis_data: AncillaryGenesisData,
    #[cfg(feature = "future_snark")]
    message_preimage: Vec<u8>,
}

impl AncillaryProofInput {
    /// Build the ancillary proof input from the prover data, the genesis data and, under
    /// `future_snark`, the rigid preimage of the protocol message being aggregated.
    pub fn new(
        prover_data: Option<AncillaryProverData>,
        genesis_data: AncillaryGenesisData,
        #[cfg(feature = "future_snark")] message_preimage: Vec<u8>,
    ) -> Self {
        Self {
            prover_data,
            genesis_data,
            #[cfg(feature = "future_snark")]
            message_preimage,
        }
    }

    /// Return the prover ancillary data carried from the previous certificate.
    pub fn prover_data(&self) -> Option<&AncillaryProverData> {
        self.prover_data.as_ref()
    }

    /// Return the prover ancillary data carried from the previous certificate.
    pub fn into_prover_data(self) -> Option<AncillaryProverData> {
        self.prover_data
    }

    /// Return the genesis ancillary data.
    pub fn genesis_data(&self) -> &AncillaryGenesisData {
        &self.genesis_data
    }

    /// Return the rigid preimage of the protocol message being aggregated.
    #[cfg(feature = "future_snark")]
    pub fn message_preimage(&self) -> &[u8] {
        &self.message_preimage
    }

    /// Build an ancillary proof input carrying no data, for use in tests.
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self::new(
            None,
            AncillaryGenesisData::dummy(),
            #[cfg(feature = "future_snark")]
            Vec::new(),
        )
    }
}

/// Ancillary output from one aggregate signature creation.
///
/// Carries the prover data to store on the new certificate (the state the proof system needs to
/// produce the next certificate) and the verifier data the new certificate exposes. It is the
/// output counterpart of [`AncillaryProofInput`]; each proof system decides whether to produce
/// either, so both are absent for a proof system that produces none.
#[derive(Clone, Debug)]
pub struct AncillaryProofOutput {
    prover_data: Option<AncillaryProverData>,
    verifier_data: Option<AncillaryVerifierData>,
}

impl AncillaryProofOutput {
    /// Build the ancillary proof output from the prover and verifier data.
    pub fn new(
        prover_data: Option<AncillaryProverData>,
        verifier_data: Option<AncillaryVerifierData>,
    ) -> Self {
        Self {
            prover_data,
            verifier_data,
        }
    }

    /// Return the prover ancillary data to store on the new certificate.
    pub fn prover_data(&self) -> Option<&AncillaryProverData> {
        self.prover_data.as_ref()
    }

    /// Return the verifier ancillary data the new certificate exposes.
    pub fn verifier_data(&self) -> Option<&AncillaryVerifierData> {
        self.verifier_data.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "future_snark")]
    use rand_chacha::ChaCha20Rng;
    #[cfg(feature = "future_snark")]
    use rand_core::SeedableRng;

    use crate::codec::CODEC_VERSION_CBOR_V1;
    #[cfg(feature = "future_snark")]
    use crate::{
        BaseFieldElement, SchnorrSigningKey,
        circuits::halo2_ivc::{
            tests::common::asset_readers::load_embedded_verification_context_asset,
            types::MessageHash,
        },
    };

    use super::*;

    // Duplicate from rolling_state.rs tests
    #[cfg(feature = "future_snark")]
    fn build_genesis_signature() -> StandardSchnorrSignature {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let message = vec![BaseFieldElement::from(1u64)];
        signing_key.sign_standard(&message, &mut rng).unwrap()
    }

    #[test]
    fn prover_data_from_bytes_rejects_every_input() {
        assert!(AncillaryProverData::from_bytes(&[]).is_err());
        assert!(AncillaryProverData::from_bytes(&[0, 1, 2]).is_err());
        assert!(AncillaryProverData::from_bytes(&[CODEC_VERSION_CBOR_V1, 0xff]).is_err());
    }

    #[test]
    fn verifier_data_from_bytes_rejects_every_input() {
        assert!(AncillaryVerifierData::from_bytes(&[]).is_err());
        assert!(AncillaryVerifierData::from_bytes(&[0, 1, 2]).is_err());
        assert!(AncillaryVerifierData::from_bytes(&[CODEC_VERSION_CBOR_V1, 0xff]).is_err());
    }

    #[test]
    fn proof_output_exposes_the_data_it_was_built_with() {
        let output = AncillaryProofOutput::new(None, None);

        assert!(output.prover_data().is_none());
        assert!(output.verifier_data().is_none());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn genesis_data_getters_return_the_values_it_was_built_with() {
        let preimage = vec![1u8, 2, 3];

        let genesis_data = AncillaryGenesisData::new(preimage.clone(), None, None);

        assert_eq!(
            genesis_data.genesis_message_preimage().0,
            preimage.as_slice()
        );
        assert!(genesis_data.genesis_schnorr_signature().is_none());
        assert!(genesis_data.genesis_schnorr_verification_key().is_none());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn proof_input_returns_the_message_preimage_it_was_built_with() {
        let message_preimage = vec![9u8, 8, 7];

        let proof_input = AncillaryProofInput::new(
            None,
            AncillaryGenesisData::dummy(),
            message_preimage.clone(),
        );

        assert_eq!(proof_input.message_preimage(), message_preimage.as_slice());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn ancillary_prover_data_to_from_bytes_round_trip() {
        let genesis_signature = build_genesis_signature();
        let fixed_base_names = vec!["base_one".to_string(), "base_two".to_string()];
        let rolling_state = IvcRollingState::genesis(genesis_signature, &fixed_base_names);
        let ancillary_prover_data = AncillaryProverData::IvcSnark(rolling_state);

        let bytes = ancillary_prover_data.to_bytes().unwrap();
        let reconstructed = AncillaryProverData::from_bytes(&bytes).unwrap();

        assert_eq!(bytes, reconstructed.to_bytes().unwrap());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn ancillary_verifier_data_to_from_bytes_round_trip() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let verifier_data = IvcVerifierData::new(
            MessageHash::ZERO,
            context.certificate_verifying_key,
            context.recursive_verifying_key,
        );
        let ancillary_verifier_data = AncillaryVerifierData::IvcSnark(verifier_data);

        let bytes = ancillary_verifier_data.to_bytes().unwrap();
        let reconstructed = AncillaryVerifierData::from_bytes(&bytes).unwrap();

        assert_eq!(bytes, reconstructed.to_bytes().unwrap());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn ancillary_snark_verifier_data_to_from_bytes_round_trip() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let verifier_data = SnarkVerifierData::new(context.certificate_verifying_key);
        let ancillary_verifier_data = AncillaryVerifierData::Snark(verifier_data);

        let bytes = ancillary_verifier_data.to_bytes().unwrap();
        let reconstructed = AncillaryVerifierData::from_bytes(&bytes).unwrap();

        assert_eq!(bytes, reconstructed.to_bytes().unwrap());
        assert!(reconstructed.as_snark_verifier_data().is_some());
        assert!(reconstructed.as_ivc_verifier_data().is_none());
    }

    /// Byte-locks the CBOR encoding of the pre-existing `IvcSnark` ancillary variant against a
    /// hardcoded digest, so appending the `Snark` variant to `AncillaryVerifierData` cannot
    /// silently change the encoding of the existing variant — which would break committed IVC
    /// certificates. ciborium tags enum variants by name, so the encoding is independent of variant
    /// order; the digest below is the pre-change value and must never change.
    #[cfg(feature = "future_snark")]
    #[test]
    fn ivc_ancillary_encoding_is_byte_stable() {
        use sha2::{Digest, Sha256};

        const EXPECTED_IVC_ANCILLARY_DIGEST: [u8; 32] = [
            98, 51, 110, 52, 61, 7, 186, 33, 25, 69, 151, 75, 36, 223, 4, 98, 6, 240, 88, 93, 35,
            185, 12, 157, 96, 39, 6, 65, 20, 46, 13, 146,
        ];
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let verifier_data = IvcVerifierData::new(
            MessageHash::ZERO,
            context.certificate_verifying_key,
            context.recursive_verifying_key,
        );
        let bytes = AncillaryVerifierData::IvcSnark(verifier_data).to_bytes().unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();

        assert_eq!(
            digest, EXPECTED_IVC_ANCILLARY_DIGEST,
            "IvcSnark ancillary encoding changed — adding a variant must not alter the existing \
             variant's CBOR, or committed IVC certificates would break"
        );
    }
}
