//! Stabilized KZG verification parameters for the IVC proof system.
//!
//! [`IvcVerifierSetup`] bundles everything needed to verify an IVC proof without
//! loading the full KZG SRS (hundreds of MB). The KZG verifier parameters are
//! embedded as a compile-time constant and deserialized on construction.

use std::collections::BTreeMap;

use anyhow::Context;
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::{poly::kzg::params::ParamsVerifierKZG, utils::SerdeFormat};
use serde::{Deserialize, Serialize};

use crate::{
    StmResult,
    circuits::{
        halo2::keys::NonRecursiveCircuitVerifyingKey,
        halo2_ivc::{
            CERTIFICATE_FIXED_BASES_PREFIX, IVC_FIXED_BASES_PREFIX,
            accumulator::fixed_bases_and_names_from_verifying_key,
            keys::RecursiveCircuitVerifyingKey, types::MessageHash,
        },
    },
    codec,
    proof_system::{KZG_VERIFIER_PARAMS, ivc_halo2_snark::prover_setup::IvcSnarkProverSetup},
};

/// Minimal setup artifacts needed to verify IVC proofs without loading the full SRS.
///
/// Unlike [`IvcSnarkProverSetup`], this struct does not hold a `ParamsKZG` (hundreds of MB). The KZG
/// verifier parameters are embedded as a compile-time constant and deserialized on
/// construction. The caller must supply the verifying keys because the certificate VK varies
/// per deployment.
///
/// # Invariant
///
/// The certificate and IVC verifying keys used to build this struct must match those used to
/// build the [`Global`] passed to [`IvcProof::verify`]. A mismatch silently produces wrong
/// public inputs and will cause verification to fail with
/// [`IvcProofError::KzgOpeningFailed`].
///
/// [`Global`]: crate::circuits::halo2_ivc::state::Global
/// [`IvcProof::verify`]: crate::proof_system::ivc_halo2_snark::proof::IvcProof::verify
/// [`IvcProofError::KzgOpeningFailed`]: crate::proof_system::ivc_halo2_snark::errors::IvcProofError::KzgOpeningFailed
pub(crate) struct IvcVerifierSetup {
    /// Stabilized KZG verifier parameters (embedded constant, no SRS load required).
    verifier_params: ParamsVerifierKZG<Bls12>,
    /// Verifying key of the IVC circuit.
    ivc_verifying_key: RecursiveCircuitVerifyingKey,
    /// Combined fixed-base map (certificate ∪ IVC) used by the accumulator check.
    combined_fixed_bases: BTreeMap<String, G1Projective>,
}

impl IvcVerifierSetup {
    /// Build from the embedded KZG params constant plus caller-supplied verifying keys.
    ///
    /// The certificate VK varies per deployment (k, m, merkle_depth); the IVC VK is typically
    /// deserialized from `RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION`. No SRS needed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn try_new(
        certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
        ivc_verifying_key: &RecursiveCircuitVerifyingKey,
    ) -> StmResult<Self> {
        let verifier_params = Self::read_embedded_params()?;

        let (certificate_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
            CERTIFICATE_FIXED_BASES_PREFIX,
            certificate_verifying_key.as_ref(),
        );
        let (ivc_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
            IVC_FIXED_BASES_PREFIX,
            ivc_verifying_key.as_ref(),
        );
        let mut combined_fixed_bases = certificate_fixed_bases;
        combined_fixed_bases.extend(ivc_fixed_bases);

        Ok(Self {
            verifier_params,
            ivc_verifying_key: ivc_verifying_key.clone(),
            combined_fixed_bases,
        })
    }

    /// Derive from an already-built [`IvcSnarkProverSetup`], reusing its precomputed fixed bases.
    ///
    /// Avoids recomputing fixed bases from scratch when a proving session is already running.
    #[allow(dead_code)]
    pub(crate) fn from_ivc_setup(ivc_setup: &IvcSnarkProverSetup) -> StmResult<Self> {
        let verifier_params = Self::read_embedded_params()?;
        Ok(Self {
            verifier_params,
            ivc_verifying_key: ivc_setup.ivc_verifying_key.clone(),
            combined_fixed_bases: ivc_setup.combined_fixed_bases.clone(),
        })
    }

    /// Derive from an already-built [`IvcSnarkProverSetup`], extracting verifier params directly
    /// from its SRS rather than the embedded constant. Only for tests — production code must
    /// not load the full SRS just to verify a proof.
    #[cfg(any(test, feature = "benchmark-internals"))]
    #[allow(dead_code)]
    pub(crate) fn from_ivc_setup_with_srs(ivc_setup: &IvcSnarkProverSetup) -> Self {
        let verifier_params = ivc_setup.srs.verifier_params();
        Self {
            verifier_params,
            ivc_verifying_key: ivc_setup.ivc_verifying_key.clone(),
            combined_fixed_bases: ivc_setup.combined_fixed_bases.clone(),
        }
    }

    /// Construct directly from pre-built parts. Only for tests that load stored assets
    /// (verifier params, VK, fixed bases) as a bundle — the caller is responsible
    /// for ensuring that `combined_fixed_bases`
    /// covers both the certificate and IVC verifying keys.
    #[cfg(test)]
    pub(crate) fn from_parts(
        verifier_params: ParamsVerifierKZG<Bls12>,
        ivc_verifying_key: RecursiveCircuitVerifyingKey,
        combined_fixed_bases: BTreeMap<String, G1Projective>,
    ) -> Self {
        Self {
            verifier_params,
            ivc_verifying_key,
            combined_fixed_bases,
        }
    }

    /// Deserialize the compile-time [`KZG_VERIFIER_PARAMS`] constant.
    ///
    /// Returns `verifier_params`. Shared by [`try_new`] and [`from_ivc_setup`].
    ///
    /// [`try_new`]: Self::try_new
    /// [`from_ivc_setup`]: Self::from_ivc_setup
    pub(crate) fn read_embedded_params() -> StmResult<ParamsVerifierKZG<Bls12>> {
        let verifier_params = ParamsVerifierKZG::<Bls12>::read(
            &mut &KZG_VERIFIER_PARAMS[..],
            SerdeFormat::RawBytesUnchecked,
        )
        .with_context(|| "Failed to read embedded IVC verifier params")?;

        Ok(verifier_params)
    }

    /// Returns the embedded KZG verifier parameters.
    pub(crate) fn verifier_params(&self) -> &ParamsVerifierKZG<Bls12> {
        &self.verifier_params
    }

    /// Returns the IVC circuit verifying key.
    pub(crate) fn ivc_verifying_key(&self) -> &RecursiveCircuitVerifyingKey {
        &self.ivc_verifying_key
    }

    /// Returns the combined fixed-base map (certificate ∪ IVC) used by the accumulator check.
    pub(crate) fn combined_fixed_bases(&self) -> &BTreeMap<String, G1Projective> {
        &self.combined_fixed_bases
    }
}

/// Represent the data needed by the verifier in order to verify an IVC proof. It contains
/// genesis information and circuit verification keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IvcVerifierData {
    genesis_message: MessageHash,
    certificate_circuit_verification_key: NonRecursiveCircuitVerifyingKey,
    ivc_circuit_verification_key: RecursiveCircuitVerifyingKey,
}

impl IvcVerifierData {
    /// Build the verifier data from the genesis message and the certificate and IVC circuit
    /// verifying keys used to produce the proof.
    ///
    /// The verifying keys are the per-circuit newtypes so their serialization preserves the circuit
    /// architecture needed to deserialize them against the correct constraint system.
    pub(crate) fn new(
        genesis_message: MessageHash,
        certificate_circuit_verification_key: NonRecursiveCircuitVerifyingKey,
        ivc_circuit_verification_key: RecursiveCircuitVerifyingKey,
    ) -> Self {
        Self {
            genesis_message,
            certificate_circuit_verification_key,
            ivc_circuit_verification_key,
        }
    }

    /// Serialize to versioned CBOR bytes, following `CODEC.md`.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Deserialize from versioned CBOR bytes, following `CODEC.md`.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes(&bytes[1..])
        } else {
            Err(anyhow::anyhow!(
                "IvcVerifierData: unsupported encoding, expected a CBOR v1 prefix"
            ))
        }
    }

    /// Returns the genesis message (hash of the genesis preimage converted to a field element)
    /// stored in the IvcVerifierData
    pub(crate) fn genesis_message(&self) -> MessageHash {
        self.genesis_message
    }

    /// Returns the certificate circuit verifying key stored in the IvcVerifierData
    pub(crate) fn certificate_circuit_verification_key(&self) -> &NonRecursiveCircuitVerifyingKey {
        &self.certificate_circuit_verification_key
    }

    /// Returns the ivc circuit verifying key stored in the IvcVerifierData
    pub(crate) fn ivc_circuit_verification_key(&self) -> &RecursiveCircuitVerifyingKey {
        &self.ivc_circuit_verification_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::{
        halo2_ivc::tests::common::asset_readers::load_embedded_verification_context_asset,
        trusted_setup::TrustedSetupProvider,
    };

    #[test]
    fn ivc_verifier_data_round_trips_byte_for_byte() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");

        let verifier_data = IvcVerifierData::new(
            MessageHash::ZERO,
            context.certificate_verifying_key,
            context.recursive_verifying_key,
        );

        let bytes = verifier_data.to_bytes().expect("serialization should not fail");
        let restored =
            IvcVerifierData::from_bytes(&bytes).expect("deserialization should not fail");
        let reencoded = restored.to_bytes().expect("re-serialization should not fail");

        assert_eq!(
            bytes, reencoded,
            "IvcVerifierData must round-trip byte-for-byte so the aggregator and client compute the same certificate hash"
        );
    }

    #[test]
    fn try_new_merges_certificate_and_ivc_fixed_bases() {
        let ctx = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let setup =
            IvcVerifierSetup::try_new(&ctx.certificate_verifying_key, &ctx.recursive_verifying_key)
                .expect("try_new must succeed with valid verifying keys");
        assert_eq!(
            setup.combined_fixed_bases.keys().collect::<Vec<_>>(),
            ctx.combined_fixed_bases.keys().collect::<Vec<_>>(),
            "combined_fixed_bases keys must match the stored verification context"
        );
    }

    #[test]
    fn embedded_ivc_verifier_params_deserialize_without_error() {
        IvcVerifierSetup::read_embedded_params()
            .expect("embedded IVC verifier params bytes must deserialize successfully");
    }

    #[test]
    #[ignore = "requires SRS download from the internet"]
    fn ivc_verifier_params_match_trusted_srs() {
        let srs = TrustedSetupProvider::default()
            .get_trusted_setup_parameters()
            .unwrap();
        let expected = srs.verifier_params();
        let mut expected_bytes = vec![];
        expected
            .write(&mut expected_bytes, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        assert_eq!(
            expected_bytes.as_slice(),
            &KZG_VERIFIER_PARAMS[..],
            "embedded IVC verifier params must match the Midnight trusted SRS"
        );
    }
}
