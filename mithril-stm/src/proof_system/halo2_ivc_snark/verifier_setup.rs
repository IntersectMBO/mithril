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
    proof_system::{KZG_VERIFIER_PARAMS, halo2_ivc_snark::prover_setup::IvcProverSetup},
};

/// Minimal setup artifacts needed to verify IVC proofs without loading the full SRS.
///
/// Unlike [`IvcProverSetup`], this struct does not hold a `ParamsKZG` (hundreds of MB). The KZG
/// verifier parameters are embedded as a compile-time constant and deserialized on
/// construction. The caller must supply the verifying keys because the certificate VK varies
/// per deployment.
///
/// # Invariant
///
/// The certificate and IVC verifying keys used to build this struct must match those used to
/// build the [`Global`] passed to [`IvcProof::verify`]. A mismatch silently produces wrong
/// public inputs and will cause verification to fail with
/// [`IvcProofError::MsmPairingCheckFailed`].
///
/// [`Global`]: crate::circuits::halo2_ivc::state::Global
/// [`IvcProof::verify`]: crate::proof_system::halo2_ivc_snark::proof::IvcProof::verify
/// [`IvcProofError::MsmPairingCheckFailed`]: crate::proof_system::halo2_ivc_snark::errors::IvcProofError::MsmPairingCheckFailed
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

    /// Derive from an already-built [`IvcProverSetup`], reusing its precomputed fixed bases.
    ///
    /// Avoids recomputing fixed bases from scratch when a proving session is already running.
    #[allow(dead_code)]
    pub(crate) fn from_ivc_setup(ivc_setup: &IvcProverSetup) -> StmResult<Self> {
        let verifier_params = Self::read_embedded_params()?;
        Ok(Self {
            verifier_params,
            ivc_verifying_key: ivc_setup.ivc_verifying_key.clone(),
            combined_fixed_bases: ivc_setup.combined_fixed_bases.clone(),
        })
    }

    /// Derive from an already-built [`IvcProverSetup`], extracting verifier params directly
    /// from its SRS rather than the embedded constant. For tests and benchmarks only
    /// (`benchmark-internals`) — production code must not load the full SRS just to verify a proof.
    #[cfg(any(test, feature = "benchmark-internals"))]
    pub(crate) fn from_ivc_setup_with_srs(ivc_setup: &IvcProverSetup) -> Self {
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
    use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    use crate::{
        BaseFieldElement,
        circuits::{
            halo2_ivc::tests::common::asset_readers::load_embedded_verification_context_asset,
            trusted_setup::TrustedSetupProvider,
        },
    };

    #[test]
    fn ivc_verifier_data_round_trips_byte_for_byte() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        // Nonzero: under `MessageHash::ZERO` a genesis message dropped on decode and defaulted
        // back to zero re-encodes to the same bytes, so byte equality alone would not see it.
        let genesis_message = MessageHash::from_field(
            BaseFieldElement::from_raw(&[0x5a; 32])
                .expect("from_raw applies modulus reduction and cannot fail")
                .0,
        );

        let verifier_data = IvcVerifierData::new(
            genesis_message,
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
        assert_eq!(
            restored.genesis_message(),
            genesis_message,
            "the genesis message must survive the round trip, not be restored as zero"
        );
    }

    #[test]
    fn input_without_the_cbor_version_prefix_is_rejected() {
        let context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let encoded = IvcVerifierData::new(
            MessageHash::ZERO,
            context.certificate_verifying_key,
            context.recursive_verifying_key,
        )
        .to_bytes()
        .expect("serialization should not fail");

        let mut under_another_version = encoded.clone();
        under_another_version[0] = under_another_version[0].wrapping_add(1);

        for (description, candidate) in [
            ("empty input", Vec::new()),
            (
                "the CBOR body with its version prefix stripped",
                encoded[1..].to_vec(),
            ),
            (
                "a body under a different version byte",
                under_another_version,
            ),
        ] {
            assert!(
                IvcVerifierData::from_bytes(&candidate).is_err(),
                "{description} must be rejected"
            );
        }
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
    #[ignore = "requires the production SRS in the local cache, see the mithril-stm README"]
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
    // The recursive key's guard must hold at the public envelope, not only at the byte codec: this
    // is the path a certificate carries, and the two circuits now share one key encoding.
    #[test]
    fn verifier_data_rejects_a_certificate_key_in_the_recursive_position() {
        // Mirrors `IvcVerifierData`'s CBOR shape with both keys as opaque bytes, so the recursive
        // slot can carry an encoding the typed constructor would never allow.
        #[derive(serde::Serialize)]
        struct VerifierDataWithOpaqueKeys {
            genesis_message: MessageHash,
            #[serde(with = "serde_bytes")]
            certificate_circuit_verification_key: Vec<u8>,
            #[serde(with = "serde_bytes")]
            ivc_circuit_verification_key: Vec<u8>,
        }

        let tampered = VerifierDataWithOpaqueKeys {
            genesis_message: MessageHash::ZERO,
            certificate_circuit_verification_key:
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec(),
            // A certificate key where the recursive one belongs.
            ivc_circuit_verification_key: NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION
                .to_vec(),
        };
        let bytes = crate::codec::to_cbor_bytes(&tampered).expect("the mirror should encode");

        let error = IvcVerifierData::from_bytes(&bytes)
            .expect_err("a certificate key must not decode in the recursive position");
        assert!(
            error.to_string().contains("architecture")
                || format!("{error:#}").contains("architecture"),
            "expected an architecture mismatch, got: {error:#}"
        );

        // The same envelope with the real recursive key decodes, so the rejection is the guard and
        // not the mirror's shape.
        let valid = VerifierDataWithOpaqueKeys {
            genesis_message: MessageHash::ZERO,
            certificate_circuit_verification_key:
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec(),
            ivc_circuit_verification_key: RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION
                .to_vec(),
        };
        let bytes = crate::codec::to_cbor_bytes(&valid).expect("the mirror should encode");
        IvcVerifierData::from_bytes(&bytes).expect("the real recursive key should decode");
    }
}
