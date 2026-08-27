use std::marker::PhantomData;
#[cfg(feature = "future_snark")]
use std::sync::Arc;

use anyhow::Context;
#[cfg(feature = "future_snark")]
use anyhow::anyhow;
#[cfg(feature = "future_snark")]
use midnight_proofs::transcript::Blake2b256;
#[cfg(feature = "future_snark")]
use rand_core::OsRng;

use crate::{
    AggregateVerificationKey, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters,
    Signer, SingleSignature, Stake, StmResult, VerificationKeyForConcatenation,
    proof_system::{ConcatenationClerk, ConcatenationProof},
};
#[cfg(feature = "future_snark")]
use crate::{
    AggregationError,
    circuits::{
        halo2::keys::NonRecursiveCircuitVerifyingKey, halo2_ivc::PREIMAGE_SIZE,
        key_provider::KeyProvider, trusted_setup::TrustedSetupProvider,
    },
    proof_system::ivc_halo2_snark::IvcSnarkProverSetup,
};

#[cfg(feature = "future_snark")]
use crate::{
    AggregateSignatureError, AncillaryProverData, AncillaryVerifierData, SnarkProof,
    circuits::halo2_ivc::{ProtocolMessagePreimage, state::Global},
    proof_system::{
        CertificateProver, MERKLE_TREE_DEPTH_FOR_SNARK, SnarkClerk, SnarkProver, SnarkVerifierData,
        ivc_halo2_snark::{
            proof::{IvcProof, IvcProver},
            verifier_setup::IvcVerifierData,
        },
    },
};

use super::{
    AggregateSignature, AggregateSignatureType, AncillaryProofInput, AncillaryProofOutput,
};

/// Clerk for aggregate signatures.
///
/// Manages both the concatenation proof clerk and, when the `future_snark`
/// feature is enabled, the SNARK proof clerk. Provides methods for signature
/// aggregation and aggregate verification key computation.
#[derive(Debug, Clone)]
pub struct Clerk<D: MembershipDigest> {
    concatenation_proof_clerk: ConcatenationClerk,
    #[cfg(feature = "future_snark")]
    snark_proof_clerk: Option<SnarkClerk>,
    phantom_data: PhantomData<D>,
}

impl<D: MembershipDigest> Clerk<D> {
    /// Create a Clerk from a signer.
    pub fn new_clerk_from_signer(signer: &Signer<D>) -> Self {
        Self {
            concatenation_proof_clerk: ConcatenationClerk::new_clerk_from_signer(signer),
            #[cfg(feature = "future_snark")]
            snark_proof_clerk: signer
                .closed_key_registration
                .has_snark_verification_keys()
                .then(|| SnarkClerk::new_clerk_from_signer(signer)),
            phantom_data: PhantomData,
        }
    }

    /// Create a Clerk from a closed key registration.
    pub fn new_clerk_from_closed_key_registration(
        parameters: &Parameters,
        closed_registration: &ClosedKeyRegistration,
    ) -> Self {
        Self {
            concatenation_proof_clerk: ConcatenationClerk::new_clerk_from_closed_key_registration(
                parameters,
                closed_registration,
            ),
            #[cfg(feature = "future_snark")]
            snark_proof_clerk: closed_registration.has_snark_verification_keys().then(|| {
                SnarkClerk::new_clerk_from_closed_key_registration(parameters, closed_registration)
            }),
            phantom_data: PhantomData,
        }
    }

    /// Aggregate a set of signatures with a given proof type.
    pub fn aggregate_signatures_with_type(
        &self,
        sigs: &[SingleSignature],
        msg: &[u8],
        aggregate_signature_type: AggregateSignatureType,
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        let _ = &ancillary_input;
        match aggregate_signature_type {
            AggregateSignatureType::Concatenation => {
                let proof = ConcatenationProof::aggregate_signatures(
                    self.get_concatenation_clerk(),
                    sigs,
                    msg,
                )
                .with_context(|| {
                    format!(
                        "Signatures failed to aggregate for type {}",
                        AggregateSignatureType::Concatenation
                    )
                })?;
                Ok((
                    AggregateSignature::Concatenation(Box::new(proof)),
                    AncillaryProofOutput::new(None, None),
                ))
            }
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => {
                let clerk = self
                    .get_snark_clerk()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingSnarkClerk))?;
                let mut prover = SnarkProver::try_new_non_deterministic(
                    &clerk.parameters,
                    MERKLE_TREE_DEPTH_FOR_SNARK,
                )?;
                // Clone the verifying key before proving so the certificate's ancillary verifier
                // data and the proof provably originate from the same setup.
                let certificate_verifying_key = prover.verification_key().clone();
                let snark_proof =
                    prover.prove_certificate(clerk, sigs, msg).with_context(|| {
                        format!(
                            "Signatures failed to aggregate for type {}",
                            AggregateSignatureType::Snark
                        )
                    })?;
                Ok((
                    AggregateSignature::Snark(Box::new(snark_proof)),
                    AncillaryProofOutput::new(
                        None,
                        Some(AncillaryVerifierData::Snark(SnarkVerifierData::new(
                            certificate_verifying_key,
                        ))),
                    ),
                ))
            }
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => {
                let snark_clerk = self
                    .get_snark_clerk()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingSnarkClerk))?;

                let snark_proof = SnarkProver::try_new_non_deterministic(
                    &snark_clerk.parameters,
                    MERKLE_TREE_DEPTH_FOR_SNARK,
                )?
                .prove_certificate(snark_clerk, sigs, msg)
                .with_context(|| {
                    format!(
                        "Signatures failed to aggregate for type {}",
                        AggregateSignatureType::Snark
                    )
                })?;

                let trusted_setup_provider = TrustedSetupProvider::default();
                let certificate_provider = KeyProvider::for_non_recursive_circuit(
                    &snark_clerk.parameters,
                    MERKLE_TREE_DEPTH_FOR_SNARK,
                )?;
                let recursive_key_provider =
                    KeyProvider::for_recursive_circuit(certificate_provider);
                let ivc_prover_setup = Arc::new(IvcSnarkProverSetup::load(
                    &trusted_setup_provider,
                    &recursive_key_provider,
                )?);
                let certificate_verifying_key = ivc_prover_setup.certificate_verifying_key.clone();

                let (ivc_proof, next_ancillary_prover_data, ancillary_verifier_data) =
                    ivc_prover_input_preparation_and_prove(
                        snark_proof,
                        msg,
                        snark_clerk,
                        &ancillary_input,
                        ivc_prover_setup,
                        certificate_verifying_key,
                    )?;

                Ok((
                    AggregateSignature::IvcSnark(Box::new(ivc_proof)),
                    AncillaryProofOutput::new(
                        next_ancillary_prover_data,
                        Some(ancillary_verifier_data),
                    ),
                ))
            }
        }
    }

    /// Get the concatenation clerk.
    pub fn get_concatenation_clerk(&self) -> &ConcatenationClerk {
        &self.concatenation_proof_clerk
    }

    /// Get the SNARK clerk, if available.
    #[cfg(feature = "future_snark")]
    pub fn get_snark_clerk(&self) -> Option<&SnarkClerk> {
        self.snark_proof_clerk.as_ref()
    }

    /// Compute the aggregate verification key covering both proof systems.
    pub fn compute_aggregate_verification_key(&self) -> AggregateVerificationKey<D> {
        AggregateVerificationKey::new(
            self.concatenation_proof_clerk
                .compute_aggregate_verification_key_for_concatenation(),
            #[cfg(feature = "future_snark")]
            self.snark_proof_clerk
                .as_ref()
                .map(|clerk| clerk.compute_aggregate_verification_key_for_snark()),
        )
    }

    /// Get the concatenation registered party for a given index.
    pub fn get_concatenation_registered_party_for_index(
        &self,
        party_index: &LotteryIndex,
    ) -> StmResult<(VerificationKeyForConcatenation, Stake)> {
        let entry = self
            .get_concatenation_clerk()
            .closed_key_registration
            .get_registration_entry_for_index(party_index)?;
        Ok((
            entry.get_verification_key_for_concatenation(),
            entry.get_stake(),
        ))
    }

    #[cfg(test)]
    pub fn update_k(&mut self, k: u64) {
        self.concatenation_proof_clerk.update_k(k);
    }

    #[cfg(test)]
    pub fn update_m(&mut self, m: u64) {
        self.concatenation_proof_clerk.update_m(m);
    }
}

/// Prepares the IVC prover inputs from `ancillary_input` and the cached prover setup to
/// build the [`Global`] chain constants, and run [`IvcProver::prove`].
///
/// Returns `(proof, ancillary_prover_data, ancillary_verifier_data)`. `ancillary_prover_data` is `Some` when
/// the step advances the epoch and `None` for same-epoch steps.
///
/// # Errors
/// Fails if the genesis Schnorr verifying key is absent, the message preimage is not PREIMAGE_SIZE bytes,
/// or the proof itself fails.
#[cfg(feature = "future_snark")]
fn ivc_prover_input_preparation_and_prove<D: MembershipDigest>(
    snark_proof: SnarkProof<D>,
    msg: &[u8],
    clerk: &SnarkClerk,
    ancillary_input: &AncillaryProofInput,
    ivc_prover_setup: Arc<IvcSnarkProverSetup>,
    certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
) -> StmResult<(
    IvcProof<Blake2b256>,
    Option<AncillaryProverData>,
    AncillaryVerifierData,
)> {
    let protocol_message_preimage_bytes: [u8; PREIMAGE_SIZE] =
        ancillary_input.message_preimage().try_into()?;

    let genesis_data = ancillary_input.genesis_data();

    let genesis_verifying_key = genesis_data
        .genesis_schnorr_verification_key()
        .cloned()
        .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;

    let genesis_message = genesis_data.genesis_message_preimage().try_into()?;

    let ivc_verifying_key = ivc_prover_setup.ivc_verifying_key.clone();

    let current_rolling_state = ancillary_input
        .prover_data()
        .map(|prover_data| {
            prover_data.as_ivc_rolling_state().ok_or(anyhow!(
                AggregationError::MissingIvcRollingStateInAncillaryProverData
            ))
        })
        .transpose()?;

    let genesis_bootstrap = &genesis_data.try_into()?;

    let avk = clerk.compute_aggregate_verification_key_for_snark();

    let global = Global::new(
        genesis_message,
        genesis_verifying_key,
        &certificate_verifying_key,
        &ivc_verifying_key,
    );

    let mut prover = IvcProver {
        ivc_setup: ivc_prover_setup,
        rng: OsRng,
    };

    let (ivc_proof, next_rolling_state) = prover.prove(
        snark_proof,
        msg,
        &avk,
        &global,
        &ProtocolMessagePreimage(protocol_message_preimage_bytes),
        genesis_bootstrap,
        current_rolling_state,
    )?;

    let next_ancillary_prover_data = next_rolling_state.map(AncillaryProverData::IvcSnark);

    let ancillary_verifier_data = AncillaryVerifierData::IvcSnark(IvcVerifierData::new(
        genesis_message,
        certificate_verifying_key,
        ivc_verifying_key,
    ));

    Ok((
        ivc_proof,
        next_ancillary_prover_data,
        ancillary_verifier_data,
    ))
}

#[cfg(feature = "future_snark")]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use midnight_curves::Bls12;
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use midnight_zk_stdlib::{self as zk, MidnightCircuit};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AncillaryGenesisData, AncillaryProofInput, MithrilMembershipDigest, Parameters,
        circuits::halo2::circuit::StmCertificateCircuit,
        circuits::halo2::keys::NonRecursiveCircuitVerifyingKey,
        circuits::halo2_ivc::PREIMAGE_SIZE,
        circuits::halo2_ivc::keys::{RecursiveCircuitProvingKey, RecursiveCircuitVerifyingKey},
        proof_system::SnarkClerk,
        proof_system::{MERKLE_TREE_DEPTH_FOR_SNARK, ivc_halo2_snark::IvcSnarkProverSetup},
        protocol::aggregate_signature::tests::setup_equal_parties,
        {AggregationError, AncillaryProverData, SnarkProof},
    };

    use super::ivc_prover_input_preparation_and_prove;

    fn build_fast_dummy_ivc_setup(
        params: Parameters,
        depth: u32,
    ) -> (Arc<IvcSnarkProverSetup>, NonRecursiveCircuitVerifyingKey) {
        let circuit = StmCertificateCircuit::try_new(&params, depth)
            .expect("certificate circuit should build");
        let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();

        let cert_srs =
            ParamsKZG::<Bls12>::unsafe_setup(circuit_degree, ChaCha20Rng::from_seed([42u8; 32]));

        let midnight_vk = zk::setup_vk(&cert_srs, &circuit);
        let midnight_pk = zk::setup_pk(&circuit, &midnight_vk);
        let cert_vk = midnight_vk.vk().clone();
        // Not the correct key but we only need a dummy
        let cert_pk = midnight_pk.pk().clone();

        let ivc_setup = Arc::new(IvcSnarkProverSetup {
            srs: cert_srs,
            certificate_verifying_key: NonRecursiveCircuitVerifyingKey::new(midnight_vk.clone()),
            ivc_verifying_key: RecursiveCircuitVerifyingKey::new(cert_vk),
            ivc_proving_key: RecursiveCircuitProvingKey::new(cert_pk),
            certificate_fixed_bases: BTreeMap::new(),
            ivc_fixed_bases: BTreeMap::new(),
            combined_fixed_bases: BTreeMap::new(),
        });

        (ivc_setup, NonRecursiveCircuitVerifyingKey::new(midnight_vk))
    }

    #[test]
    fn ivc_prover_input_preparation_fails_when_prover_data_carries_no_ivc_rolling_state() {
        use crate::SchnorrVerificationKey;

        let tiny_params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let (ivc_prover_setup, certificate_verifying_key) =
            build_fast_dummy_ivc_setup(tiny_params, 1);

        let ps = setup_equal_parties(tiny_params, 1);
        let snark_clerk = SnarkClerk::new_clerk_from_signer(&ps[0]);
        let snark_proof = SnarkProof::<MithrilMembershipDigest>::new(
            vec![],
            tiny_params,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );

        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::Future),
            AncillaryGenesisData::new(vec![0u8; 32], None, Some(SchnorrVerificationKey::default())),
            vec![0u8; PREIMAGE_SIZE],
        );

        let err = ivc_prover_input_preparation_and_prove(
            snark_proof,
            &[0u8; 32],
            &snark_clerk,
            &ancillary_input,
            ivc_prover_setup,
            certificate_verifying_key,
        )
        .expect_err("Should fail without IVC rolling state.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingIvcRollingStateInAncillaryProverData),
            "missing IVC rolling state in ancillary prover data must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_prover_input_preparation_fails_when_genesis_verification_key_is_absent() {
        let tiny_params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let (ivc_prover_setup, certificate_verifying_key) =
            build_fast_dummy_ivc_setup(tiny_params, 1);

        let ps = setup_equal_parties(tiny_params, 1);
        let snark_clerk = SnarkClerk::new_clerk_from_signer(&ps[0]);
        let snark_proof = SnarkProof::<MithrilMembershipDigest>::new(
            vec![],
            tiny_params,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );

        let ancillary_input = AncillaryProofInput::new(
            None,
            AncillaryGenesisData::new(vec![0u8; 32], None, None),
            vec![0u8; PREIMAGE_SIZE],
        );

        let err = ivc_prover_input_preparation_and_prove(
            snark_proof,
            &[0u8; 32],
            &snark_clerk,
            &ancillary_input,
            ivc_prover_setup,
            certificate_verifying_key,
        )
        .expect_err("Should fail without genesis verification key.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingGenesisVerificationKey),
            "missing genesis verification key must be rejected, got: {err}"
        );
    }
}
