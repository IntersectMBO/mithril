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
    AggregateSignatureError, AncillaryProverData, AncillaryVerifierData, MithrilMembershipDigest,
    circuits::halo2_ivc::{ProtocolMessagePreimage, state::Global},
    proof_system::{
        MERKLE_TREE_DEPTH_FOR_SNARK, SnarkClerk, SnarkProver, SnarkVerifierData,
        ivc_halo2_snark::{
            proof::{
                IvcGenesisBootstrapInput, IvcProof, IvcProver, prepare_checks,
                prepare_genesis_checks,
            },
            rolling_state::IvcRollingState,
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
                    prover.aggregate_signatures(clerk, sigs, msg).with_context(|| {
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

                let prepared = prepare_ivc_snark_request(snark_clerk, &ancillary_input, msg)?;

                let (ivc_proof, next_ancillary_prover_data, ancillary_verifier_data) =
                    prove_ivc_snark(prepared, sigs, msg, snark_clerk)?;

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

/// Bundles the outputs of [`prepare_ivc_snark_request`]: everything [`prove_ivc_snark`] needs to
/// generate the certificate proof and complete IVC proving, once the request has passed every
/// check that doesn't require that proof.
#[cfg(feature = "future_snark")]
struct PreparedIvcSnarkRequest<'a> {
    ivc_prover_setup: Arc<IvcSnarkProverSetup>,
    certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    global: Global,
    protocol_message_preimage: ProtocolMessagePreimage,
    current_rolling_state: Option<&'a IvcRollingState>,
    genesis_bootstrap: IvcGenesisBootstrapInput,
}

/// Loads the IVC prover setup, builds [`Global`], and runs every off circuit check that
/// doesn't require the certificate proof: genesis verification key validity, rolling-state
/// presence, protocol parameters unchanged, and message/preimage hash matching (genesis or
/// non-genesis, depending on whether `ancillary_input` carries a rolling state).
#[cfg(feature = "future_snark")]
fn prepare_ivc_snark_request<'a>(
    snark_clerk: &SnarkClerk,
    ancillary_input: &'a AncillaryProofInput,
    msg: &[u8],
) -> StmResult<PreparedIvcSnarkRequest<'a>> {
    let genesis_data = ancillary_input.genesis_data();
    let genesis_verifying_key = genesis_data
        .genesis_schnorr_verification_key()
        .cloned()
        .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
    let genesis_message = genesis_data.genesis_message_preimage().try_into()?;
    let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;

    let current_rolling_state = ancillary_input
        .prover_data()
        .map(|prover_data| {
            prover_data.as_ivc_rolling_state().ok_or(anyhow!(
                AggregationError::MissingIvcRollingStateInAncillaryProverData
            ))
        })
        .transpose()?;

    let protocol_message_preimage_bytes: [u8; PREIMAGE_SIZE] =
        ancillary_input.message_preimage().try_into()?;
    let protocol_message_preimage = ProtocolMessagePreimage(protocol_message_preimage_bytes);

    let trusted_setup_provider = TrustedSetupProvider::default();
    let certificate_provider = KeyProvider::for_non_recursive_circuit(
        &snark_clerk.parameters,
        MERKLE_TREE_DEPTH_FOR_SNARK,
    )?;
    let recursive_key_provider = KeyProvider::for_recursive_circuit(certificate_provider);
    let ivc_prover_setup = Arc::new(IvcSnarkProverSetup::load(
        &trusted_setup_provider,
        &recursive_key_provider,
    )?);
    let certificate_verifying_key = ivc_prover_setup.certificate_verifying_key.clone();

    let global = Global::new(
        genesis_message,
        genesis_verifying_key,
        &certificate_verifying_key,
        &ivc_prover_setup.ivc_verifying_key,
    )?;

    match current_rolling_state {
        Some(rolling_state) => {
            rolling_state.assert_protocol_parameters_unchanged()?;

            let avk = snark_clerk
                .compute_aggregate_verification_key_for_snark::<MithrilMembershipDigest>();
            prepare_checks(msg, &avk, &protocol_message_preimage, rolling_state)?;
        }
        None => {
            let combined_fixed_base_names: Vec<String> =
                ivc_prover_setup.combined_fixed_bases.keys().cloned().collect();
            let genesis_rolling_state = IvcRollingState::genesis(
                genesis_bootstrap.genesis_signature,
                &combined_fixed_base_names,
            );
            prepare_genesis_checks(&genesis_rolling_state, &protocol_message_preimage, &global)?;
        }
    }

    Ok(PreparedIvcSnarkRequest {
        ivc_prover_setup,
        certificate_verifying_key,
        global,
        protocol_message_preimage,
        current_rolling_state,
        genesis_bootstrap,
    })
}

/// Generates the certificate proof and completes IVC proving for a request already validated by
/// [`prepare_ivc_snark_request`].
///
/// Returns `(proof, ancillary_prover_data, ancillary_verifier_data)`. `ancillary_prover_data` is `Some` when
/// the step advances the epoch and `None` for same-epoch steps.
///
/// # Errors
/// Fails if the message preimage is not PREIMAGE_SIZE bytes, or the proof itself fails.
#[cfg(feature = "future_snark")]
fn prove_ivc_snark(
    prepared: PreparedIvcSnarkRequest,
    sigs: &[SingleSignature],
    msg: &[u8],
    snark_clerk: &SnarkClerk,
) -> StmResult<(
    IvcProof<Blake2b256>,
    Option<AncillaryProverData>,
    AncillaryVerifierData,
)> {
    let snark_proof = SnarkProver::try_new_non_deterministic(
        &snark_clerk.parameters,
        MERKLE_TREE_DEPTH_FOR_SNARK,
    )?
    .aggregate_signatures::<MithrilMembershipDigest>(snark_clerk, sigs, msg)
    .with_context(|| {
        format!(
            "Signatures failed to aggregate for type {}",
            AggregateSignatureType::Snark
        )
    })?;

    let avk = snark_clerk.compute_aggregate_verification_key_for_snark::<MithrilMembershipDigest>();

    let ivc_verifying_key = prepared.ivc_prover_setup.ivc_verifying_key.clone();

    let mut prover = IvcProver {
        ivc_setup: prepared.ivc_prover_setup,
        rng: OsRng,
    };

    let (ivc_proof, next_rolling_state) = prover.prove(
        snark_proof,
        msg,
        &avk,
        &prepared.global,
        &prepared.protocol_message_preimage,
        &prepared.genesis_bootstrap,
        prepared.current_rolling_state,
    )?;

    let next_ancillary_prover_data = next_rolling_state.map(AncillaryProverData::IvcSnark);

    let ancillary_verifier_data = AncillaryVerifierData::IvcSnark(IvcVerifierData::new(
        prepared.global.genesis_message,
        prepared.certificate_verifying_key,
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
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AncillaryGenesisData, AncillaryProofInput, Parameters, SchnorrSigningKey,
        SchnorrVerificationKey,
        circuits::halo2_ivc::PREIMAGE_SIZE,
        protocol::aggregate_signature::tests::setup_equal_parties,
        {AggregationError, AncillaryProverData},
    };

    use super::{AggregateSignatureType, Clerk};

    fn valid_genesis_verification_key() -> SchnorrVerificationKey {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        SchnorrVerificationKey::new_from_signing_key(signing_key)
    }

    #[test]
    fn aggregate_signatures_with_type_ivc_snark_fails_when_prover_data_carries_no_ivc_rolling_state()
     {
        let tiny_params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let ps = setup_equal_parties(tiny_params, 1);
        let clerk = Clerk::new_clerk_from_signer(&ps[0]);

        let genesis_verification_key = valid_genesis_verification_key();
        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::Future),
            AncillaryGenesisData::new(vec![0u8; 32], None, Some(genesis_verification_key)),
            vec![0u8; PREIMAGE_SIZE],
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &[0u8; 32],
                AggregateSignatureType::IvcSnark,
                ancillary_input,
            )
            .expect_err("Should fail without IVC rolling state.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingIvcRollingStateInAncillaryProverData),
            "missing IVC rolling state in ancillary prover data must be rejected, got: {err}"
        );
    }

    #[test]
    fn aggregate_signatures_with_type_ivc_snark_fails_when_genesis_verification_key_is_absent() {
        let tiny_params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let ps = setup_equal_parties(tiny_params, 1);
        let clerk = Clerk::new_clerk_from_signer(&ps[0]);

        let ancillary_input = AncillaryProofInput::new(
            None,
            AncillaryGenesisData::new(vec![0u8; 32], None, None),
            vec![0u8; PREIMAGE_SIZE],
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &[0u8; 32],
                AggregateSignatureType::IvcSnark,
                ancillary_input,
            )
            .expect_err("Should fail without genesis verification key.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingGenesisVerificationKey),
            "missing genesis verification key must be rejected, got: {err}"
        );
    }
}
