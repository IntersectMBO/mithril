use std::marker::PhantomData;
#[cfg(feature = "future_snark")]
use std::sync::Arc;

use anyhow::Context;
#[cfg(feature = "future_snark")]
use anyhow::anyhow;

#[cfg(all(feature = "future_snark", test))]
use crate::proof_system::MockSnarkProverFactory;
use crate::{
    AggregateVerificationKey, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters,
    Signer, SingleSignature, Stake, StmResult, VerificationKeyForConcatenation,
    proof_system::{
        ConcatenationClerk, ConcatenationProof,
        ivc_halo2_snark::proof::{IvcChainInput, IvcChainProver},
    },
};

#[cfg(feature = "future_snark")]
use crate::{
    AggregateSignatureError, AncillaryProverData, AncillaryVerifierData,
    proof_system::{
        NonDeterministicSnarkProverFactory, SnarkAggregateSignatureProver, SnarkClerk,
        SnarkProverFactory, SnarkVerifierData, ivc_halo2_snark::verifier_setup::IvcVerifierData,
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
    #[cfg(feature = "future_snark")]
    snark_prover_factory: Arc<dyn SnarkProverFactory<D>>,
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
            #[cfg(feature = "future_snark")]
            snark_prover_factory: Arc::new(NonDeterministicSnarkProverFactory),
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
            #[cfg(feature = "future_snark")]
            snark_prover_factory: Arc::new(NonDeterministicSnarkProverFactory),
            phantom_data: PhantomData,
        }
    }

    /// Create a Clerk from a signer whose SNARK provers come from a mocked factory.
    #[cfg(all(feature = "future_snark", test))]
    pub(crate) fn new_clerk_from_signer_with_mock_prover_factory(
        signer: &Signer<D>,
        snark_prover_factory: MockSnarkProverFactory<D>,
    ) -> Self
    where
        D: 'static,
    {
        Self {
            snark_prover_factory: Arc::new(snark_prover_factory),
            ..Self::new_clerk_from_signer(signer)
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

                let mut prover =
                    self.snark_prover_factory.snark_signature_prover(&clerk.parameters)?;
                Self::aggregate_signatures_for_snark(clerk, prover.as_mut(), sigs, msg)
            }
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => {
                let snark_clerk = self
                    .get_snark_clerk()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingSnarkClerk))?;

                let mut snark_agg_sig_prover = self
                    .snark_prover_factory
                    .snark_signature_prover(&snark_clerk.parameters)?;

                let mut ivc_prover =
                    self.snark_prover_factory.ivc_chain_prover(&snark_clerk.parameters)?;
                Self::aggregate_signatures_for_ivc_snark(
                    snark_clerk,
                    snark_agg_sig_prover.as_mut(),
                    ivc_prover.as_mut(),
                    sigs,
                    msg,
                    ancillary_input,
                )
            }
        }
    }

    fn aggregate_signatures_for_snark(
        snark_clerk: &SnarkClerk,
        prover: &mut dyn SnarkAggregateSignatureProver<D>,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        let certificate_verifying_key = prover.verification_key().clone();
        let snark_proof = prover
            .aggregate_signatures(snark_clerk, sigs, msg)
            .with_context(|| "")?;
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

    fn aggregate_signatures_for_ivc_snark(
        snark_clerk: &SnarkClerk,
        snark_agg_sig_prover: &mut dyn SnarkAggregateSignatureProver<D>,
        ivc_prover: &mut dyn IvcChainProver<D>,
        sigs: &[SingleSignature],
        msg: &[u8],
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        let certificate_verifying_key = snark_agg_sig_prover.verification_key().clone();
        let certificate_proof = snark_agg_sig_prover
            .aggregate_signatures(snark_clerk, sigs, msg)
            .with_context(|| "")?;
        let chain_input = IvcChainInput::try_new(
            certificate_proof,
            msg,
            snark_clerk.compute_aggregate_verification_key_for_snark(),
            ancillary_input,
            &certificate_verifying_key,
            ivc_prover.verifying_key(),
        )?;
        let genesis_message = chain_input.global.genesis_message;
        let (ivc_proof, next_rolling_state) = ivc_prover.advance_chain(chain_input)?;
        let verifier_data = IvcVerifierData::new(
            genesis_message,
            certificate_verifying_key,
            ivc_prover.verifying_key().clone(),
        );
        Ok((
            AggregateSignature::IvcSnark(Box::new(ivc_proof)),
            AncillaryProofOutput::new(
                next_rolling_state.map(AncillaryProverData::IvcSnark),
                Some(AncillaryVerifierData::IvcSnark(verifier_data)),
            ),
        ))
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

#[cfg(feature = "future_snark")]
#[cfg(test)]
mod tests {

    use anyhow::anyhow;
    use midnight_proofs::transcript::Blake2b256;

    use crate::{
        AggregateSignature, AggregateSignatureError, AggregateSignatureType, AggregationError,
        AncillaryGenesisData, AncillaryProofInput, AncillaryProverData, Clerk, MembershipDigest,
        MithrilMembershipDigest, Parameters, SnarkProof,
        circuits::{
            halo2::{
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                keys::NonRecursiveCircuitVerifyingKey,
            },
            halo2_ivc::{
                PREIMAGE_SIZE, RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                accumulator::trivial_accumulator,
                keys::RecursiveCircuitVerifyingKey,
                state::State,
                types::{EpochNumber, IvcProofBytes, MessageHash, StepCounter},
            },
        },
        codec::{TryFromBytes, TryToBytes},
        proof_system::{
            MERKLE_TREE_DEPTH_FOR_SNARK, MockSnarkAggregateSignatureProver, MockSnarkProverFactory,
            SnarkClerk,
            ivc_halo2_snark::{
                build_standard_rolling_state,
                proof::{IvcProof, MockIvcChainProver},
                verifier_setup::IvcVerifierData,
            },
        },
        protocol::aggregate_signature::tests::{
            setup_equal_parties, setup_party_without_snark_keys,
        },
    };

    const MESSAGE: [u8; 0] = [];

    const PROTOCOL_MESSAGE_PREIMAGE: [u8; PREIMAGE_SIZE] = [0u8; PREIMAGE_SIZE];

    fn certificate_verifying_key() -> NonRecursiveCircuitVerifyingKey {
        NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize")
    }

    fn ivc_verifying_key() -> RecursiveCircuitVerifyingKey {
        RecursiveCircuitVerifyingKey::try_from_bytes(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize")
    }

    fn dummy_snark_proof(params: Parameters) -> SnarkProof<MithrilMembershipDigest> {
        SnarkProof::new(vec![], params, MERKLE_TREE_DEPTH_FOR_SNARK)
    }

    fn build_ancillary_input(prover_data: Option<AncillaryProverData>) -> AncillaryProofInput {
        AncillaryProofInput::new(
            prover_data,
            AncillaryGenesisData::dummy(),
            #[cfg(feature = "future_snark")]
            PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        )
    }

    fn dummy_ivc_proof() -> IvcProof<Blake2b256> {
        IvcProof::new(
            IvcProofBytes::empty(),
            State::genesis(),
            trivial_accumulator(&[]),
        )
    }

    fn factory_with<D: MembershipDigest + 'static>(
        snark_agg_sig_prover: MockSnarkAggregateSignatureProver<D>,
        ivc_prover: MockIvcChainProver<D>,
    ) -> MockSnarkProverFactory<D> {
        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .return_once(move |_| Ok(Box::new(snark_agg_sig_prover)));
        factory
            .expect_ivc_chain_prover()
            .once()
            .return_once(move |_| Ok(Box::new(ivc_prover)));
        factory
    }

    #[test]
    fn ivc_aggregation_threads_next_rolling_state_into_prover_data() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);
        let current_rolling_state =
            build_standard_rolling_state(StepCounter::new(3), EpochNumber::new(2));
        let next_rolling_state =
            build_standard_rolling_state(StepCounter::new(4), EpochNumber::new(3));
        let expected_prover_data = AncillaryProverData::IvcSnark(next_rolling_state.clone())
            .to_bytes()
            .unwrap();

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_chain_prover = MockIvcChainProver::new();
        ivc_chain_prover
            .expect_verifying_key()
            .return_const(ivc_verifying_key());
        ivc_chain_prover
            .expect_advance_chain()
            .once()
            .withf(|step_input| {
                step_input.message == MESSAGE
                    && step_input.rolling_state.as_ref().is_some_and(|rolling_state| {
                        rolling_state.state().step_counter == StepCounter::new(3)
                    })
            })
            .return_once(move |_| Ok((dummy_ivc_proof(), Some(next_rolling_state))));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_chain_prover),
        );

        let (aggregate_signature, ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(Some(AncillaryProverData::IvcSnark(current_rolling_state))),
            )
            .expect("aggregation with mocked provers should succeed");

        assert!(matches!(
            aggregate_signature,
            AggregateSignature::IvcSnark(_)
        ));
        assert_eq!(
            ancillary_output.prover_data().unwrap().to_bytes().unwrap(),
            expected_prover_data
        );
    }

    #[test]
    fn concatenation_aggregation_does_not_build_snark_provers() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);
        let signature = signers[0].create_single_signature(&MESSAGE).unwrap();

        let mut factory = MockSnarkProverFactory::new();
        factory.expect_snark_signature_prover().never();
        factory.expect_ivc_chain_prover().never();

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let (aggregate_signature, _ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[signature],
                &MESSAGE,
                AggregateSignatureType::Concatenation,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");

        assert!(matches!(
            aggregate_signature,
            AggregateSignature::Concatenation(_)
        ));
    }

    #[test]
    fn snark_aggregation_fails_when_snark_clerk_is_missing() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signer = setup_party_without_snark_keys(params, 1);
        let clerk = Clerk::new_clerk_from_signer(&signer);

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::Snark,
                build_ancillary_input(None),
            )
            .expect_err("Should fail without Snark clerk.");

        assert_eq!(
            err.downcast_ref::<AggregateSignatureError>(),
            Some(&AggregateSignatureError::MissingSnarkClerk),
            "missing IVC Snark clerk must be rejected, got: {err}"
        );
    }

    #[test]
    fn snark_aggregation_builds_snark_agg_sig_prover_with_clerk_parameters() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .withf(move |actual_params| *actual_params == params)
            .return_once(move |_| Ok(Box::new(snark_agg_sig_prover)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let (aggregate_signature, _ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::Snark,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");

        assert!(matches!(aggregate_signature, AggregateSignature::Snark(_)));
    }

    #[test]
    fn snark_aggregation_propagates_prover_factory_error() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .return_once(|_| Err(anyhow!("factory error")));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::Snark,
                build_ancillary_input(None),
            )
            .expect_err("factory error should propagate");

        assert_eq!(err.to_string(), "factory error");
    }

    #[test]
    fn snark_aggregation_returns_verifier_data_from_prover_key() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .return_once(move |_| Ok(Box::new(snark_agg_sig_prover)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let (aggregate_signature, ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::Snark,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");

        assert!(matches!(aggregate_signature, AggregateSignature::Snark(_)));

        let verifier_data = ancillary_output
            .verifier_data()
            .unwrap()
            .as_snark_verifier_data()
            .unwrap();

        assert_eq!(
            verifier_data
                .certificate_circuit_verification_key()
                .to_bytes_vec()
                .unwrap(),
            certificate_verifying_key().to_bytes_vec().unwrap()
        );
    }

    #[test]
    fn snark_aggregation_propagates_prover_error() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(|_, _, _| Err(anyhow!("prover error")));

        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .return_once(move |_| Ok(Box::new(snark_agg_sig_prover)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::Snark,
                build_ancillary_input(None),
            )
            .expect_err("prover error should propagate");

        assert_eq!(err.root_cause().to_string(), "prover error");
    }

    #[test]
    fn ivc_aggregation_fails_when_snark_clerk_is_missing() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signer = setup_party_without_snark_keys(params, 1);
        let clerk = Clerk::new_clerk_from_signer(&signer);

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect_err("Should fail without Snark clerk.");

        assert_eq!(
            err.downcast_ref::<AggregateSignatureError>(),
            Some(&AggregateSignatureError::MissingSnarkClerk),
            "missing IVC Snark clerk must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_aggregation_propagates_prover_factory_error() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        let mut factory = MockSnarkProverFactory::new();
        factory
            .expect_snark_signature_prover()
            .once()
            .return_once(move |_| Ok(Box::new(snark_agg_sig_prover)));
        factory
            .expect_ivc_chain_prover()
            .once()
            .return_once(|_| Err(anyhow!("ivc factory error")));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(&signers[0], factory);

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect_err("ivc factory error should propagate");

        assert_eq!(err.to_string(), "ivc factory error");
    }

    #[test]
    fn ivc_aggregation_does_not_advance_chain_on_invalid_ancillary_input() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover.expect_advance_chain().never();

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let invalid_ancillary_input = AncillaryProofInput::new(
            None,
            AncillaryGenesisData::new(vec![0u8; PREIMAGE_SIZE], None, None),
            PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                invalid_ancillary_input,
            )
            .expect_err("Should fail without genesis verification key.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingGenesisVerificationKey),
            "missing genesis verification key must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_aggregation_passes_certificate_proof_and_message_to_step_prover() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);
        let message: &[u8] = &[7, 7, 7];

        let snark_clerk = SnarkClerk::new_clerk_from_signer(&signers[0]);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let expected_proof_bytes = dummy_snark_proof(params).to_bytes().unwrap();

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover
            .expect_advance_chain()
            .once()
            .withf(move |chain_input| {
                chain_input.message == message
                    && chain_input.certificate_proof.to_bytes().unwrap() == expected_proof_bytes
                    && chain_input.aggregate_verification_key
                        == snark_clerk.compute_aggregate_verification_key_for_snark()
            })
            .return_once(|_| Ok((dummy_ivc_proof(), None)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        clerk
            .aggregate_signatures_with_type(
                &[],
                message,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");
    }

    #[test]
    fn ivc_aggregation_uses_snark_agg_sig_prover_key_for_global_and_verifier_data() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover
            .expect_advance_chain()
            .once()
            .return_once(|_| Ok((dummy_ivc_proof(), None)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let (_aggregate_signature, ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");

        let verifier_data = ancillary_output
            .verifier_data()
            .unwrap()
            .as_ivc_verifier_data()
            .unwrap();

        let genesis_message: MessageHash = AncillaryGenesisData::dummy()
            .genesis_message_preimage()
            .try_into()
            .unwrap();
        let expected = IvcVerifierData::new(
            genesis_message,
            certificate_verifying_key(),
            ivc_verifying_key(),
        );

        assert_eq!(
            verifier_data.to_bytes().unwrap(),
            expected.to_bytes().unwrap()
        );
    }

    #[test]
    fn ivc_aggregation_returns_no_prover_data_on_same_epoch_step() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover
            .expect_advance_chain()
            .once()
            .return_once(|_| Ok((dummy_ivc_proof(), None)));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let (_aggregate_signature, ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect("aggregation with mocked provers should succeed");

        assert!(ancillary_output.prover_data().is_none());
    }

    #[test]
    fn ivc_aggregation_propagates_snark_agg_sig_prover_error() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(|_, _, _| Err(anyhow!("SNARK aggregate signature prover error")));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().never();
        ivc_prover.expect_advance_chain().never();

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect_err("SNARK aggregate signature prover error should propagate");

        assert_eq!(
            err.root_cause().to_string(),
            "SNARK aggregate signature prover error"
        );
    }

    #[test]
    fn ivc_aggregation_propagates_ivc_prover_error() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover
            .expect_advance_chain()
            .once()
            .return_once(|_| Err(anyhow!("ivc prover error")));

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(None),
            )
            .expect_err("ivc prover error should propagate");

        assert_eq!(err.root_cause().to_string(), "ivc prover error");
    }

    #[test]
    fn ivc_aggregation_does_not_advance_chain_when_prover_data_carries_no_ivc_rolling_state() {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let signers = setup_equal_parties(params, 1);

        let mut snark_agg_sig_prover = MockSnarkAggregateSignatureProver::new();
        snark_agg_sig_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_agg_sig_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| Ok(dummy_snark_proof(params)));

        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover.expect_advance_chain().never();

        let clerk = Clerk::new_clerk_from_signer_with_mock_prover_factory(
            &signers[0],
            factory_with(snark_agg_sig_prover, ivc_prover),
        );

        let err = clerk
            .aggregate_signatures_with_type(
                &[],
                &MESSAGE,
                AggregateSignatureType::IvcSnark,
                build_ancillary_input(Some(AncillaryProverData::Future)),
            )
            .expect_err("Should fail when prover data carries no IVC rolling state.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingIvcRollingStateInAncillaryProverData),
            "missing IVC rolling state must be rejected, got: {err}"
        );
    }
}
