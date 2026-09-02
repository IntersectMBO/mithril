use std::marker::PhantomData;
#[cfg(feature = "future_snark")]
use std::sync::Arc;

use anyhow::Context;
#[cfg(feature = "future_snark")]
use anyhow::anyhow;

#[cfg(all(feature = "future_snark", test))]
use crate::proof_system::MockSnarkProverFactory;
#[cfg(feature = "future_snark")]
use crate::{
    AggregateSignatureError, AncillaryProverData, AncillaryVerifierData,
    proof_system::{
        NonDeterministicSnarkProverFactory, SnarkAggregateSignatureProver, SnarkClerk,
        SnarkProverFactory, SnarkVerifierData,
        ivc_halo2_snark::{proof::IvcChainInput, verifier_setup::IvcVerifierData},
    },
};
use crate::{
    AggregateVerificationKey, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters,
    Signer, SingleSignature, Stake, StmResult, VerificationKeyForConcatenation,
    proof_system::{ConcatenationClerk, ConcatenationProof},
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
    /// A factory that returns the provers necessary to create the SNARK proofs
    #[cfg(feature = "future_snark")]
    snark_prover_factory: Arc<dyn SnarkProverFactory<D> + Send + Sync>,
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
        D: Send + Sync + 'static,
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

                let mut prover = self
                    .snark_prover_factory
                    .snark_aggregate_signature_prover(&clerk.parameters)?;
                Self::aggregate_signatures_for_snark(clerk, prover.as_mut(), sigs, msg)
            }
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => {
                let snark_clerk = self
                    .get_snark_clerk()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingSnarkClerk))?;

                self.aggregate_signatures_for_ivc_snark(snark_clerk, sigs, msg, ancillary_input)
            }
        }
    }

    #[cfg(feature = "future_snark")]
    fn aggregate_signatures_for_snark(
        snark_clerk: &SnarkClerk,
        prover: &mut dyn SnarkAggregateSignatureProver<D>,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        let certificate_verifying_key = prover.verification_key().clone();
        let snark_proof =
            prover.aggregate_signatures(snark_clerk, sigs, msg).with_context(|| {
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
    fn aggregate_signatures_for_ivc_snark(
        &self,
        snark_clerk: &SnarkClerk,
        sigs: &[SingleSignature],
        msg: &[u8],
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        let mut snark_prover = self
            .snark_prover_factory
            .snark_aggregate_signature_prover(&snark_clerk.parameters)?;

        let certificate_verifying_key = snark_prover.verification_key().clone();
        let certificate_proof = snark_prover
            .aggregate_signatures(snark_clerk, sigs, msg)
            .with_context(|| {
                format!(
                    "Signatures failed to aggregate for type {}",
                    AggregateSignatureType::IvcSnark
                )
            })?;
        drop(snark_prover);

        let mut ivc_prover = self.snark_prover_factory.ivc_chain_prover(&snark_clerk.parameters)?;
        let chain_input = IvcChainInput::try_new(
            certificate_proof,
            msg,
            snark_clerk.compute_aggregate_verification_key_for_snark(),
            ancillary_input,
            &certificate_verifying_key,
            ivc_prover.verifying_key(),
        )?;
        let genesis_protocol_message_hash = chain_input.global.genesis_message;
        let (ivc_proof, next_rolling_state) = ivc_prover.advance_chain(chain_input)?;
        let verifier_data = IvcVerifierData::new(
            genesis_protocol_message_hash,
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
        AncillaryGenesisData, AncillaryProofInput, AncillaryProofOutput, AncillaryProverData,
        Clerk, MithrilMembershipDigest, Parameters, Signer, SnarkProof, StmResult,
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
            IvcRollingState, MERKLE_TREE_DEPTH_FOR_SNARK, MockSnarkAggregateSignatureProver,
            MockSnarkProverFactory, SnarkClerk,
            ivc_halo2_snark::{
                MockIvcChainProver, build_standard_rolling_state,
                proof::{IvcChainInput, IvcProof},
                verifier_setup::IvcVerifierData,
            },
        },
        protocol::aggregate_signature::tests::{
            setup_equal_parties, setup_party_without_snark_keys,
        },
    };

    const DUMMY_MESSAGE: [u8; 0] = [];

    const DUMMY_PROTOCOL_MESSAGE_PREIMAGE: [u8; PREIMAGE_SIZE] = [0u8; PREIMAGE_SIZE];

    type D = MithrilMembershipDigest;

    type ChainInputPredicate = Box<dyn Fn(&IvcChainInput<D>) -> bool + Send>;

    type ParametersPredicate = Box<dyn Fn(&Parameters) -> bool + Send>;

    const PARAMS: Parameters = Parameters {
        k: 1,
        m: 10,
        phi_f: 0.9,
    };

    /// How the mocked SNARK aggregate signature prover behaves.
    enum SnarkProverBehavior {
        /// Returns a dummy certificate proof.
        AggregatesSignatures,
        /// Returns a dummy certificate proof only if the given predicate holds for the
        /// parameters passed to the factory.
        AggregatesSignaturesWithFunction(ParametersPredicate),
        /// The factory fails to build it, with the given root cause.
        FailsToBuild(&'static str),
        /// It is built but fails to aggregate, with the given root cause.
        FailsToAggregate(&'static str),
        /// The SNARK prover is never called.
        NeverCalled,
    }

    /// How the mocked IVC chain prover behaves.
    enum IvcProverBehavior {
        /// Advances the chain and returns the given next rolling state.
        AdvancesChain(Option<IvcRollingState>),
        /// Advances the chain only if the given predicate holds for the built `IvcChainInput`,
        /// then returns the given next rolling state.
        AdvancesChainWithFunction(ChainInputPredicate, Option<IvcRollingState>),
        /// The factory fails to build it, with the given root cause.
        FailsToBuild(&'static str),
        /// It is built but fails to advance the chain, with the given root cause.
        FailsToAdvanceChain(&'static str),
        /// It must never be asked to advance the chain.
        NeverAdvancesChain,
        /// The Ivc prover is never called.
        NeverCalled,
    }

    /// Builds the [`MockSnarkProverFactory`] backing a clerk under test.
    ///
    /// Defaults to the happy path: the SNARK prover returns a dummy certificate proof and the IVC
    /// prover advances the chain without producing a next rolling state.
    struct MockProverFactory {
        /// The snark prover behavior
        snark_behavior: SnarkProverBehavior,
        /// The ivc prover behavior
        ivc_behavior: IvcProverBehavior,
    }

    impl MockProverFactory {
        fn new() -> Self {
            Self {
                snark_behavior: SnarkProverBehavior::AggregatesSignatures,
                ivc_behavior: IvcProverBehavior::AdvancesChain(None),
            }
        }

        fn snark_prover(mut self, behavior: SnarkProverBehavior) -> Self {
            self.snark_behavior = behavior;
            self
        }
        fn ivc_prover(mut self, behavior: IvcProverBehavior) -> Self {
            self.ivc_behavior = behavior;
            self
        }

        fn without_snark_prover(mut self) -> Self {
            self.snark_behavior = SnarkProverBehavior::NeverCalled;
            self
        }

        fn without_ivc_prover(mut self) -> Self {
            self.ivc_behavior = IvcProverBehavior::NeverCalled;
            self
        }

        fn build_clerk(self, signer: &Signer<D>) -> Clerk<D> {
            let mut factory = MockSnarkProverFactory::new();

            match self.snark_behavior {
                SnarkProverBehavior::AggregatesSignatures => {
                    wire_snark_prover(
                        &mut factory,
                        snark_prover_returning(Ok(dummy_snark_proof(PARAMS))),
                    );
                }
                SnarkProverBehavior::AggregatesSignaturesWithFunction(predicate) => {
                    let snark_prover = snark_prover_returning(Ok(dummy_snark_proof(PARAMS)));
                    factory
                        .expect_snark_aggregate_signature_prover()
                        .once()
                        .withf(move |actual_params| predicate(actual_params))
                        .return_once(move |_| Ok(Box::new(snark_prover)));
                }
                SnarkProverBehavior::FailsToBuild(message) => {
                    factory
                        .expect_snark_aggregate_signature_prover()
                        .once()
                        .return_once(move |_| Err(anyhow!(message)));
                }
                SnarkProverBehavior::FailsToAggregate(message) => {
                    wire_snark_prover(&mut factory, snark_prover_returning(Err(message)));
                }
                SnarkProverBehavior::NeverCalled => {}
            }

            match self.ivc_behavior {
                IvcProverBehavior::AdvancesChain(rolling_state) => {
                    let mut ivc_prover = ivc_prover_with_verifying_key();
                    ivc_prover
                        .expect_advance_chain()
                        .once()
                        .return_once(move |_| Ok((dummy_ivc_proof(), rolling_state)));
                    wire_ivc_prover(&mut factory, ivc_prover);
                }
                IvcProverBehavior::AdvancesChainWithFunction(predicate, rolling_state) => {
                    let mut ivc_prover = ivc_prover_with_verifying_key();
                    ivc_prover
                        .expect_advance_chain()
                        .once()
                        .withf(move |chain_input| predicate(chain_input))
                        .return_once(move |_| Ok((dummy_ivc_proof(), rolling_state)));
                    wire_ivc_prover(&mut factory, ivc_prover);
                }
                IvcProverBehavior::FailsToBuild(message) => {
                    factory
                        .expect_ivc_chain_prover()
                        .once()
                        .return_once(move |_| Err(anyhow!(message)));
                }
                IvcProverBehavior::FailsToAdvanceChain(message) => {
                    let mut ivc_prover = ivc_prover_with_verifying_key();
                    ivc_prover
                        .expect_advance_chain()
                        .once()
                        .return_once(move |_| Err(anyhow!(message)));
                    wire_ivc_prover(&mut factory, ivc_prover);
                }
                IvcProverBehavior::NeverAdvancesChain => {
                    let mut ivc_prover = ivc_prover_with_verifying_key();
                    ivc_prover.expect_advance_chain().never();
                    wire_ivc_prover(&mut factory, ivc_prover);
                }
                IvcProverBehavior::NeverCalled => {}
            }

            Clerk::new_clerk_from_signer_with_mock_prover_factory(signer, factory)
        }
    }

    fn wire_snark_prover(
        factory: &mut MockSnarkProverFactory<D>,
        snark_prover: MockSnarkAggregateSignatureProver<D>,
    ) {
        factory
            .expect_snark_aggregate_signature_prover()
            .once()
            .return_once(move |_| Ok(Box::new(snark_prover)));
    }

    fn wire_ivc_prover(factory: &mut MockSnarkProverFactory<D>, ivc_prover: MockIvcChainProver<D>) {
        factory
            .expect_ivc_chain_prover()
            .once()
            .return_once(move |_| Ok(Box::new(ivc_prover)));
    }

    fn snark_prover_returning(
        result: Result<SnarkProof<D>, &'static str>,
    ) -> MockSnarkAggregateSignatureProver<D> {
        let mut snark_prover = MockSnarkAggregateSignatureProver::new();
        snark_prover
            .expect_verification_key()
            .return_const(certificate_verifying_key());
        snark_prover
            .expect_aggregate_signatures()
            .once()
            .return_once(move |_, _, _| result.map_err(|message| anyhow!(message)));
        snark_prover
    }

    fn aggregate_snark(
        clerk: Clerk<D>,
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        clerk.aggregate_signatures_with_type(
            &[],
            &DUMMY_MESSAGE,
            AggregateSignatureType::Snark,
            ancillary_input,
        )
    }

    fn aggregate_ivc_with_dummy_message(
        clerk: Clerk<D>,
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        clerk.aggregate_signatures_with_type(
            &[],
            &DUMMY_MESSAGE,
            AggregateSignatureType::IvcSnark,
            ancillary_input,
        )
    }

    fn aggregate_ivc_with_message(
        clerk: Clerk<D>,
        message: &[u8],
        ancillary_input: AncillaryProofInput,
    ) -> StmResult<(AggregateSignature<D>, AncillaryProofOutput)> {
        clerk.aggregate_signatures_with_type(
            &[],
            message,
            AggregateSignatureType::IvcSnark,
            ancillary_input,
        )
    }

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

    fn dummy_snark_proof(params: Parameters) -> SnarkProof<D> {
        SnarkProof::new(vec![], params, MERKLE_TREE_DEPTH_FOR_SNARK)
    }

    fn build_ancillary_input(prover_data: Option<AncillaryProverData>) -> AncillaryProofInput {
        AncillaryProofInput::new(
            prover_data,
            AncillaryGenesisData::dummy(),
            DUMMY_PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        )
    }

    fn dummy_ivc_proof() -> IvcProof<Blake2b256> {
        IvcProof::new(
            IvcProofBytes::empty(),
            State::genesis(),
            trivial_accumulator(&[]),
        )
    }

    fn setup_single_party(params: Parameters) -> Signer<D> {
        setup_equal_parties(params, 1).into_iter().next().unwrap()
    }

    /// An IVC chain prover stub with only its verifying key set
    fn ivc_prover_with_verifying_key() -> MockIvcChainProver<D> {
        let mut ivc_prover = MockIvcChainProver::new();
        ivc_prover.expect_verifying_key().return_const(ivc_verifying_key());
        ivc_prover
    }

    #[test]
    fn ivc_aggregation_threads_next_rolling_state_into_prover_data() {
        let signer = setup_single_party(PARAMS);
        let current_rolling_state =
            build_standard_rolling_state(StepCounter::new(3), EpochNumber::new(2));
        let next_rolling_state =
            build_standard_rolling_state(StepCounter::new(4), EpochNumber::new(3));
        let expected_prover_data = AncillaryProverData::IvcSnark(next_rolling_state.clone())
            .to_bytes()
            .unwrap();

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::AdvancesChainWithFunction(
                Box::new(|step_input| {
                    step_input.message == DUMMY_MESSAGE
                        && step_input.rolling_state.as_ref().is_some_and(|rolling_state| {
                            rolling_state.state().step_counter == StepCounter::new(3)
                        })
                }),
                Some(next_rolling_state),
            ))
            .build_clerk(&signer);

        let (aggregate_signature, ancillary_output) = aggregate_ivc_with_dummy_message(
            clerk,
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
        let signer = setup_single_party(PARAMS);
        let signature = signer.create_single_signature(&DUMMY_MESSAGE).unwrap();

        let clerk = MockProverFactory::new()
            .without_snark_prover()
            .without_ivc_prover()
            .build_clerk(&signer);

        let (aggregate_signature, _ancillary_output) = clerk
            .aggregate_signatures_with_type(
                &[signature],
                &DUMMY_MESSAGE,
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
        let signer = setup_party_without_snark_keys(PARAMS, 1);
        let clerk = Clerk::new_clerk_from_signer(&signer);

        let err = aggregate_snark(clerk, build_ancillary_input(None))
            .expect_err("Should fail without Snark clerk.");

        assert_eq!(
            err.downcast_ref::<AggregateSignatureError>(),
            Some(&AggregateSignatureError::MissingSnarkClerk),
            "missing IVC Snark clerk must be rejected, got: {err}"
        );
    }

    #[test]
    fn snark_aggregation_builds_snark_prover_with_clerk_parameters() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .without_ivc_prover()
            .snark_prover(SnarkProverBehavior::AggregatesSignaturesWithFunction(
                Box::new(|actual_params| *actual_params == PARAMS),
            ))
            .build_clerk(&signer);

        let (aggregate_signature, _ancillary_output) =
            aggregate_snark(clerk, build_ancillary_input(None))
                .expect("aggregation with mocked provers should succeed");

        assert!(matches!(aggregate_signature, AggregateSignature::Snark(_)));
    }

    #[test]
    fn snark_aggregation_propagates_prover_factory_error() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .without_ivc_prover()
            .snark_prover(SnarkProverBehavior::FailsToBuild("factory error"))
            .build_clerk(&signer);

        let err = aggregate_snark(clerk, build_ancillary_input(None))
            .expect_err("factory error should propagate");

        assert_eq!(err.to_string(), "factory error");
    }

    #[test]
    fn snark_aggregation_returns_verifier_data_from_prover_key() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new().without_ivc_prover().build_clerk(&signer);

        let (aggregate_signature, ancillary_output) =
            aggregate_snark(clerk, build_ancillary_input(None))
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
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .without_ivc_prover()
            .snark_prover(SnarkProverBehavior::FailsToAggregate("prover error"))
            .build_clerk(&signer);

        let err = aggregate_snark(clerk, build_ancillary_input(None))
            .expect_err("prover error should propagate");

        assert_eq!(err.root_cause().to_string(), "prover error");
    }

    #[test]
    fn ivc_aggregation_fails_when_snark_clerk_is_missing() {
        let signer = setup_party_without_snark_keys(PARAMS, 1);
        let clerk = Clerk::new_clerk_from_signer(&signer);

        let err = aggregate_snark(clerk, build_ancillary_input(None))
            .expect_err("Should fail without Snark clerk.");

        assert_eq!(
            err.downcast_ref::<AggregateSignatureError>(),
            Some(&AggregateSignatureError::MissingSnarkClerk),
            "missing IVC Snark clerk must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_aggregation_propagates_ivc_chain_prover_factory_error() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::FailsToBuild("ivc factory error"))
            .build_clerk(&signer);

        let err = aggregate_ivc_with_dummy_message(clerk, build_ancillary_input(None))
            .expect_err("ivc factory error should propagate");

        assert_eq!(err.to_string(), "ivc factory error");
    }

    #[test]
    fn ivc_aggregation_does_not_advance_chain_on_invalid_ancillary_input() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::NeverAdvancesChain)
            .build_clerk(&signer);

        let invalid_ancillary_input = AncillaryProofInput::new(
            None,
            AncillaryGenesisData::new(vec![0u8; PREIMAGE_SIZE], None, None),
            DUMMY_PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        );

        let err = aggregate_ivc_with_dummy_message(clerk, invalid_ancillary_input)
            .expect_err("Should fail without genesis verification key.");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingGenesisVerificationKey),
            "missing genesis verification key must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_aggregation_passes_certificate_proof_message_and_avk_to_step_prover() {
        let signer = setup_single_party(PARAMS);
        let message: &[u8] = &[7, 7, 7];

        let snark_clerk = SnarkClerk::new_clerk_from_signer(&signer);
        let expected_proof_bytes = dummy_snark_proof(PARAMS).to_bytes().unwrap();
        let expected_avk = snark_clerk.compute_aggregate_verification_key_for_snark();

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::AdvancesChainWithFunction(
                Box::new(move |chain_input| {
                    chain_input.message == message
                        && chain_input.certificate_proof.to_bytes().unwrap() == expected_proof_bytes
                        && chain_input.aggregate_verification_key == expected_avk
                }),
                None,
            ))
            .build_clerk(&signer);

        aggregate_ivc_with_message(clerk, message, build_ancillary_input(None))
            .expect("aggregation with mocked provers should succeed");
    }

    #[test]
    fn ivc_aggregation_uses_snark_prover_key_for_global_and_verifier_data() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new().build_clerk(&signer);

        let (_aggregate_signature, ancillary_output) =
            aggregate_ivc_with_dummy_message(clerk, build_ancillary_input(None))
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
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new().build_clerk(&signer);

        let (_aggregate_signature, ancillary_output) =
            aggregate_ivc_with_dummy_message(clerk, build_ancillary_input(None))
                .expect("aggregation with mocked provers should succeed");

        assert!(ancillary_output.prover_data().is_none());
    }

    #[test]
    fn ivc_aggregation_propagates_snark_prover_error() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .snark_prover(SnarkProverBehavior::FailsToAggregate("SNARK prover error"))
            .without_ivc_prover()
            .build_clerk(&signer);

        let err = aggregate_ivc_with_dummy_message(clerk, build_ancillary_input(None))
            .expect_err("SNARK prover error should propagate");

        assert_eq!(err.root_cause().to_string(), "SNARK prover error");
    }

    #[test]
    fn ivc_aggregation_propagates_ivc_prover_error() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::FailsToAdvanceChain("ivc prover error"))
            .build_clerk(&signer);

        let err = aggregate_ivc_with_dummy_message(clerk, build_ancillary_input(None))
            .expect_err("ivc prover error should propagate");

        assert_eq!(err.root_cause().to_string(), "ivc prover error");
    }

    #[test]
    fn ivc_aggregation_does_not_advance_chain_when_prover_data_carries_no_ivc_rolling_state() {
        let signer = setup_single_party(PARAMS);

        let clerk = MockProverFactory::new()
            .ivc_prover(IvcProverBehavior::NeverAdvancesChain)
            .build_clerk(&signer);

        let err = aggregate_ivc_with_dummy_message(
            clerk,
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
