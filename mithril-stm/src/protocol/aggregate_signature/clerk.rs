use std::marker::PhantomData;

use anyhow::Context;
#[cfg(feature = "future_snark")]
use anyhow::anyhow;

use crate::{
    AggregateVerificationKey, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters,
    Signer, SingleSignature, Stake, StmResult, VerificationKeyForConcatenation,
    proof_system::{ConcatenationClerk, ConcatenationProof},
};

#[cfg(feature = "future_snark")]
use crate::{
    AggregateSignatureError, AncillaryVerifierData,
    proof_system::{
        MERKLE_TREE_DEPTH_FOR_SNARK, SnarkClerk, SnarkProver, SnarkVerifierData,
        ivc_halo2_snark::PreparedIvcSnarkRequest,
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

                let prepared_request =
                    PreparedIvcSnarkRequest::prepare_and_check_ivc_snark_request(
                        snark_clerk,
                        &ancillary_input,
                        msg,
                    )?;

                let (ivc_proof, next_ancillary_prover_data, ancillary_verifier_data) =
                    prepared_request.prove_ivc_snark(sigs, msg, snark_clerk)?;

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

#[cfg(feature = "future_snark")]
#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AggregationError, AncillaryGenesisData, AncillaryProofInput, AncillaryProverData,
        BaseFieldElement, Parameters, SchnorrSigningKey, SchnorrVerificationKey,
        StandardSchnorrSignature, circuits::halo2_ivc::PREIMAGE_SIZE,
        protocol::aggregate_signature::tests::setup_equal_parties,
    };

    use super::{AggregateSignatureType, Clerk};

    fn valid_genesis_verification_key_and_signature()
    -> (StandardSchnorrSignature, SchnorrVerificationKey) {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        (
            signing_key
                .sign_standard(&[BaseFieldElement::get_one()], &mut rng)
                .unwrap(),
            SchnorrVerificationKey::new_from_signing_key(signing_key),
        )
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

        let (schnorr_sig, genesis_verification_key) =
            valid_genesis_verification_key_and_signature();
        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::Future),
            AncillaryGenesisData::new(
                vec![0u8; PREIMAGE_SIZE],
                Some(schnorr_sig),
                Some(genesis_verification_key),
            ),
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
