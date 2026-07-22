use anyhow::anyhow;

use crate::{
    MembershipDigest, Parameters, RegistrationEntryForConcatenation, SignatureError, Stake,
    StmResult, VerificationKeyForConcatenation,
    membership_commitment::MerkleTreeBatchCommitment,
    signature_scheme::{BlsSignature, BlsSigningKey},
};

use super::{SingleSignatureForConcatenation, is_lottery_won};

/// Concatenation Proof single signature generator.
/// Contains the signer's stake and signing key besides the total stake of the closed registration,
/// protocol parameters, and the Merkle Tree commitment of the key registration for concatenation
/// proof.
#[derive(Debug, Clone)]
pub(crate) struct ConcatenationProofSigner<D: MembershipDigest> {
    pub(crate) stake: Stake,
    total_stake: Stake,
    parameters: Parameters,
    signing_key: BlsSigningKey,
    verification_key: VerificationKeyForConcatenation,
    key_registration_commitment:
        MerkleTreeBatchCommitment<D::ConcatenationHash, RegistrationEntryForConcatenation>,
}

impl<D: MembershipDigest> ConcatenationProofSigner<D> {
    /// Generates a new instance of `ConcatenationProofSigner`
    pub fn new(
        stake: Stake,
        total_stake: Stake,
        parameters: Parameters,
        signing_key: BlsSigningKey,
        verification_key: VerificationKeyForConcatenation,
        key_registration_commitment: MerkleTreeBatchCommitment<
            D::ConcatenationHash,
            RegistrationEntryForConcatenation,
        >,
    ) -> Self {
        Self {
            stake,
            total_stake,
            parameters,
            signing_key,
            verification_key,
            key_registration_commitment,
        }
    }

    /// Generates a single signature for concatenation proof system.
    /// First, concatenates the given message with the Merkle tree commitment. Then, generates a bls
    /// signature for the `message_with_commitment`. Checks the lottery and collects the winning
    /// indices. If there is no winning indices, returns an error. Otherwise, returns
    /// `SingleSignatureForConcatenation`.
    pub fn create_single_signature(
        &self,
        message: &[u8],
    ) -> StmResult<SingleSignatureForConcatenation> {
        let message_with_commitment =
            self.key_registration_commitment.concatenate_with_message(message);

        let sigma = self.signing_key.sign(&message_with_commitment);
        let indices = self.check_lottery(&message_with_commitment, &sigma)?;

        if indices.is_empty() {
            Err(anyhow!(SignatureError::LotteryLost))
        } else {
            Ok(SingleSignatureForConcatenation::new(sigma, indices))
        }
    }

    /// Checks the lottery for given `message_with_commitment` and the `sigma`.
    /// Returns a vector of winning indices.
    pub fn check_lottery(
        &self,
        message_with_commitment: &[u8],
        sigma: &BlsSignature,
    ) -> StmResult<Vec<u64>> {
        let mut indices = Vec::new();
        for index in 0..self.parameters.m {
            if is_lottery_won(
                self.parameters.phi_f,
                sigma.evaluate_dense_mapping(message_with_commitment, index),
                self.stake,
                self.total_stake,
            )? {
                indices.push(index);
            }
        }
        Ok(indices)
    }

    pub fn get_verification_key(&self) -> VerificationKeyForConcatenation {
        self.verification_key
    }
}
