use std::cmp::Ordering;

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

use crate::{
    LotteryIndex, MembershipDigest, Parameters, SignatureError, Stake, StmResult,
    VerificationKeyForConcatenation, proof_system::AggregateVerificationKeyForConcatenation,
    signature_scheme::BlsSignature,
};

use super::is_lottery_won;

/// Single signature for the concatenation proof system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SingleSignatureForConcatenation {
    /// The underlying BLS signature
    sigma: BlsSignature,
    /// The index(es) for which the signature is valid
    indexes: Vec<LotteryIndex>,
}

impl SingleSignatureForConcatenation {
    /// Create and return a new instance of `SingleSignatureForConcatenation` for given `sigma` and
    /// `indexes`.
    pub(crate) fn new(sigma: BlsSignature, indexes: Vec<LotteryIndex>) -> Self {
        Self { sigma, indexes }
    }

    /// Verify a `SingleSignatureForConcatenation` by validating the underlying BLS signature and checking
    /// that the lottery was won for all indexes.
    pub(crate) fn verify<D: MembershipDigest>(
        &self,
        params: &Parameters,
        pk: &VerificationKeyForConcatenation,
        stake: &Stake,
        avk: &AggregateVerificationKeyForConcatenation<D>,
        msg: &[u8],
    ) -> StmResult<()> {
        let msgp = avk.get_merkle_tree_batch_commitment().concatenate_with_message(msg);
        self.sigma.verify(&msgp, pk).with_context(
            || "Single signature verification failed for concatenation proof system.",
        )?;
        self.check_indices(params, stake, &msgp, &avk.get_total_stake())
            .with_context(
                || {
                format!(
                    "Single signature verification failed for concatenation proof system; indexes: {:?}",
                    self.indexes
                )
            })?;
        Ok(())
    }

    /// Verify that all indices of single signature are valid by checking bounds and lottery win.
    pub(crate) fn check_indices(
        &self,
        params: &Parameters,
        stake: &Stake,
        msg: &[u8],
        total_stake: &Stake,
    ) -> StmResult<()> {
        for &index in &self.indexes {
            if index > params.m {
                return Err(anyhow!(SignatureError::IndexBoundFailed(index, params.m)));
            }

            let ev = self.sigma.evaluate_dense_mapping(msg, index);

            if !is_lottery_won(params.phi_f, ev, *stake, *total_stake)? {
                return Err(anyhow!(SignatureError::LotteryLost));
            }
        }
        Ok(())
    }

    /// Return `indices` of the single signature
    pub(crate) fn get_indices(&self) -> &[LotteryIndex] {
        &self.indexes
    }

    /// Set `indexes` of single signature to given `indices`
    pub(crate) fn set_indices(&mut self, indices: &[LotteryIndex]) {
        self.indexes = indices.to_vec()
    }

    /// Return `sigma` of single signature
    pub(crate) fn get_sigma(&self) -> BlsSignature {
        self.sigma
    }
}

impl PartialEq for SingleSignatureForConcatenation {
    fn eq(&self, other: &Self) -> bool {
        self.sigma == other.sigma
    }
}

impl Eq for SingleSignatureForConcatenation {}

impl PartialOrd for SingleSignatureForConcatenation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for SingleSignatureForConcatenation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sigma.cmp(&other.sigma)
    }
}
