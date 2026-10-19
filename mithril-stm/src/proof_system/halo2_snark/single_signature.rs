use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::{
    BaseFieldElement, LotteryIndex, MembershipDigest, SignerIndex, StmResult,
    UniqueSchnorrSignature, VerificationKeyForSnark,
};

use super::{AggregateVerificationKeyForSnark, build_snark_message};

/// Single signature for the Snark proof system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SingleSignatureForSnark {
    /// The underlying Schnorr signature
    schnorr_signature: UniqueSchnorrSignature,
    /// Winning lottery indices. Empty at signing time; populated later during aggregation.
    indices: Vec<LotteryIndex>,
    /// Index of the signer in the SNARK Merkle tree.
    snark_signer_index: SignerIndex,
}

impl SingleSignatureForSnark {
    /// Create and return a new instance of `SingleSignatureForSnark` for given `schnorr_signature`
    /// and `indices`.
    pub(crate) fn new(
        schnorr_signature: UniqueSchnorrSignature,
        indices: Vec<LotteryIndex>,
        snark_signer_index: SignerIndex,
    ) -> Self {
        Self {
            schnorr_signature,
            indices,
            snark_signer_index,
        }
    }

    /// Verify a `SingleSignatureForSnark`. First try to build the message to verify using the
    /// provided `AggregateVerificationKeyForSnark` and the input `message`. Then verify the Schnorr
    /// signature for the built message and the provided `VerificationKeyForSnark`. The lottery
    /// eligibility check is not performed in this function, as it is expected to be done
    /// in the witness preparation.
    pub(crate) fn verify<D: MembershipDigest>(
        &self,
        verification_key: &VerificationKeyForSnark,
        message: &[u8],
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
    ) -> StmResult<()> {
        let message_to_verify = build_snark_message(
            &aggregate_verification_key.get_merkle_tree_commitment().root,
            message,
        )?;
        self.schnorr_signature
            .verify(&message_to_verify, verification_key)
            .with_context(|| "Schnorr signature verification failed for SNARK proof system.")?;

        Ok(())
    }

    /// Verify a `SingleSignatureForSnark` against a pre-computed message.
    ///
    /// Unlike `verify`, this skips the `build_snark_message` step and verifies the Schnorr
    /// signature directly against the provided `message_to_sign`. Use this when the caller has
    /// already built the message (in a loop over many signatures sharing the same avk).
    pub(crate) fn verify_with_prepared_message(
        &self,
        verification_key: &VerificationKeyForSnark,
        message_to_sign: &[BaseFieldElement; 2],
    ) -> StmResult<()> {
        self.schnorr_signature
            .verify(message_to_sign, verification_key)
            .with_context(|| "Schnorr signature verification failed for SNARK proof system.")?;

        Ok(())
    }

    /// Return `indices` of the single signature
    pub(crate) fn get_indices(&self) -> &[LotteryIndex] {
        &self.indices
    }

    /// Set `indices` of single signature to given value
    pub(crate) fn set_indices(&mut self, indices: &[LotteryIndex]) {
        self.indices = indices.to_vec();
    }

    /// Return `schnorr_signature` of single signature
    pub(crate) fn get_schnorr_signature(&self) -> UniqueSchnorrSignature {
        self.schnorr_signature
    }

    /// Return the index of the signer in the SNARK Merkle tree
    pub(crate) fn get_snark_signer_index(&self) -> SignerIndex {
        self.snark_signer_index
    }
}

impl Hash for SingleSignatureForSnark {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.schnorr_signature.hash(state);
    }
}

impl PartialEq for SingleSignatureForSnark {
    fn eq(&self, other: &Self) -> bool {
        self.schnorr_signature == other.schnorr_signature
    }
}

impl Eq for SingleSignatureForSnark {}
