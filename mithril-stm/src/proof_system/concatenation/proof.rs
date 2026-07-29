use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    AggregateSignatureError, AggregationError, MembershipDigest, Parameters,
    RegistrationEntryForConcatenation, SingleSignature, SingleSignatureWithRegisteredParty,
    StmResult, VerificationKeyForConcatenation, codec,
    membership_commitment::MerkleBatchPath,
    proof_system::{AggregateVerificationKeyForConcatenation, ConcatenationClerk},
    signature_scheme::BlsSignature,
};

/// CBOR-friendly envelope for `ConcatenationProof` serialization.
///
/// Used as an intermediate representation because `ConcatenationProof` contains
/// types with custom `Serialize` implementations (tuple format) that are
/// incompatible with ciborium's derived `Deserialize` (which expects map format).
/// Each sub-component is stored as pre-serialized bytes to avoid this mismatch.
#[derive(Serialize, Deserialize)]
struct ConcatenationProofCborEnvelope {
    signature_bytes: Vec<Vec<u8>>,
    batch_proof_bytes: Vec<u8>,
}

/// `ConcatenationProof` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "MerkleBatchPath<D::ConcatenationHash>: Serialize",
    deserialize = "MerkleBatchPath<D::ConcatenationHash>: Deserialize<'de>"
))]
pub struct ConcatenationProof<D: MembershipDigest> {
    pub(crate) signatures: Vec<SingleSignatureWithRegisteredParty>,
    /// The list of unique merkle tree nodes that covers path for all signatures.
    pub batch_proof: MerkleBatchPath<D::ConcatenationHash>,
}

impl<D: MembershipDigest> ConcatenationProof<D> {
    /// Aggregate a set of signatures for their corresponding indices.
    ///
    /// This function first deduplicates the repeated signatures, and if there are enough signatures, it collects the merkle tree indexes of unique signatures.
    /// The list of merkle tree indexes is used to create a batch proof, to prove that all signatures are from eligible signers.
    ///
    /// It returns an instance of `ConcatenationProof`.
    pub fn aggregate_signatures(
        clerk: &ConcatenationClerk,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> StmResult<ConcatenationProof<D>> {
        let sig_reg_list = sigs
            .iter()
            .map(|sig| {
                clerk
                    .closed_key_registration
                    .get_registration_entry_for_index(&sig.signer_index)
                    .map(|reg_party| {
                        #[cfg(feature = "future_snark")]
                        // We need to remove the SNARK fields from the registration entry used in Concatenation proofs to avoid breaking change with previous client not able to parse the aggregate signature.
                        // This happens because of the way the `ClosedRegistrationEntry` is serialized with an array representation instead of map representation.
                        let reg_party = reg_party.without_snark_fields();
                        SingleSignatureWithRegisteredParty {
                            sig: sig.clone(),
                            reg_party,
                        }
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let avk: AggregateVerificationKeyForConcatenation<D> =
            clerk.compute_aggregate_verification_key_for_concatenation();
        let mut unique_sigs = ConcatenationClerk::select_valid_signatures_for_k_indices(
            &clerk.parameters,
            msg,
            &sig_reg_list,
            &avk,
        )
        .with_context(
            || "Failed to aggregate unique signatures during selection for the k indices.",
        )?;

        unique_sigs.sort_unstable();

        let mt_index_list = unique_sigs
            .iter()
            .map(|sig_reg| sig_reg.sig.signer_index as usize)
            .collect::<Vec<usize>>();

        let batch_proof = clerk
            .closed_key_registration
            .to_merkle_tree::<D::ConcatenationHash, RegistrationEntryForConcatenation>()
            .compute_merkle_tree_batch_path(mt_index_list);

        Ok(Self {
            signatures: unique_sigs,
            batch_proof,
        })
    }

    /// Verify all checks from signatures, except for the signature verification itself.
    ///
    /// Checks that each signature contains only valid indices, the lottery is indeed won by each
    /// one of them. Validates whether all collected indices are unique and at least `k` are present.
    /// It collects leaves from signatures and checks the batch proof.
    /// After batch proof is checked, it collects and returns the signatures and
    /// verification keys to be used by aggregate verification.
    fn preliminary_verify(
        &self,
        msg: &[u8],
        avk: &AggregateVerificationKeyForConcatenation<D>,
        parameters: &Parameters,
    ) -> StmResult<(Vec<BlsSignature>, Vec<VerificationKeyForConcatenation>)> {
        let msgp = avk.get_merkle_tree_batch_commitment().concatenate_with_message(msg);

        let mut nr_indices = 0;
        let mut unique_indices = HashSet::new();

        for sig_reg in self.signatures.clone() {
            sig_reg
                .sig
                .check_indices(
                    parameters,
                    &sig_reg.reg_party.get_stake(),
                    &msgp,
                    &avk.get_total_stake(),
                )
                .with_context(|| "Preliminary verification for basic verifier failed.")?;
            for &index in &sig_reg.sig.get_concatenation_signature_indices() {
                unique_indices.insert(index);
                nr_indices += 1;
            }
        }

        if nr_indices != unique_indices.len() {
            return Err(anyhow!(AggregationError::IndexNotUnique));
        }
        if (nr_indices as u64) < parameters.k {
            return Err(anyhow!(AggregationError::NotEnoughSignatures(
                nr_indices as u64,
                parameters.k
            )));
        }

        let leaves = self
            .signatures
            .iter()
            .filter_map(|r| r.reg_party.clone().into())
            .collect::<Vec<RegistrationEntryForConcatenation>>();

        avk.get_merkle_tree_batch_commitment()
            .verify_leaves_membership_from_batch_path(&leaves, &self.batch_proof)
            .with_context(|| "Batch proof is invalid in preliminary verification.")?;

        Ok(self.collect_signatures_verification_keys())
    }

    /// Verify concatenation proof, by checking that
    /// * each signature contains only valid indices,
    /// * the lottery is indeed won by each one of them,
    /// * the merkle tree path is valid,
    /// * the aggregate signature validates with respect to the aggregate verification key
    ///   (aggregation is computed using functions `MSP.BKey` and `MSP.BSig` as described in Section 2.4 of the paper).
    pub fn verify(
        &self,
        msg: &[u8],
        avk: &AggregateVerificationKeyForConcatenation<D>,
        parameters: &Parameters,
    ) -> StmResult<()> {
        let msgp = avk.get_merkle_tree_batch_commitment().concatenate_with_message(msg);
        let (sigs, vks) = self
            .preliminary_verify(msg, avk, parameters)
            .with_context(|| "Aggregate signature verification failed")?;

        BlsSignature::verify_aggregate(msgp.as_slice(), &vks, &sigs)
            .with_context(|| "Aggregate signature verification failed")?;
        Ok(())
    }

    /// Batch verify a set of signatures, with different messages and avks.
    pub fn batch_verify(
        stm_signatures: &[Self],
        msgs: &[Vec<u8>],
        avks: &[AggregateVerificationKeyForConcatenation<D>],
        parameters: &[Parameters],
    ) -> StmResult<()> {
        let batch_size = stm_signatures.len();
        assert_eq!(
            batch_size,
            msgs.len(),
            "Number of messages should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            avks.len(),
            "Number of avks should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            parameters.len(),
            "Number of parameters should correspond to size of the batch"
        );

        let mut aggr_sigs = Vec::with_capacity(batch_size);
        let mut aggr_vks = Vec::with_capacity(batch_size);
        for (idx, sig_group) in stm_signatures.iter().enumerate() {
            sig_group.preliminary_verify(&msgs[idx], &avks[idx], &parameters[idx])?;
            let grouped_sigs: Vec<BlsSignature> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.sig.get_concatenation_signature_sigma())
                .collect();
            let grouped_vks: Vec<VerificationKeyForConcatenation> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.reg_party.get_verification_key_for_concatenation())
                .collect();

            let (aggr_vk, aggr_sig) = BlsSignature::aggregate(&grouped_vks, &grouped_sigs).unwrap();
            aggr_sigs.push(aggr_sig);
            aggr_vks.push(aggr_vk);
        }

        let concat_msgs: Vec<Vec<u8>> = msgs
            .iter()
            .zip(avks.iter())
            .map(|(msg, avk)| avk.get_merkle_tree_batch_commitment().concatenate_with_message(msg))
            .collect();

        BlsSignature::batch_verify_aggregates(&concat_msgs, &aggr_vks, &aggr_sigs)?;
        Ok(())
    }

    /// Convert concatenation proof to CBOR bytes with a version prefix.
    ///
    /// Uses an intermediate envelope struct to avoid ciborium incompatibility
    /// with nested types that use custom tuple-based `Serialize` implementations.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        let envelope = ConcatenationProofCborEnvelope {
            signature_bytes: self
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.to_bytes())
                .collect::<StmResult<Vec<_>>>()?,
            batch_proof_bytes: self.batch_proof.to_bytes()?,
        };
        codec::to_cbor_bytes(&envelope)
    }

    /// Extract a concatenation proof from a byte slice.
    ///
    /// Supports both the new versioned CBOR format and the legacy byte-packed format.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<ConcatenationProof<D>> {
        if codec::has_cbor_v1_prefix(bytes) {
            let envelope: ConcatenationProofCborEnvelope = codec::from_cbor_bytes(&bytes[1..])?;
            let signatures = envelope
                .signature_bytes
                .iter()
                .map(|sig_bytes| SingleSignatureWithRegisteredParty::from_bytes::<D>(sig_bytes))
                .collect::<StmResult<Vec<_>>>()?;
            let batch_proof = MerkleBatchPath::from_bytes(&envelope.batch_proof_bytes)?;
            Ok(ConcatenationProof {
                signatures,
                batch_proof,
            })
        } else {
            Self::from_bytes_legacy(bytes)
        }
    }

    /// Extract a concatenation proof from a byte slice using the legacy format.
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<ConcatenationProof<D>> {
        let mut bytes_index = 0;

        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(
            bytes
                .get(bytes_index..bytes_index + 8)
                .ok_or(AggregateSignatureError::SerializationError)?,
        );
        let total_sigs = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| AggregateSignatureError::SerializationError)?;
        bytes_index += 8;

        let mut sig_reg_list = Vec::new();
        for _ in 0..total_sigs {
            let size_field_end = bytes_index
                .checked_add(8)
                .ok_or(AggregateSignatureError::SerializationError)?;
            u64_bytes.copy_from_slice(
                bytes
                    .get(bytes_index..size_field_end)
                    .ok_or(AggregateSignatureError::SerializationError)?,
            );
            let sig_reg_size = usize::try_from(u64::from_be_bytes(u64_bytes))
                .map_err(|_| AggregateSignatureError::SerializationError)?;
            let sig_reg_end = size_field_end
                .checked_add(sig_reg_size)
                .ok_or(AggregateSignatureError::SerializationError)?;
            let sig_reg = SingleSignatureWithRegisteredParty::from_bytes::<D>(
                bytes
                    .get(size_field_end..sig_reg_end)
                    .ok_or(AggregateSignatureError::SerializationError)?,
            )?;
            bytes_index = sig_reg_end;
            sig_reg_list.push(sig_reg);
        }

        let batch_proof = MerkleBatchPath::from_bytes(
            bytes
                .get(bytes_index..)
                .ok_or(AggregateSignatureError::SerializationError)?,
        )?;

        Ok(ConcatenationProof {
            signatures: sig_reg_list,
            batch_proof,
        })
    }

    /// Collect and return `Vec<BlsSignature>, Vec<BlsVerificationKey>` which will be used
    /// by the aggregate verification.
    pub(crate) fn collect_signatures_verification_keys(
        &self,
    ) -> (Vec<BlsSignature>, Vec<VerificationKeyForConcatenation>) {
        let sigs = self
            .signatures
            .iter()
            .map(|sig_reg| sig_reg.sig.get_concatenation_signature_sigma())
            .collect::<Vec<BlsSignature>>();
        let vks = self
            .signatures
            .iter()
            .map(|sig_reg| sig_reg.reg_party.get_verification_key_for_concatenation())
            .collect::<Vec<VerificationKeyForConcatenation>>();

        (sigs, vks)
    }
}

#[cfg(test)]
mod tests {
    mod golden_cbor {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::{
            AggregateSignatureType, AncillaryProofInput, Clerk, KeyRegistration,
            MithrilMembershipDigest, Parameters, RegistrationEntry, Signer,
            VerificationKeyProofOfPossessionForConcatenation,
            proof_system::ConcatenationProofSigner, protocol::AggregateSignature,
            signature_scheme::BlsSigningKey,
        };

        type D = MithrilMembershipDigest;

        fn golden_aggregate_signature() -> AggregateSignature<D> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let msg = [0u8; 16];
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let sk_1 = BlsSigningKey::generate(&mut rng);
            let sk_2 = BlsSigningKey::generate(&mut rng);
            let pk_1 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_1);
            let pk_2 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_2);

            let mut key_reg = KeyRegistration::initialize();
            let entry1 = RegistrationEntry::new(
                pk_1,
                1,
                #[cfg(feature = "future_snark")]
                None,
            )
            .unwrap();
            let entry2 = RegistrationEntry::new(
                pk_2,
                1,
                #[cfg(feature = "future_snark")]
                None,
            )
            .unwrap();

            key_reg.register_by_entry(&entry1).unwrap();
            key_reg.register_by_entry(&entry2).unwrap();
            let closed_key_reg = key_reg.close_registration(&params).unwrap();

            let clerk = Clerk::new_clerk_from_closed_key_registration(&params, &closed_key_reg);

            let signer_1: Signer<D> = Signer::new(
                0,
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    pk_1.vk,
                    closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment(),
                ),
                closed_key_reg.clone(),
                params,
                1,
                #[cfg(feature = "future_snark")]
                None,
            );

            let signer_2: Signer<D> = Signer::new(
                1,
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_2,
                    pk_2.vk,
                    closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment(),
                ),
                closed_key_reg.clone(),
                params,
                1,
                #[cfg(feature = "future_snark")]
                None,
            );
            let signature_1 = signer_1.create_single_signature(&msg).unwrap();
            let signature_2 = signer_2.create_single_signature(&msg).unwrap();

            let (signature, _ancillary_proof_output) = clerk
                .aggregate_signatures_with_type(
                    &[signature_1, signature_2],
                    &msg,
                    AggregateSignatureType::Concatenation,
                    AncillaryProofInput::dummy(),
                )
                .unwrap();
            signature
        }

        const GOLDEN_CBOR_BYTES: &[u8; 2974] = &[
            1, 162, 111, 115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 98, 121, 116, 101, 115,
            130, 153, 2, 218, 1, 24, 162, 24, 111, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97, 24,
            116, 24, 117, 24, 114, 24, 101, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24,
            152, 24, 131, 1, 24, 24, 24, 191, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 105,
            24, 24, 24, 103, 24, 24, 24, 109, 24, 24, 24, 97, 24, 24, 24, 152, 24, 24, 24, 48, 24,
            24, 24, 24, 24, 24, 24, 149, 24, 24, 24, 24, 24, 24, 24, 157, 24, 24, 24, 24, 24, 24,
            24, 201, 24, 24, 24, 24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 140, 24, 24, 24,
            24, 24, 24, 24, 54, 0, 24, 24, 24, 24, 24, 24, 24, 128, 24, 24, 24, 24, 24, 24, 24,
            209, 24, 24, 24, 24, 24, 24, 24, 88, 16, 24, 24, 24, 24, 24, 24, 24, 203, 24, 24, 24,
            24, 24, 24, 24, 61, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 77, 24,
            24, 24, 24, 24, 24, 24, 98, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24,
            24, 133, 24, 24, 24, 24, 24, 24, 24, 58, 24, 24, 24, 24, 24, 24, 24, 152, 24, 24, 24,
            24, 24, 24, 24, 29, 24, 24, 24, 24, 24, 24, 24, 74, 24, 24, 24, 24, 24, 24, 24, 217,
            24, 24, 24, 24, 24, 24, 24, 113, 24, 24, 24, 24, 24, 24, 24, 64, 24, 24, 24, 24, 24,
            24, 24, 100, 10, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24, 24, 186, 24,
            24, 24, 24, 24, 24, 24, 167, 24, 24, 24, 24, 24, 24, 24, 133, 24, 24, 24, 24, 24, 24,
            24, 114, 24, 24, 24, 24, 24, 24, 24, 211, 24, 24, 24, 24, 24, 24, 24, 153, 24, 24, 24,
            24, 24, 24, 24, 218, 24, 24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24, 24, 24, 24, 223,
            24, 24, 24, 24, 24, 24, 24, 84, 24, 24, 24, 24, 24, 24, 24, 105, 24, 24, 24, 24, 24,
            24, 24, 242, 24, 24, 24, 24, 24, 24, 24, 41, 24, 24, 24, 24, 24, 24, 24, 54, 24, 24,
            24, 24, 24, 24, 24, 224, 24, 24, 24, 24, 24, 24, 24, 170, 24, 24, 24, 24, 24, 24, 24,
            208, 24, 24, 24, 24, 24, 24, 24, 185, 24, 24, 24, 24, 24, 24, 24, 126, 24, 24, 24, 24,
            24, 24, 24, 83, 24, 24, 24, 103, 24, 24, 24, 105, 24, 24, 24, 110, 24, 24, 24, 100, 24,
            24, 24, 101, 24, 24, 24, 120, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 132, 1, 4,
            5, 8, 24, 24, 24, 108, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24, 24, 103, 24, 24, 24,
            110, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24, 95, 24, 24, 24, 105, 24, 24, 24,
            110, 24, 24, 24, 100, 24, 24, 24, 101, 24, 24, 24, 120, 0, 24, 24, 24, 255, 24, 120,
            24, 24, 24, 114, 24, 101, 24, 103, 24, 105, 24, 115, 24, 116, 24, 114, 24, 97, 24, 116,
            24, 105, 24, 111, 24, 110, 24, 95, 24, 101, 24, 110, 24, 116, 24, 114, 24, 121, 24, 95,
            24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 219, 1, 24, 24, 24, 162, 24,
            24, 24, 118, 24, 24, 24, 118, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24, 105, 24,
            24, 24, 102, 24, 24, 24, 105, 24, 24, 24, 99, 24, 24, 24, 97, 24, 24, 24, 116, 24, 24,
            24, 105, 24, 24, 24, 111, 24, 24, 24, 110, 24, 24, 24, 95, 24, 24, 24, 107, 24, 24, 24,
            101, 24, 24, 24, 121, 24, 24, 24, 95, 24, 24, 24, 98, 24, 24, 24, 121, 24, 24, 24, 116,
            24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 152, 24, 24, 24, 96, 24, 24, 24, 24, 24,
            24, 24, 143, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24, 24, 255, 24, 24,
            24, 24, 24, 24, 24, 48, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 57,
            24, 24, 24, 24, 24, 24, 24, 204, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24,
            24, 24, 25, 24, 24, 24, 24, 24, 24, 24, 221, 24, 24, 24, 24, 24, 24, 24, 164, 24, 24,
            24, 24, 24, 24, 24, 252, 24, 24, 24, 24, 24, 24, 24, 248, 14, 24, 24, 24, 24, 24, 24,
            24, 56, 24, 24, 24, 24, 24, 24, 24, 126, 24, 24, 24, 24, 24, 24, 24, 186, 24, 24, 24,
            24, 24, 24, 24, 135, 24, 24, 24, 24, 24, 24, 24, 228, 24, 24, 24, 24, 24, 24, 24, 188,
            24, 24, 24, 24, 24, 24, 24, 145, 24, 24, 24, 24, 24, 24, 24, 181, 24, 24, 24, 24, 24,
            24, 24, 52, 24, 24, 24, 24, 24, 24, 24, 200, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24,
            24, 24, 24, 24, 24, 99, 24, 24, 24, 24, 24, 24, 24, 213, 24, 24, 24, 24, 24, 24, 24,
            46, 0, 24, 24, 24, 24, 24, 24, 24, 199, 24, 24, 24, 24, 24, 24, 24, 193, 24, 24, 24,
            24, 24, 24, 24, 89, 24, 24, 24, 24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 88,
            24, 24, 24, 24, 24, 24, 24, 29, 24, 24, 24, 24, 24, 24, 24, 135, 24, 24, 24, 24, 24,
            24, 24, 173, 24, 24, 24, 24, 24, 24, 24, 244, 24, 24, 24, 24, 24, 24, 24, 86, 24, 24,
            24, 24, 24, 24, 24, 36, 24, 24, 24, 24, 24, 24, 24, 83, 24, 24, 24, 24, 24, 24, 24, 54,
            24, 24, 24, 24, 24, 24, 24, 67, 24, 24, 24, 24, 24, 24, 24, 164, 6, 24, 24, 24, 24, 24,
            24, 24, 137, 24, 24, 24, 24, 24, 24, 24, 94, 24, 24, 24, 24, 24, 24, 24, 72, 6, 24, 24,
            24, 24, 24, 24, 24, 105, 24, 24, 24, 24, 24, 24, 24, 128, 24, 24, 24, 24, 24, 24, 24,
            128, 24, 24, 24, 24, 24, 24, 24, 93, 24, 24, 24, 24, 24, 24, 24, 48, 24, 24, 24, 24,
            24, 24, 24, 176, 11, 4, 24, 24, 24, 24, 24, 24, 24, 246, 24, 24, 24, 24, 24, 24, 24,
            138, 24, 24, 24, 24, 24, 24, 24, 48, 24, 24, 24, 24, 24, 24, 24, 180, 24, 24, 24, 24,
            24, 24, 24, 133, 24, 24, 24, 24, 24, 24, 24, 90, 24, 24, 24, 24, 24, 24, 24, 142, 24,
            24, 24, 24, 24, 24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
            24, 193, 24, 24, 24, 24, 24, 24, 24, 111, 24, 24, 24, 24, 24, 24, 24, 142, 24, 24, 24,
            24, 24, 24, 24, 31, 24, 24, 24, 24, 24, 24, 24, 76, 24, 24, 24, 24, 24, 24, 24, 111,
            24, 24, 24, 24, 24, 24, 24, 110, 24, 24, 24, 24, 24, 24, 24, 234, 24, 24, 24, 24, 24,
            24, 24, 153, 24, 24, 24, 24, 24, 24, 24, 90, 24, 24, 24, 24, 24, 24, 24, 208, 24, 24,
            24, 24, 24, 24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 31, 24, 24, 24, 24, 24, 24, 24,
            124, 24, 24, 24, 24, 24, 24, 24, 95, 24, 24, 24, 24, 24, 24, 24, 102, 24, 24, 24, 24,
            24, 24, 24, 49, 24, 24, 24, 24, 24, 24, 24, 158, 24, 24, 24, 24, 24, 24, 24, 99, 24,
            24, 24, 24, 24, 24, 24, 52, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24, 24,
            24, 165, 24, 24, 24, 24, 24, 24, 24, 94, 24, 24, 24, 24, 24, 24, 24, 251, 24, 24, 24,
            24, 24, 24, 24, 68, 24, 24, 24, 24, 24, 24, 24, 69, 24, 24, 24, 24, 24, 24, 24, 121,
            16, 24, 24, 24, 24, 24, 24, 24, 224, 24, 24, 24, 24, 24, 24, 24, 194, 24, 24, 24, 101,
            24, 24, 24, 115, 24, 24, 24, 116, 24, 24, 24, 97, 24, 24, 24, 107, 24, 24, 24, 101, 1,
            153, 2, 214, 1, 24, 162, 24, 111, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97, 24, 116,
            24, 117, 24, 114, 24, 101, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152,
            24, 128, 1, 24, 24, 24, 191, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24,
            24, 103, 24, 24, 24, 109, 24, 24, 24, 97, 24, 24, 24, 152, 24, 24, 24, 48, 24, 24, 24,
            24, 24, 24, 24, 149, 24, 24, 24, 24, 24, 24, 24, 169, 22, 24, 24, 24, 24, 24, 24, 24,
            201, 24, 24, 24, 24, 24, 24, 24, 216, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24,
            24, 24, 24, 163, 24, 24, 24, 24, 24, 24, 24, 188, 24, 24, 24, 24, 24, 24, 24, 115, 24,
            24, 24, 24, 24, 24, 24, 210, 24, 24, 24, 24, 24, 24, 24, 217, 24, 24, 24, 24, 24, 24,
            24, 236, 24, 24, 24, 24, 24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24,
            24, 24, 24, 24, 201, 13, 24, 24, 24, 24, 24, 24, 24, 42, 24, 24, 24, 24, 24, 24, 24,
            132, 12, 24, 24, 24, 24, 24, 24, 24, 63, 5, 24, 24, 24, 24, 24, 24, 24, 31, 24, 24, 24,
            24, 24, 24, 24, 120, 22, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24,
            177, 24, 24, 24, 24, 24, 24, 24, 125, 24, 24, 24, 24, 24, 24, 24, 134, 24, 24, 24, 24,
            24, 24, 24, 208, 24, 24, 24, 24, 24, 24, 24, 205, 24, 24, 24, 24, 24, 24, 24, 73, 24,
            24, 24, 24, 24, 24, 24, 58, 24, 24, 24, 24, 24, 24, 24, 247, 24, 24, 24, 24, 24, 24,
            24, 141, 24, 24, 24, 24, 24, 24, 24, 59, 24, 24, 24, 24, 24, 24, 24, 62, 24, 24, 24,
            24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 81, 24, 24, 24, 24, 24, 24, 24, 213,
            24, 24, 24, 24, 24, 24, 24, 30, 24, 24, 24, 24, 24, 24, 24, 153, 24, 24, 24, 24, 24,
            24, 24, 218, 24, 24, 24, 24, 24, 24, 24, 41, 24, 24, 24, 24, 24, 24, 24, 42, 24, 24,
            24, 24, 24, 24, 24, 110, 24, 24, 24, 24, 24, 24, 24, 156, 24, 24, 24, 24, 24, 24, 24,
            161, 24, 24, 24, 24, 24, 24, 24, 205, 24, 24, 24, 103, 24, 24, 24, 105, 24, 24, 24,
            110, 24, 24, 24, 100, 24, 24, 24, 101, 24, 24, 24, 120, 24, 24, 24, 101, 24, 24, 24,
            115, 24, 24, 24, 131, 0, 3, 6, 24, 24, 24, 108, 24, 24, 24, 115, 24, 24, 24, 105, 24,
            24, 24, 103, 24, 24, 24, 110, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24, 95, 24, 24,
            24, 105, 24, 24, 24, 110, 24, 24, 24, 100, 24, 24, 24, 101, 24, 24, 24, 120, 1, 24, 24,
            24, 255, 24, 120, 24, 24, 24, 114, 24, 101, 24, 103, 24, 105, 24, 115, 24, 116, 24,
            114, 24, 97, 24, 116, 24, 105, 24, 111, 24, 110, 24, 95, 24, 101, 24, 110, 24, 116, 24,
            114, 24, 121, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 220, 1,
            24, 24, 24, 162, 24, 24, 24, 118, 24, 24, 24, 118, 24, 24, 24, 101, 24, 24, 24, 114,
            24, 24, 24, 105, 24, 24, 24, 102, 24, 24, 24, 105, 24, 24, 24, 99, 24, 24, 24, 97, 24,
            24, 24, 116, 24, 24, 24, 105, 24, 24, 24, 111, 24, 24, 24, 110, 24, 24, 24, 95, 24, 24,
            24, 107, 24, 24, 24, 101, 24, 24, 24, 121, 24, 24, 24, 95, 24, 24, 24, 98, 24, 24, 24,
            121, 24, 24, 24, 116, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 152, 24, 24, 24,
            96, 24, 24, 24, 24, 24, 24, 24, 145, 24, 24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24,
            24, 24, 24, 175, 24, 24, 24, 24, 24, 24, 24, 32, 24, 24, 24, 24, 24, 24, 24, 122, 24,
            24, 24, 24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 214, 24, 24, 24, 24, 24, 24,
            24, 226, 24, 24, 24, 24, 24, 24, 24, 251, 24, 24, 24, 24, 24, 24, 24, 148, 24, 24, 24,
            24, 24, 24, 24, 88, 9, 1, 24, 24, 24, 24, 24, 24, 24, 103, 24, 24, 24, 24, 24, 24, 24,
            159, 24, 24, 24, 24, 24, 24, 24, 146, 24, 24, 24, 24, 24, 24, 24, 80, 24, 24, 24, 24,
            24, 24, 24, 166, 24, 24, 24, 24, 24, 24, 24, 107, 24, 24, 24, 24, 24, 24, 24, 243, 24,
            24, 24, 24, 24, 24, 24, 251, 24, 24, 24, 24, 24, 24, 24, 236, 24, 24, 24, 24, 24, 24,
            24, 41, 24, 24, 24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24, 111, 24, 24, 24,
            24, 24, 24, 24, 128, 24, 24, 24, 24, 24, 24, 24, 207, 24, 24, 24, 24, 24, 24, 24, 164,
            24, 24, 24, 24, 24, 24, 24, 132, 24, 24, 24, 24, 24, 24, 24, 147, 24, 24, 24, 24, 24,
            24, 24, 228, 24, 24, 24, 24, 24, 24, 24, 83, 24, 24, 24, 24, 24, 24, 24, 246, 24, 24,
            24, 24, 24, 24, 24, 228, 24, 24, 24, 24, 24, 24, 24, 170, 24, 24, 24, 24, 24, 24, 24,
            68, 24, 24, 24, 24, 24, 24, 24, 89, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24,
            24, 24, 60, 24, 24, 24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24, 123, 24, 24,
            24, 24, 24, 24, 24, 130, 24, 24, 24, 24, 24, 24, 24, 88, 24, 24, 24, 24, 24, 24, 24,
            234, 24, 24, 24, 24, 24, 24, 24, 38, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24,
            24, 24, 24, 42, 24, 24, 24, 24, 24, 24, 24, 65, 1, 24, 24, 24, 24, 24, 24, 24, 100, 24,
            24, 24, 24, 24, 24, 24, 53, 18, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24,
            24, 131, 8, 24, 24, 24, 24, 24, 24, 24, 61, 24, 24, 24, 24, 24, 24, 24, 122, 24, 24,
            24, 24, 24, 24, 24, 131, 24, 24, 24, 24, 24, 24, 24, 238, 24, 24, 24, 24, 24, 24, 24,
            84, 24, 24, 24, 24, 24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 223, 24, 24, 24, 24,
            24, 24, 24, 154, 24, 24, 24, 24, 24, 24, 24, 118, 24, 24, 24, 24, 24, 24, 24, 118, 24,
            24, 24, 24, 24, 24, 24, 73, 24, 24, 24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24,
            27, 24, 24, 24, 24, 24, 24, 24, 101, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24,
            24, 24, 24, 80, 24, 24, 24, 24, 24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 123, 24,
            24, 24, 24, 24, 24, 24, 206, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24, 24,
            24, 174, 24, 24, 24, 24, 24, 24, 24, 134, 24, 24, 24, 24, 24, 24, 24, 205, 24, 24, 24,
            24, 24, 24, 24, 71, 24, 24, 24, 24, 24, 24, 24, 110, 24, 24, 24, 24, 24, 24, 24, 112,
            24, 24, 24, 24, 24, 24, 24, 180, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24, 24,
            24, 24, 98, 0, 24, 24, 24, 24, 24, 24, 24, 113, 24, 24, 24, 24, 24, 24, 24, 69, 24, 24,
            24, 24, 24, 24, 24, 145, 24, 24, 24, 24, 24, 24, 24, 231, 24, 24, 24, 24, 24, 24, 24,
            168, 24, 24, 24, 24, 24, 24, 24, 43, 24, 24, 24, 24, 24, 24, 24, 173, 24, 24, 24, 24,
            24, 24, 24, 172, 24, 24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24, 24, 24, 24, 104, 24,
            24, 24, 24, 24, 24, 24, 208, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 116, 24, 24,
            24, 97, 24, 24, 24, 107, 24, 24, 24, 101, 1, 113, 98, 97, 116, 99, 104, 95, 112, 114,
            111, 111, 102, 95, 98, 121, 116, 101, 115, 152, 29, 1, 24, 163, 24, 102, 24, 118, 24,
            97, 24, 108, 24, 117, 24, 101, 24, 115, 24, 128, 24, 103, 24, 105, 24, 110, 24, 100,
            24, 105, 24, 99, 24, 101, 24, 115, 24, 130, 0, 1, 24, 102, 24, 104, 24, 97, 24, 115,
            24, 104, 24, 101, 24, 114, 24, 246,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            use super::super::ConcatenationProof;
            let decoded = ConcatenationProof::<D>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            let re_encoded = decoded.to_bytes().expect("re-encode should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), re_encoded.as_slice());
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let aggregate = golden_aggregate_signature();
            let proof = match aggregate {
                AggregateSignature::Concatenation(proof) => proof,
                #[cfg(feature = "future_snark")]
                _ => panic!("Expected Concatenation variant"),
            };
            let bytes = proof
                .to_bytes()
                .expect("ConcatenationProof serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }

        #[test]
        fn cbor_encoding_is_deterministic() {
            let aggregate_1 = golden_aggregate_signature();
            let proof_1 = match aggregate_1 {
                AggregateSignature::Concatenation(proof) => proof,
                #[cfg(feature = "future_snark")]
                _ => panic!("Expected Concatenation variant"),
            };
            let bytes_1 = proof_1
                .to_bytes()
                .expect("ConcatenationProof serialization should not fail");

            let aggregate_2 = golden_aggregate_signature();
            let proof_2 = match aggregate_2 {
                AggregateSignature::Concatenation(proof) => proof,
                #[cfg(feature = "future_snark")]
                _ => panic!("Expected Concatenation variant"),
            };
            let bytes_2 = proof_2
                .to_bytes()
                .expect("ConcatenationProof serialization should not fail");

            assert_eq!(bytes_1, bytes_2);
        }
    }
}
