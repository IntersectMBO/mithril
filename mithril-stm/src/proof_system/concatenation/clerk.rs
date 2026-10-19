use anyhow::anyhow;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    AggregationError, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters, Signer,
    SingleSignatureWithRegisteredParty, StmResult,
    proof_system::AggregateVerificationKeyForConcatenation,
};

/// The `ConcatenationClerk` is responsible for managing the proof system related to
/// concatenation signatures.
#[derive(Debug, Clone)]
pub struct ConcatenationClerk {
    /// The closed key registration associated with this clerk.
    pub(crate) closed_key_registration: ClosedKeyRegistration,
    /// Protocol parameters
    pub(crate) parameters: Parameters,
}

impl ConcatenationClerk {
    /// Create a new `ConcatenationClerk` from a closed registration instance.
    pub fn new_clerk_from_closed_key_registration(
        parameters: &Parameters,
        closed_key_registration: &ClosedKeyRegistration,
    ) -> Self {
        Self {
            parameters: *parameters,
            closed_key_registration: closed_key_registration.clone(),
        }
    }

    /// Create a `ConcatenationClerk` from a signer.
    pub fn new_clerk_from_signer<D: MembershipDigest>(signer: &Signer<D>) -> Self {
        Self {
            parameters: signer.parameters,
            closed_key_registration: signer.closed_key_registration.clone(),
        }
    }

    /// Compute the `ConcatenationProofKey` related to the used registration.
    pub fn compute_aggregate_verification_key_for_concatenation<D: MembershipDigest>(
        &self,
    ) -> AggregateVerificationKeyForConcatenation<D> {
        AggregateVerificationKeyForConcatenation::from(
            self.closed_key_registration
                .get_closed_key_registration_for_concatenation(),
        )
    }

    #[cfg(test)]
    pub(crate) fn update_k(&mut self, k: u64) {
        self.parameters.k = k;
    }

    #[cfg(test)]
    pub(crate) fn update_m(&mut self, m: u64) {
        self.parameters.m = m;
    }

    /// Given a slice of `sig_reg_list`, this function returns a new list of `sig_reg_list` with only valid indices.
    /// In case of conflict (having several signatures for the same index)
    /// it selects the smallest signature (i.e. takes the signature with the smallest scalar).
    /// The function selects at least `self.k` indexes.
    ///  # Error
    /// If there is no sufficient signatures, then the function fails.
    // todo: We need to agree on a criteria to dedup (by default we use a BTreeMap that guarantees keys order)
    // todo: not good, because it only removes index if there is a conflict (see benches)
    pub fn select_valid_signatures_for_k_indices<D: MembershipDigest>(
        params: &Parameters,
        msg: &[u8],
        sigs: &[SingleSignatureWithRegisteredParty],
        avk: &AggregateVerificationKeyForConcatenation<D>,
    ) -> StmResult<Vec<SingleSignatureWithRegisteredParty>> {
        let mut sig_by_index: BTreeMap<LotteryIndex, &SingleSignatureWithRegisteredParty> =
            BTreeMap::new();
        let mut removal_idx_by_vk: HashMap<&SingleSignatureWithRegisteredParty, Vec<LotteryIndex>> =
            HashMap::new();

        for sig_reg in sigs.iter() {
            if sig_reg
                .sig
                .concatenation_signature
                .verify(
                    params,
                    &sig_reg.reg_party.get_verification_key_for_concatenation(),
                    &sig_reg.reg_party.get_stake(),
                    avk,
                    msg,
                )
                .is_err()
            {
                continue;
            }
            for index in sig_reg.sig.get_concatenation_signature_indices().iter() {
                let mut insert_this_sig = false;
                if let Some(&previous_sig) = sig_by_index.get(index) {
                    let sig_to_remove_index = if sig_reg.sig.get_concatenation_signature_sigma()
                        < previous_sig.sig.get_concatenation_signature_sigma()
                    {
                        insert_this_sig = true;
                        previous_sig
                    } else {
                        sig_reg
                    };

                    if let Some(indexes) = removal_idx_by_vk.get_mut(sig_to_remove_index) {
                        indexes.push(*index);
                    } else {
                        removal_idx_by_vk.insert(sig_to_remove_index, vec![*index]);
                    }
                } else {
                    insert_this_sig = true;
                }

                if insert_this_sig {
                    sig_by_index.insert(*index, sig_reg);
                }
            }
        }

        let mut dedup_sigs: HashSet<SingleSignatureWithRegisteredParty> = HashSet::new();
        let mut count: u64 = 0;

        for &sig_reg in sig_by_index.values() {
            if dedup_sigs.contains(sig_reg) {
                continue;
            }
            let mut deduped_sig = sig_reg.clone();
            if let Some(indexes) = removal_idx_by_vk.get(sig_reg) {
                let indices = deduped_sig
                    .sig
                    .get_concatenation_signature_indices()
                    .into_iter()
                    .filter(|i| !indexes.contains(i))
                    .collect::<Vec<LotteryIndex>>();
                deduped_sig.sig.set_concatenation_signature_indices(&indices);
            }

            let size: Result<u64, _> =
                deduped_sig.sig.get_concatenation_signature_indices().len().try_into();
            if let Ok(size) = size {
                if dedup_sigs.contains(&deduped_sig) {
                    panic!(
                        "Invariant violation: duplicate signature encountered in deduplication set, which should not be possible."
                    );
                }
                dedup_sigs.insert(deduped_sig);
                count += size;

                if count >= params.k {
                    return Ok(dedup_sigs.into_iter().collect());
                }
            }
        }
        Err(anyhow!(AggregationError::NotEnoughSignatures(
            count, params.k
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    use crate::{
        ClosedKeyRegistration, Initializer, KeyRegistration, MithrilMembershipDigest, Parameters,
        SingleSignatureWithRegisteredParty, proof_system::ConcatenationClerk,
    };

    use super::AggregationError;

    type D = MithrilMembershipDigest;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn test_dedup(
            seed in any::<[u8; 32]>(),
            msg in any::<[u8;16]>(),
            nparties in 1_usize..10,
            m in 1_u64..20,
            k in 1_u64..10,
            phi_f in 1u32..100,
            num_invalid_sigs_per_party in 0_usize..3,
        ) {
            prop_assume!(k <= m);
            let params = Parameters { m, k, phi_f: (phi_f as f64) / 100.0f64 };
            let mut rng = ChaCha20Rng::from_seed(seed);

            // False messages
            let mut false_msgs = Vec::new();
            for _ in 0..num_invalid_sigs_per_party {
                let mut false_msg = vec![0u8; 32];
                rng.fill_bytes(&mut false_msg);
                if false_msg == msg {
                    false_msg[0] = msg[0].wrapping_add(1);
                }
                false_msgs.push(false_msg);
            }

            let mut key_registration = KeyRegistration::initialize();
            let mut initializers = Vec::new();

            for i in 0..nparties {
                let stake = (i as u64 + 1) * 10;
                let initializer = Initializer::new(params, stake, &mut rng);
                key_registration.register_by_entry(&initializer.clone().try_into().unwrap());
                initializers.push(initializer);
            }

            let closed_registration: ClosedKeyRegistration = key_registration.close_registration(&params).unwrap();

            let signers: Vec<_> = initializers
                .into_iter()
                .map(|init| init.try_create_signer::<MithrilMembershipDigest>(&closed_registration).unwrap())
                .collect();

            let clerk = ConcatenationClerk::new_clerk_from_signer(&signers[0]);
            let avk = clerk.compute_aggregate_verification_key_for_concatenation::<D>();

            let mut all_sigs = Vec::new();
            for signer in &signers {
                // Add invalid signatures
                for false_msg in &false_msgs {
                    if let Ok(sig) = signer.create_single_signature(false_msg) {
                        all_sigs.push(sig);
                    }
                }

                // Add valid signatures
                if let Ok(sig) = signer.create_single_signature(&msg) {
                    all_sigs.push(sig);
                }
            }

            let sig_reg_list = all_sigs
                .iter()
                .map(|sig| {
                    let reg_party = clerk.closed_key_registration.get_closed_key_registration_for_concatenation().get_registration_entry_for_index(&sig.signer_index).unwrap();
                    #[cfg(feature = "snark")]
                    // We need to remove the SNARK fields from the registration entry used in Concatenation proofs to avoid breaking change with previous client not able to parse the aggregate signature.
                    // This happens because of the way the `ClosedRegistrationEntry` is serialized with an array representation instead of map representation.
                    let reg_party = reg_party.without_snark_fields();
                    SingleSignatureWithRegisteredParty {
                        sig: sig.clone(),
                        reg_party,
                    }
                })
                .collect::<Vec<SingleSignatureWithRegisteredParty>>();

            let dedup_result =
                ConcatenationClerk::select_valid_signatures_for_k_indices(&params, &msg, &sig_reg_list, &avk);

            match dedup_result {
                Ok(valid_sigs) => {
                    assert!(!valid_sigs.is_empty(), "Should have at least one valid signature");
                    for passed_sigs in &valid_sigs {
                        let signer = &signers[passed_sigs.sig.signer_index as usize];
                        let verify_result = passed_sigs.sig.concatenation_signature.verify(
                            &params,
                            &signer.get_bls_verification_key(),
                            &passed_sigs.reg_party.get_stake(),
                            &avk,
                            &msg,
                        );
                        assert!(verify_result.is_ok(), "All returned signatures should verify: {:?}", verify_result);
                    }
                    // If all signatures are valid, check that indices are unique and at least k
                    // unique indices are collected across all signatures
                    let mut unique_indices = HashSet::new();
                    let mut count: u64 = 0;
                    for sig in valid_sigs.iter() {
                        for index in sig.sig.get_concatenation_signature_indices().iter() {
                            count += 1;
                            unique_indices.insert(*index);
                        }
                    }
                    assert_eq!(unique_indices.len() as u64, count, "Indices should be unique");
                    assert!(count >= k, "Should have at least k unique indices");
                }
                Err(error) => {
                    assert!(
                        matches!(
                            error.downcast_ref::<AggregationError>(),
                            Some(AggregationError::NotEnoughSignatures(..))
                        ),
                        "Expected NotEnoughSignatures, got: {:?}", error
                    );
                }
            }
        }
    }
}
