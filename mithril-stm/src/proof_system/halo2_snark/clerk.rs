use std::collections::{BTreeMap, HashMap};

use anyhow::anyhow;
use sha2::{Digest, Sha256};

use crate::{
    AggregationError, ClosedKeyRegistration, LotteryIndex, MembershipDigest, Parameters,
    RegistrationEntryForSnark, Signer, SignerIndex, SingleSignature, StmResult,
    signature_scheme::BaseFieldElement,
};

use super::AggregateVerificationKeyForSnark;

/// Domain Separation Tag (DST) for deriving the selection seed from the signed message.
const DOMAIN_SEPARATION_TAG_SELECTION_SEED: &[u8] = b"MITHRIL_SNARK_SELECTION_SEED";
/// Domain Separation Tag (DST) for the index selection hash.
const DOMAIN_SEPARATION_TAG_SELECTION_INDEX: &[u8] = b"MITHRIL_SNARK_SELECTION_INDEX";
/// Domain Separation Tag (DST) for the deduplication hash.
const DOMAIN_SEPARATION_TAG_SELECTION_DEDUP: &[u8] = b"MITHRIL_SNARK_SELECTION_DEDUP";

/// Clerk for managing the SNARK proof system.
///
/// Responsible for computing the SNARK aggregate verification key from
/// a closed key registration. This is the SNARK counterpart of the
/// `ConcatenationClerk`.
#[derive(Debug, Clone)]
pub struct SnarkClerk {
    /// The closed key registration associated with this clerk.
    pub(crate) closed_key_registration: ClosedKeyRegistration,
    /// Protocol parameters
    pub(crate) parameters: Parameters,
    /// A mapping between the signer index in the list of all signers
    /// and their index in the reduced list of signers with SNARK keys.
    concatenation_to_snark_index_mapping: HashMap<SignerIndex, SignerIndex>,
}

impl SnarkClerk {
    /// Create a `SnarkClerk` from a closed key registration and protocol parameters.
    pub fn new_clerk_from_closed_key_registration(
        parameters: &Parameters,
        closed_key_registration: &ClosedKeyRegistration,
    ) -> Self {
        let concatenation_to_snark_index_mapping =
            closed_key_registration.compute_concatenation_to_snark_index_mapping();
        Self {
            parameters: *parameters,
            closed_key_registration: closed_key_registration.clone(),
            concatenation_to_snark_index_mapping,
        }
    }

    /// Create a `SnarkClerk` by extracting the parameters and closed key registration from `Signer`
    pub fn new_clerk_from_signer<D: MembershipDigest>(signer: &Signer<D>) -> Self {
        let closed_key_registration = signer.closed_key_registration.clone();
        let concatenation_to_snark_index_mapping =
            closed_key_registration.compute_concatenation_to_snark_index_mapping();
        Self {
            parameters: signer.parameters,
            closed_key_registration,
            concatenation_to_snark_index_mapping,
        }
    }

    /// Compute the `AggregateVerificationKeyForSnark` from the closed key registration.
    pub fn compute_aggregate_verification_key_for_snark<D: MembershipDigest>(
        &self,
    ) -> AggregateVerificationKeyForSnark<D> {
        AggregateVerificationKeyForSnark::from(&self.closed_key_registration)
    }

    /// Look up and convert the registration entry for a signer into its SNARK representation.
    pub fn get_snark_registration_entry(
        &self,
        signer_index: SignerIndex,
    ) -> StmResult<Option<RegistrationEntryForSnark>> {
        let closed_registration_entry = self
            .closed_key_registration
            .get_registration_entry_for_index(&signer_index)?;
        Ok(closed_registration_entry.into())
    }

    /// Returns the snark index given a concatenation index.
    /// Uses the `concatenation_to_snark_index_mapping` mapping to get the signer index
    /// in the snark merkle tree.
    pub(crate) fn get_signer_index_in_snark_merkle_tree(
        &self,
        concatenation_index: SignerIndex,
    ) -> StmResult<SignerIndex> {
        self.concatenation_to_snark_index_mapping
            .get(&concatenation_index)
            .copied()
            .ok_or(AggregationError::MissingSnarkIndexMapping(concatenation_index).into())
    }

    /// Select exactly `k` winning lottery indices and resolve contested indices.
    ///
    /// Uses separate hashes derived from public inputs only:
    /// 1. **Index selection:** `SHA-256(seed || lottery_index)` assigns a priority to each
    ///    lottery index independent of who signed it. The `k` indices with the smallest
    ///    hashes are selected.
    /// 2. **Deduplication:** for each selected index claimed by multiple signers,
    ///    `SHA-256(seed || lottery_index || signer_index)` picks the winner.
    ///
    /// The selection is fully deterministic from public inputs, publicly verifiable, and immune to
    /// grinding. The returned `BTreeMap` preserves strictly increasing lottery index order.
    ///
    /// Returns `AggregationError::NotEnoughSignatures` if fewer than `k` unique winning
    /// indices can be collected.
    pub(crate) fn select_valid_signatures_for_k_indices(
        parameters: &Parameters,
        signatures: &[SingleSignature],
        message_to_sign: &[BaseFieldElement; 2],
    ) -> StmResult<BTreeMap<LotteryIndex, SingleSignature>> {
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(DOMAIN_SEPARATION_TAG_SELECTION_SEED);
        seed_hasher.update(message_to_sign[0].to_bytes());
        seed_hasher.update(message_to_sign[1].to_bytes());
        let seed: [u8; 32] = seed_hasher.finalize().into();

        // Collect all valid signatures grouped by lottery index.
        let mut index_to_signatures: BTreeMap<LotteryIndex, Vec<SingleSignature>> = BTreeMap::new();
        for signature in signatures {
            let Some(snark_indices) = signature.get_snark_signature_indices() else {
                continue;
            };

            for index in snark_indices {
                index_to_signatures.entry(index).or_default().push(signature.clone());
            }
        }

        let count = index_to_signatures.len() as u64;
        if count < parameters.k {
            return Err(AggregationError::NotEnoughSignatures(count, parameters.k).into());
        }

        // Select: rank indices by their hash and keep the k smallest.
        let mut hashed_indices: Vec<HashedKey> = index_to_signatures
            .keys()
            .map(|&lottery_index| HashedKey::for_lottery_index(&seed, lottery_index))
            .collect();
        hashed_indices.sort();
        hashed_indices.truncate(parameters.k as usize);

        // Deduplicate: for each selected index, keep the signer with the smallest hash.
        let mut result = BTreeMap::new();
        for hashed_index in hashed_indices {
            let lottery_index = hashed_index.index;
            let candidates = index_to_signatures.remove(&lottery_index).ok_or_else(|| {
                anyhow!(
                    "Unexpected deduplication state: signature map missing lottery index {lottery_index}"
                )
            })?;
            let winner = candidates
                .into_iter()
                .min_by_key(|sig| HashedKey::for_signer_index(&seed, lottery_index, sig.signer_index))
                .ok_or_else(|| {
                    anyhow!(
                        "Unexpected deduplication state: no candidates for lottery index {lottery_index}"
                    )
                })?;
            result.insert(lottery_index, winner);
        }

        Ok(result)
    }
}

/// A hash paired with a tie-breaker for deterministic ordering.
///
/// Used in two contexts:
/// - **Index selection:** hash is `SHA-256(seed || lottery_index)`, tie-breaker is the lottery index.
/// - **Deduplication:** hash is `SHA-256(seed || lottery_index || signer_index)`, tie-breaker is
///   the signer index.
///
/// Ordering is by hash first, then by the tie-breaker to ensure a total ordering.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct HashedKey {
    hash: [u8; 32],
    index: u64,
}

impl HashedKey {
    fn for_lottery_index(seed: &[u8; 32], lottery_index: LotteryIndex) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_SEPARATION_TAG_SELECTION_INDEX);
        hasher.update(seed);
        hasher.update(lottery_index.to_le_bytes());
        Self {
            hash: hasher.finalize().into(),
            index: lottery_index,
        }
    }

    fn for_signer_index(
        seed: &[u8; 32],
        lottery_index: LotteryIndex,
        signer_index: SignerIndex,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_SEPARATION_TAG_SELECTION_DEDUP);
        hasher.update(seed);
        hasher.update(lottery_index.to_le_bytes());
        hasher.update(signer_index.to_le_bytes());
        Self {
            hash: hasher.finalize().into(),
            index: signer_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;

    use super::{DOMAIN_SEPARATION_TAG_SELECTION_SEED, HashedKey};
    use crate::{
        AggregationError, Initializer, KeyRegistration, LotteryIndex, MithrilMembershipDigest,
        Parameters, RegistrationEntry, Signer, SingleSignature,
        proof_system::{
            SnarkClerk,
            halo2_snark::{
                AggregateVerificationKeyForSnark, build_snark_message,
                compute_winning_lottery_indices,
            },
        },
        signature_scheme::BaseFieldElement,
    };

    type D = MithrilMembershipDigest;

    fn setup_signers_and_clerk(
        params: Parameters,
        nparties: usize,
        rng: &mut ChaCha20Rng,
    ) -> (Vec<Signer<D>>, SnarkClerk) {
        let mut key_reg = KeyRegistration::initialize();
        let mut initializers = Vec::with_capacity(nparties);

        for i in 0..nparties {
            let stake = (i as u64 + 1) * 10;
            let init = Initializer::new(params, stake, rng);
            let entry = RegistrationEntry::new(
                init.get_verification_key_proof_of_possession_for_concatenation(),
                init.stake,
                #[cfg(feature = "future_snark")]
                init.schnorr_verification_key,
            )
            .unwrap();
            key_reg.register_by_entry(&entry).unwrap();
            initializers.push(init);
        }

        let closed_reg = key_reg.close_registration(&params).unwrap();
        let signers: Vec<Signer<D>> = initializers
            .into_iter()
            .map(|init| init.try_create_signer::<D>(&closed_reg).unwrap())
            .collect();

        let clerk = SnarkClerk::new_clerk_from_signer(&signers[0]);
        (signers, clerk)
    }

    // Collect signatures and populate their SNARK winning indices using the
    // provided `message_to_sign`.
    fn collect_signatures_with_indices(
        signers: &[Signer<D>],
        clerk: &SnarkClerk,
        message: &[u8],
        message_to_sign: &[BaseFieldElement; 2],
    ) -> Vec<SingleSignature> {
        signers
            .iter()
            .filter_map(|signer| {
                let mut sig = signer.create_single_signature(message).ok()?;
                let snark_sig = sig.snark_signature.as_ref()?;
                let reg_entry =
                    clerk.get_snark_registration_entry(sig.signer_index).ok().flatten()?;
                let indices = compute_winning_lottery_indices(
                    clerk.parameters.m,
                    message_to_sign,
                    &snark_sig.get_schnorr_signature(),
                    reg_entry.1,
                )
                .ok()?;
                sig.set_snark_signature_indices(&indices);
                Some(sig)
            })
            .collect()
    }

    fn compute_message_to_sign(clerk: &SnarkClerk, message: &[u8]) -> [BaseFieldElement; 2] {
        let avk = clerk.compute_aggregate_verification_key_for_snark::<D>();
        build_snark_message(&avk.get_merkle_tree_commitment().root, message)
            .expect("build_snark_message should succeed")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn compute_snark_avk(
            seed in any::<[u8; 32]>(),
            number_of_parties in 1_usize..10,
            m in 1_u64..20,
            k in 1_u64..10,
            phi_f in 10_u64..100,
        ) {
            let parameters = Parameters { m, k, phi_f: phi_f as f64 / 100f64 };
            let mut rng = ChaCha20Rng::from_seed(seed);

            let (signers, clerk_from_signer) =
                setup_signers_and_clerk(parameters, number_of_parties, &mut rng);

            let clerk_from_registration = SnarkClerk::new_clerk_from_closed_key_registration(
                &parameters,
                &signers[0].closed_key_registration,
            );

            let avk_from_registration: AggregateVerificationKeyForSnark<D> =
                clerk_from_registration.compute_aggregate_verification_key_for_snark();
            let avk_from_signer: AggregateVerificationKeyForSnark<D> =
                clerk_from_signer.compute_aggregate_verification_key_for_snark();

            let expected_total_stake: u64 = (1..=number_of_parties as u64).map(|i| i * 10).sum();
            prop_assert_eq!(avk_from_registration.get_total_stake(), expected_total_stake);
            prop_assert_eq!(&avk_from_registration, &avk_from_signer);

            let bytes = avk_from_registration.to_bytes()
                .expect("serialization should succeed");
            let deserialized = AggregateVerificationKeyForSnark::<D>::from_bytes(&bytes)
                .expect("deserialization should succeed");
            prop_assert_eq!(&avk_from_registration, &deserialized);

            let avk_second: AggregateVerificationKeyForSnark<D> =
                clerk_from_registration.compute_aggregate_verification_key_for_snark();
            prop_assert_eq!(&avk_from_registration, &avk_second);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn dedup_selects_k_unique_indices(
            seed in any::<[u8; 32]>(),
            msg in any::<[u8; 32]>(),
            nparties in 1_usize..10,
            m in 1_u64..20,
            k in 1_u64..10,
            phi_f in 1_u32..100,
            num_false_msgs in 0_usize..3,
        ) {
            let params = Parameters { m, k, phi_f: (phi_f as f64) / 100.0f64 };
            let mut rng = ChaCha20Rng::from_seed(seed);

            let (signers, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);
            let message_to_sign = compute_message_to_sign(&clerk, &msg);

            // Collect valid signatures with SNARK indices
            let mut all_sigs = collect_signatures_with_indices(&signers, &clerk, &msg, &message_to_sign);

            // Also create signatures for false messages
            for _ in 0..num_false_msgs {
                let mut false_msg = vec![0u8; 32];
                rng.fill_bytes(&mut false_msg);
                if false_msg[..msg.len()] == msg[..] {
                    false_msg[0] = msg[0].wrapping_add(1);
                }
                let false_message_to_sign = compute_message_to_sign(&clerk, &false_msg);
                let false_sigs =
                    collect_signatures_with_indices(&signers, &clerk, &false_msg, &false_message_to_sign);
                all_sigs.extend(false_sigs);
            }

            let dedup_result =
                SnarkClerk::select_valid_signatures_for_k_indices(&params, &all_sigs, &message_to_sign);

            match dedup_result {
                Ok(unique_index_map) => {
                    prop_assert!(
                        !unique_index_map.is_empty(),
                        "Should have at least one entry"
                    );

                    // All lottery indices should be unique
                    let count = unique_index_map.len() as u64;
                    prop_assert!(
                        count >= k,
                        "Should have at least k unique indices, got {count} < {k}"
                    );
                    prop_assert_eq!(
                        count, k,
                        "Early stopping should collect exactly k indices"
                    );

                    // Each selected signature should have a SNARK component
                    for (lottery_index, sig) in &unique_index_map {
                        prop_assert!(
                            sig.snark_signature.is_some(),
                            "Signature at lottery index {lottery_index} should have a SNARK component"
                        );

                        // The lottery index should be within valid range
                        prop_assert!(
                            *lottery_index < m,
                            "Lottery index {lottery_index} should be less than m={m}"
                        );
                    }

                    // Verify that unique signers are tracked correctly
                    let signer_indices: HashSet<_> = unique_index_map
                        .values()
                        .map(|sig| sig.signer_index)
                        .collect();
                    prop_assert!(
                        !signer_indices.is_empty(),
                        "Should have at least one distinct signer"
                    );
                }
                Err(error) => {
                    prop_assert!(
                        matches!(
                            error.downcast_ref::<AggregationError>(),
                            Some(AggregationError::NotEnoughSignatures(..))
                        ),
                        "Expected NotEnoughSignatures, got: {error:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn selection_is_deterministic() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };

        let (signers, clerk) = setup_signers_and_clerk(params, 10, &mut rng);
        let msg = [7u8; 32];
        let message_to_sign = compute_message_to_sign(&clerk, &msg);
        let sigs = collect_signatures_with_indices(&signers, &clerk, &msg, &message_to_sign);

        let result_1 =
            SnarkClerk::select_valid_signatures_for_k_indices(&params, &sigs, &message_to_sign)
                .expect("should succeed");
        let result_2 =
            SnarkClerk::select_valid_signatures_for_k_indices(&params, &sigs, &message_to_sign)
                .expect("should succeed");

        let indices_1: Vec<LotteryIndex> = result_1.keys().copied().collect();
        let indices_2: Vec<LotteryIndex> = result_2.keys().copied().collect();
        assert_eq!(
            indices_1, indices_2,
            "Same inputs must produce the same selection"
        );
    }

    #[test]
    fn different_messages_produce_different_selections() {
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };

        let (signers, clerk) = setup_signers_and_clerk(params, 10, &mut rng);

        let msg_a = [1u8; 32];
        let msg_b = [2u8; 32];
        let message_to_sign_a = compute_message_to_sign(&clerk, &msg_a);
        let message_to_sign_b = compute_message_to_sign(&clerk, &msg_b);
        let sigs_a = collect_signatures_with_indices(&signers, &clerk, &msg_a, &message_to_sign_a);
        let sigs_b = collect_signatures_with_indices(&signers, &clerk, &msg_b, &message_to_sign_b);

        let selection_a =
            SnarkClerk::select_valid_signatures_for_k_indices(&params, &sigs_a, &message_to_sign_a)
                .expect("should succeed");
        let selection_b =
            SnarkClerk::select_valid_signatures_for_k_indices(&params, &sigs_b, &message_to_sign_b)
                .expect("should succeed");

        let indices_a: Vec<LotteryIndex> = selection_a.keys().copied().collect();
        let indices_b: Vec<LotteryIndex> = selection_b.keys().copied().collect();
        assert_ne!(
            indices_a, indices_b,
            "Different messages should produce different selections"
        );
    }

    #[test]
    fn selection_is_independent_of_input_order() {
        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };

        let (signers, clerk) = setup_signers_and_clerk(params, 10, &mut rng);
        let msg = [9u8; 32];
        let message_to_sign = compute_message_to_sign(&clerk, &msg);
        let sigs = collect_signatures_with_indices(&signers, &clerk, &msg, &message_to_sign);

        let mut sigs_shuffled = sigs.clone();
        sigs_shuffled.reverse();

        let selection =
            SnarkClerk::select_valid_signatures_for_k_indices(&params, &sigs, &message_to_sign)
                .expect("should succeed");
        let selection_shuffled = SnarkClerk::select_valid_signatures_for_k_indices(
            &params,
            &sigs_shuffled,
            &message_to_sign,
        )
        .expect("should succeed");

        let indices: Vec<LotteryIndex> = selection.keys().copied().collect();
        let indices_shuffled: Vec<LotteryIndex> = selection_shuffled.keys().copied().collect();
        assert_eq!(
            indices, indices_shuffled,
            "Selection must be independent of input signature order"
        );
    }

    #[test]
    fn deduplication_picks_smaller_hash_winner() {
        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
        let params = Parameters {
            m: 200,
            k: 1,
            phi_f: 0.8,
        };

        let (signers, clerk) = setup_signers_and_clerk(params, 10, &mut rng);
        let msg = [11u8; 32];
        let message_to_sign = compute_message_to_sign(&clerk, &msg);
        let mut sigs = collect_signatures_with_indices(&signers, &clerk, &msg, &message_to_sign);
        assert!(sigs.len() >= 2, "need at least two valid signatures");

        // Force the first two signatures to both claim the same lottery index.
        let contested_index: LotteryIndex = 7;
        sigs[0].set_snark_signature_indices(&[contested_index]);
        sigs[1].set_snark_signature_indices(&[contested_index]);
        let contested_sigs = vec![sigs[0].clone(), sigs[1].clone()];

        // Recompute the seed the same way production does.
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(DOMAIN_SEPARATION_TAG_SELECTION_SEED);
        seed_hasher.update(message_to_sign[0].to_bytes());
        seed_hasher.update(message_to_sign[1].to_bytes());
        let seed: [u8; 32] = seed_hasher.finalize().into();

        let expected_winner_signer_index = contested_sigs
            .iter()
            .min_by_key(|sig| HashedKey::for_signer_index(&seed, contested_index, sig.signer_index))
            .expect("at least one candidate")
            .signer_index;

        let result = SnarkClerk::select_valid_signatures_for_k_indices(
            &params,
            &contested_sigs,
            &message_to_sign,
        )
        .expect("selection should succeed");

        assert_eq!(result.len(), 1);
        let winner = result
            .get(&contested_index)
            .expect("contested index should be selected");
        assert_eq!(winner.signer_index, expected_winner_signer_index);
    }

    mod slow {
        use super::*;

        #[test]
        fn selection_distributes_fairly_across_index_range() {
            let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
            let m = 200_u64;
            let k = 5_u64;
            let params = Parameters { m, k, phi_f: 0.8 };

            let (signers, clerk) = setup_signers_and_clerk(params, 10, &mut rng);

            let midpoint = m / 2;
            let mut lower_half_count: u64 = 0;
            let mut upper_half_count: u64 = 0;
            let num_rounds = 20;

            for round in 0..num_rounds {
                let mut msg = [0u8; 32];
                msg[0] = round;

                let message_to_sign = compute_message_to_sign(&clerk, &msg);
                let sigs =
                    collect_signatures_with_indices(&signers, &clerk, &msg, &message_to_sign);

                let result = SnarkClerk::select_valid_signatures_for_k_indices(
                    &params,
                    &sigs,
                    &message_to_sign,
                );

                if let Ok(selected) = result {
                    for &index in selected.keys() {
                        if index < midpoint {
                            lower_half_count += 1;
                        } else {
                            upper_half_count += 1;
                        }
                    }
                }
            }

            let total = lower_half_count + upper_half_count;
            assert!(
                total > 0,
                "Expected at least one successful signature selection across {num_rounds} rounds",
            );
            let lower_ratio = lower_half_count as f64 / total as f64;
            assert!(
                (0.4..=0.6).contains(&lower_ratio),
                "Selection is biased: lower half got {lower_half_count}/{total} \
             ({:.1}%), expected roughly even distribution",
                lower_ratio * 100.0,
            );
        }
    }
}
