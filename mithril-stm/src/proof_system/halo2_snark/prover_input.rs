use std::collections::{BTreeMap, btree_map::Entry};

use crate::{
    AggregationError, BaseFieldElement, LotteryIndex, MembershipDigest, SignerIndex,
    SingleSignature, StmResult,
    circuits::{
        CircuitInstance, CircuitMerkleTreeLeaf, CircuitWitness, MerklePath as Halo2MerklePath,
        halo2::witness::CircuitWitnessEntry,
    },
    membership_commitment::{MerkleTree, MerkleTreeSnarkLeaf},
    proof_system::{
        AggregateVerificationKeyForSnark, SnarkClerk,
        halo2_snark::{
            MERKLE_TREE_DEPTH_FOR_SNARK, build_snark_message, compute_winning_lottery_indices,
        },
    },
};

/// Prover input for the SNARK circuit, bundling public and private data.
/// The **instance** carries the Merkle tree commitment and the signed message, the two public inputs
/// exposed to the verifier. The **witness** contains one entry per winning lottery index,
/// each providing the Schnorr signature, Merkle leaf, and authentication path that the circuit
/// checks privately.
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SnarkProverInput {
    /// Public inputs to the SNARK circuit.
    instance: CircuitInstance,
    /// Per-winning-lottery-index witness data.
    witness: CircuitWitness,
}

// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl SnarkProverInput {
    /// Build the SNARK prover input from a set of single signatures.
    ///
    /// This method orchestrates the full SNARK prover input preparation pipeline:
    /// 1. **Signature validation** each signature's Schnorr component is verified against the
    ///    signer's registered verification key and the aggregate verification key.
    /// 2. **Lottery evaluation** winning lottery indices are computed for every valid signature
    ///    and attached to a cloned copy of the signature.
    /// 3. **Deduplication** `SnarkClerk::select_valid_signatures_for_k_indices` keeps exactly `k`
    ///    unique lottery indices, breaking ties by smallest Schnorr signature.
    /// 4. **Witness construction** `create_witness` builds the per-index witness data
    ///    (Merkle leaf, authentication path, signature).
    ///
    /// Returns an error if fewer than `k` unique winning indices can be collected, or if a Merkle
    /// path conversion fails.
    pub fn prepare_prover_input<D: MembershipDigest>(
        clerk: &SnarkClerk,
        signatures: &[SingleSignature],
        message: &[u8],
    ) -> StmResult<SnarkProverInput> {
        let avk: AggregateVerificationKeyForSnark<D> =
            clerk.compute_aggregate_verification_key_for_snark();
        let message_to_sign = build_snark_message(&avk.get_merkle_tree_commitment().root, message)?;

        let valid_signatures_with_indices =
            Self::collect_valid_signatures_with_indices(clerk, signatures, &message_to_sign);

        let unique_index_signature_map = SnarkClerk::select_valid_signatures_for_k_indices(
            &clerk.parameters,
            &valid_signatures_with_indices,
            &message_to_sign,
        )?;

        let witness = Self::create_witness::<D>(unique_index_signature_map, clerk)?;

        let instance = (message_to_sign[0].into(), message_to_sign[1].into());

        Ok(SnarkProverInput { witness, instance })
    }

    /// Collect only the valid signatures that have a SNARK component and winning lottery indices.
    ///
    /// For each signature, this method verifies the Schnorr signature against the signer's
    /// registered verification key using the pre-computed `message_to_sign`, then computes
    /// winning lottery indices. Only signatures that pass all checks are included in the result;
    /// any that lack a SNARK component, have no or invalid registration entry, fail verification,
    /// or yield no winning indices are discarded. Since the goal is to gather as many valid
    /// signatures as possible, individual failures are not propagated, the caller decides
    /// whether the collected set is sufficient.
    fn collect_valid_signatures_with_indices(
        clerk: &SnarkClerk,
        signatures: &[SingleSignature],
        message_to_sign: &[BaseFieldElement; 2],
    ) -> Vec<SingleSignature> {
        signatures
            .iter()
            .filter_map(|sig| {
                let snark_sig = sig.snark_signature.as_ref()?;
                let reg_entry = match clerk.get_snark_registration_entry(sig.signer_index) {
                    Ok(Some(entry)) => entry,
                    Ok(None) => return None,
                    Err(_) => return None,
                };
                snark_sig
                    .verify_with_prepared_message(&reg_entry.0, message_to_sign)
                    .ok()?;
                let indices = compute_winning_lottery_indices(
                    clerk.parameters.m,
                    message_to_sign,
                    &snark_sig.get_schnorr_signature(),
                    reg_entry.1,
                )
                .ok()?;
                let mut new_sig = sig.clone();
                new_sig.set_snark_signature_indices(&indices);
                Some(new_sig)
            })
            .collect()
    }

    /// Build the witness vector from a deduplicated map of winning lottery indices.
    ///
    /// The construction proceeds in two phases:
    /// 1. Signer deduplication: iterates over the signatures to collect, for each unique signer,
    ///    the Merkle leaf (verification key + lottery target) and authentication path. A `BTreeMap`
    ///    keyed by `SignerIndex` ensures each signer's path is computed only once. Signers whose
    ///    registration entry is missing (`Ok(None)`) or whose lookup fails (`Err`) are skipped,
    ///    since the input signatures have already been validated upstream.
    /// 2. Entry assembly: maps every `(lottery_index, signature)` pair to a circuit witness tuple by
    ///    looking up the precomputed leaf and path for the signature's signer.
    ///
    /// The returned vector is sorted by lottery index (guaranteed by `BTreeMap` iteration order of
    /// `unique_index_signature_map`).
    ///
    /// Returns an error if a Merkle path cannot be converted to the circuit representation, or
    /// if any witness entry cannot be assembled (missing signer data or SNARK signature).
    fn create_witness<D: MembershipDigest>(
        unique_index_signature_map: BTreeMap<LotteryIndex, SingleSignature>,
        clerk: &SnarkClerk,
    ) -> StmResult<CircuitWitness> {
        let merkle_tree: MerkleTree<D::SnarkHash, MerkleTreeSnarkLeaf> =
            clerk.closed_key_registration.to_merkle_tree();
        let mut unique_signers: BTreeMap<SignerIndex, (MerkleTreeSnarkLeaf, Halo2MerklePath)> =
            BTreeMap::new();

        for sig in unique_index_signature_map.values() {
            if let Entry::Vacant(vacant) = unique_signers.entry(sig.signer_index) {
                let leaf = match clerk.get_snark_registration_entry(sig.signer_index) {
                    Ok(Some(entry)) => entry,
                    Ok(None) => continue,
                    Err(_) => continue,
                };
                let merkle_path = merkle_tree.compute_merkle_tree_path_fixed_length(
                    sig.signer_index as usize,
                    MERKLE_TREE_DEPTH_FOR_SNARK,
                );
                let merkle_path_circuit: Halo2MerklePath = Halo2MerklePath::try_from(&merkle_path)?;
                vacant.insert((leaf, merkle_path_circuit));
            }
        }

        unique_index_signature_map
            .into_iter()
            .map(|(lottery_index, sig)| {
                let (leaf, merkle_path) = unique_signers
                    .get(&sig.signer_index)
                    .ok_or(AggregationError::MissingSnarkSignerData(sig.signer_index))?;
                let schnorr_sig = sig
                    .snark_signature
                    .as_ref()
                    .ok_or(AggregationError::MissingSnarkSignature(lottery_index))?
                    .get_schnorr_signature();
                let circuit_leaf = CircuitMerkleTreeLeaf(leaf.0, leaf.1.into());
                Ok(CircuitWitnessEntry {
                    leaf: circuit_leaf,
                    merkle_path: merkle_path.clone(),
                    unique_schnorr_signature: schnorr_sig,
                    lottery_index,
                })
            })
            .collect()
    }

    /// Return the public instance as a `(merkle_tree_commitment, message)` pair.
    pub fn get_instance(&self) -> CircuitInstance {
        self.instance
    }

    /// Consume self and return the witness entries.
    pub fn into_witness(self) -> CircuitWitness {
        self.witness
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AggregationError, Initializer, KeyRegistration, MithrilMembershipDigest, Parameters,
        Signer, SingleSignature,
        proof_system::{SnarkClerk, halo2_snark::build_snark_message},
    };

    use super::SnarkProverInput;

    type D = MithrilMembershipDigest;

    fn setup_signers_and_clerk(
        params: Parameters,
        nparties: usize,
        rng: &mut ChaCha20Rng,
    ) -> (Vec<Signer<D>>, SnarkClerk) {
        let mut key_reg = KeyRegistration::initialize();
        let mut initializers = Vec::with_capacity(nparties);

        for _ in 0..nparties {
            let init = Initializer::new(params, 1, rng);
            key_reg.register_by_entry(&init.clone().try_into().unwrap()).unwrap();
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

    fn collect_signatures(signers: &[Signer<D>], message: &[u8]) -> Vec<SingleSignature> {
        signers
            .iter()
            .filter_map(|signer| signer.create_single_signature(message).ok())
            .collect()
    }

    #[test]
    fn succeeds_with_enough_valid_signatures() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };
        let nparties = 10;
        let message = [1u8; 32];

        let (signers, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);
        let signatures = collect_signatures(&signers, &message);

        let result = SnarkProverInput::prepare_prover_input::<D>(&clerk, &signatures, &message);
        assert!(result.is_ok(), "Expected success, got: {result:?}");

        let prover_input = result.unwrap();
        assert_eq!(
            prover_input.into_witness().len() as u64,
            params.k,
            "Witness should contain exactly k entries"
        );
    }

    #[test]
    fn fails_when_not_enough_signatures() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let params = Parameters {
            m: 5,
            k: 100,
            phi_f: 0.2,
        };
        let nparties = 2;
        let message = [2u8; 32];

        let (signers, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);
        let signatures = collect_signatures(&signers, &message);

        let result = SnarkProverInput::prepare_prover_input::<D>(&clerk, &signatures, &message);
        assert!(
            result.is_err(),
            "Expected failure due to insufficient signatures"
        );

        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<AggregationError>().is_some(),
            "Expected AggregationError, got: {err:?}"
        );
    }

    #[test]
    fn skips_signatures_without_snark_component() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };
        let nparties = 10;
        let message = [3u8; 32];

        let (signers, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);
        let mut signatures = collect_signatures(&signers, &message);

        // Strip the SNARK component from all signatures
        for sig in &mut signatures {
            sig.snark_signature = None;
        }

        let result = SnarkProverInput::prepare_prover_input::<D>(&clerk, &signatures, &message);
        assert!(
            result.is_err(),
            "Expected failure when all SNARK signatures are stripped"
        );
    }

    #[test]
    fn empty_signatures_fails() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };
        let nparties = 5;

        let (_, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);

        let result = SnarkProverInput::prepare_prover_input::<D>(&clerk, &[], &[4u8; 32]);
        assert!(result.is_err(), "Expected failure with empty signatures");
    }

    #[test]
    fn instance_contains_expected_message_components() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let params = Parameters {
            m: 200,
            k: 5,
            phi_f: 0.8,
        };
        let nparties = 10;
        let message = [5u8; 32];

        let (signers, clerk) = setup_signers_and_clerk(params, nparties, &mut rng);
        let signatures = collect_signatures(&signers, &message);

        let prover_input =
            SnarkProverInput::prepare_prover_input::<D>(&clerk, &signatures, &message).unwrap();

        // Recompute expected instance from the clerk's AVK
        let avk = clerk.compute_aggregate_verification_key_for_snark::<D>();
        let expected_message =
            build_snark_message(&avk.get_merkle_tree_commitment().root, &message).unwrap();

        let (instance_merkle_tree_commitment, instance_msg) = prover_input.get_instance();
        assert_eq!(
            instance_merkle_tree_commitment,
            expected_message[0].into(),
            "Instance merkle tree commitment mismatch"
        );
        assert_eq!(
            instance_msg,
            expected_message[1].into(),
            "Instance message mismatch"
        );
    }
}
