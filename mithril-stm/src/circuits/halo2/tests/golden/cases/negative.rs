use crate::LotteryIndex;
use crate::circuits::common::merkle::Position;
use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::gadgets::LOTTERY_BIT_BOUND;
use crate::circuits::halo2::tests::golden::helpers::{
    LOTTERIES_PER_K, LeafSelector, StmCircuitScenario, assert_proof_rejected_by_verifier,
    assert_proving_circuit_error, build_witness, build_witness_with_fixed_signer,
    build_witness_with_indices, create_default_merkle_tree, create_merkle_tree_with_leaf_selector,
    find_two_distinct_witness_entries, prove_and_verify_result, setup_stm_circuit_env,
};
use crate::circuits::halo2::witness::{
    CircuitMerkleTreeLeaf, CircuitWitnessEntry, SignedMessageWithoutPrefix,
};
use crate::signature_scheme::{BaseFieldElement, ScalarFieldElement};

#[test]
fn k_not_less_than_m() {
    const CIRCUIT_DEGREE: u32 = 13;
    const K: u32 = 3;
    const M: u32 = 3;
    let result = setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, M);
    let error = assert_proving_circuit_error(result);
    assert!(matches!(
        error,
        CertificateCircuitError::InvalidCircuitParameters { k: K, m: M }
    ));
}

#[test]
fn m_exceeds_lottery_bit_bound() {
    const CIRCUIT_DEGREE: u32 = 13;
    const K: u32 = 3;
    const M: u32 = (1 << LOTTERY_BIT_BOUND) as u32;
    let result = setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, M);
    let error = assert_proving_circuit_error(result);
    assert!(matches!(
        error,
        CertificateCircuitError::InvalidCircuitParameters { k: K, m: M }
    ));
}

mod slow {
    use super::*;

    #[test]
    fn message_mismatch() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message0 = SignedMessageWithoutPrefix::from(42);
        let message1 = SignedMessageWithoutPrefix::from(43);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("message_mismatch env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("message_mismatch tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let witness = build_witness(&merkle_tree, merkle_tree_commitment, message0, K)
            .expect("message_mismatch witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message1, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn merkle_tree_commitment_mismatch() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("merkle_tree_commitment_mismatch env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("merkle_tree_commitment_mismatch tree creation should succeed");
        let merkle_tree_commitment_0 = merkle_tree.merkle_tree_commitment();
        let merkle_tree_commitment_1 = merkle_tree_commitment_0 + SignedMessageWithoutPrefix::ONE;
        let witness = build_witness(&merkle_tree, merkle_tree_commitment_0, message, K)
            .expect("merkle_tree_commitment_mismatch witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment_1, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn signature_other_message() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message0 = SignedMessageWithoutPrefix::from(42);
        let message1 = SignedMessageWithoutPrefix::from(43);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("signature_other_message env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("signature_other_message tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let witness0 =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message0, &indices)
                .expect("signature_other_message witness0 build should succeed");
        let witness1 =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message1, &indices)
                .expect("signature_other_message witness1 build should succeed");

        // Witness membership/path/index match (merkle_tree_commitment, message1),
        // but signature is from (merkle_tree_commitment, message0).
        let mut witness = Vec::with_capacity(witness1.len());
        for (w1, w0) in witness1.into_iter().zip(witness0) {
            witness.push(CircuitWitnessEntry {
                leaf: w1.leaf,
                merkle_path: w1.merkle_path,
                unique_schnorr_signature: w0.unique_schnorr_signature,
                lottery_index: w1.lottery_index,
            });
        }

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message1, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn signature_verification_key_mismatch() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("signature_verification_key_mismatch env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("signature_verification_key_mismatch tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("signature_verification_key_mismatch witness build should succeed");

        let (i, j) = find_two_distinct_witness_entries(&witness)
            .expect("signature_verification_key_mismatch distinct entries should exist");
        // Keep leaf/path/index from i, but replace signature with j's signature.
        let sig_j = witness[j].unique_schnorr_signature;
        witness[i].unique_schnorr_signature = sig_j;

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn signature_bad_challenge() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("signature_bad_challenge env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("signature_bad_challenge tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("signature_bad_challenge witness build should succeed");

        witness[0].unique_schnorr_signature.challenge =
            witness[0].unique_schnorr_signature.challenge + BaseFieldElement::get_one();

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn signature_bad_response() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("signature_bad_response env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("signature_bad_response tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("signature_bad_response witness build should succeed");

        witness[0].unique_schnorr_signature.response = witness[0].unique_schnorr_signature.response
            - ScalarFieldElement::from_base_field(&BaseFieldElement::get_one())
                .expect("signature_bad_response response scalar conversion should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn signature_bad_commitment() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("signature_bad_commitment env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("signature_bad_commitment tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("signature_bad_commitment witness build should succeed");

        witness[0].unique_schnorr_signature.commitment_point =
            witness[1].unique_schnorr_signature.commitment_point;

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn indices_not_increasing() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("indices_not_increasing env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("indices_not_increasing tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 14];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("indices_not_increasing witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn index_out_of_bounds() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("index_out_of_bounds env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("index_out_of_bounds tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices = vec![6, 14, m as LotteryIndex];
        let witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("index_out_of_bounds witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::LotteryIndexOutOfBounds {
                index: m as LotteryIndex,
                m,
            }
        );
    }

    #[test]
    fn index_too_large_for_circuit_range() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("index_too_large_for_circuit_range env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("index_too_large_for_circuit_range tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let max_supported = ((1u64 << LOTTERY_BIT_BOUND) - 1) as LotteryIndex;
        let too_large = max_supported + 1;
        let indices = vec![6, 14, too_large];
        let witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("index_too_large_for_circuit_range witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::LotteryIndexTooLarge {
                index: too_large,
                max_supported,
            }
        );
    }

    #[test]
    fn merkle_path_corrupt_sibling() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("merkle_path_corrupt_sibling env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("merkle_path_corrupt_sibling tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("merkle_path_corrupt_sibling witness build should succeed");
        let d = 0usize;
        assert!(!witness[0].merkle_path.siblings.is_empty());
        assert!(d < witness[0].merkle_path.siblings.len());
        witness[0].merkle_path.siblings[d].1 += SignedMessageWithoutPrefix::ONE;

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn merkle_path_flip_position() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("merkle_path_flip_position env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("merkle_path_flip_position tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("merkle_path_flip_position witness build should succeed");
        let d = 1usize;
        assert!(d < witness[0].merkle_path.siblings.len());
        witness[0].merkle_path.siblings[d].0 = match witness[0].merkle_path.siblings[d].0 {
            Position::Left => Position::Right,
            Position::Right => Position::Left,
        };

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn merkle_path_length_short() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("merkle_path_length_short env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("merkle_path_length_short tree creation should succeed");
        let expected_depth = env.num_signers().next_power_of_two().trailing_zeros();

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("merkle_path_length_short witness build should succeed");
        assert!(!witness[0].merkle_path.siblings.is_empty());
        witness[0].merkle_path.siblings.pop();

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::MerkleSiblingLengthMismatch {
                expected_depth,
                actual: expected_depth - 1,
            }
        );
    }

    #[test]
    fn merkle_path_length_long() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("merkle_path_length_long env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("merkle_path_length_long tree creation should succeed");
        let expected_depth = env.num_signers().next_power_of_two().trailing_zeros();

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("merkle_path_length_long witness build should succeed");
        witness[0]
            .merkle_path
            .siblings
            .push((Position::Left, SignedMessageWithoutPrefix::ZERO));

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::MerkleSiblingLengthMismatch {
                expected_depth,
                actual: expected_depth + 1,
            }
        );
    }

    #[test]
    fn leaf_swap_keep_merkle_path() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("leaf_swap_keep_merkle_path env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("leaf_swap_keep_merkle_path tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("leaf_swap_keep_merkle_path witness build should succeed");
        let (i, j) = find_two_distinct_witness_entries(&witness)
            .expect("leaf_swap_keep_merkle_path distinct entries should exist");
        // Keep path/signature/index from i, but swap leaf with j.
        witness[i].leaf = witness[j].leaf;

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn leaf_merkle_path_mismatch() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("leaf_merkle_path_mismatch env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("leaf_merkle_path_mismatch tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("leaf_merkle_path_mismatch witness build should succeed");
        let (i, j) = find_two_distinct_witness_entries(&witness)
            .expect("leaf_merkle_path_mismatch distinct entries should exist");
        // Keep leaf/signature/index from i, but swap in j's Merkle path.
        witness[i].merkle_path = witness[j].merkle_path.clone();

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn leaf_wrong_verification_key() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("leaf_wrong_verification_key env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("leaf_wrong_verification_key tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("leaf_wrong_verification_key witness build should succeed");
        let (i, j) = find_two_distinct_witness_entries(&witness)
            .expect("leaf_wrong_verification_key distinct entries should exist");
        // Keep lottery_target_value/path/signature/index from i, but swap in j's verification key.
        let lottery_target_value = witness[i].leaf.lottery_target_value();
        let verification_key = witness[j].leaf.verification_key();
        witness[i].leaf = CircuitMerkleTreeLeaf(verification_key, lottery_target_value);

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn target_less_than_evaluation() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("target_less_than_evaluation env setup should succeed");
        let depth = env.num_signers().next_power_of_two().trailing_zeros();
        let signer_index = 0usize;
        let (merkle_tree, _) = create_merkle_tree_with_leaf_selector(
            depth,
            LeafSelector::Index(signer_index),
            SignedMessageWithoutPrefix::ZERO,
        )
        .expect("target_less_than_evaluation tree creation should succeed");

        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![5, 17, 25];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let witness = build_witness_with_fixed_signer(
            &merkle_tree,
            signer_index,
            merkle_tree_commitment,
            message,
            &indices,
        )
        .expect("target_less_than_evaluation witness build should succeed");

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }

    #[test]
    fn witness_length_short() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("witness_length_short env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("witness_length_short tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let mut witness = build_witness(&merkle_tree, merkle_tree_commitment, message, K)
            .expect("witness_length_short witness build should succeed");

        witness.pop();

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::WitnessLengthMismatch {
                expected_k: K,
                actual: 2,
            }
        );
    }

    #[test]
    fn witness_length_long() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("witness_length_long env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("witness_length_long tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let mut witness = build_witness(&merkle_tree, merkle_tree_commitment, message, K)
            .expect("witness_length_long witness build should succeed");

        let extra = witness
            .last()
            .cloned()
            .expect("witness should not be empty in witness_length_long");
        witness.push(extra);

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        let error = assert_proving_circuit_error(prove_and_verify_result(&env, scenario));
        assert_eq!(
            error,
            CertificateCircuitError::WitnessLengthMismatch {
                expected_k: K,
                actual: 4,
            }
        );
    }

    #[test]
    fn witness_duplicate_entry() {
        const CIRCUIT_DEGREE: u32 = 13;
        const K: u32 = 3;
        let message = SignedMessageWithoutPrefix::from(42);
        let env =
            setup_stm_circuit_env(current_function!(), CIRCUIT_DEGREE, K, K * LOTTERIES_PER_K)
                .expect("witness_duplicate_entry env setup should succeed");
        let merkle_tree = create_default_merkle_tree(env.num_signers())
            .expect("witness_duplicate_entry tree creation should succeed");
        let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();
        let m = env.m();
        let indices: Vec<LotteryIndex> = vec![6, 14, 22];
        assert!(indices.iter().all(|i| *i < m as LotteryIndex));
        let mut witness =
            build_witness_with_indices(&merkle_tree, merkle_tree_commitment, message, &indices)
                .expect("witness_duplicate_entry witness build should succeed");

        witness[1] = witness[0].clone();

        let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);
        assert_proof_rejected_by_verifier(prove_and_verify_result(&env, scenario));
    }
}
