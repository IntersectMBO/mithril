mod aggregate_key;
mod clerk;
mod eligibility;
mod message;
mod proof;
mod prover_input;
mod setup;
mod signer;
mod single_signature;

pub use aggregate_key::AggregateVerificationKeyForSnark;
#[cfg(test)]
pub(crate) use aggregate_key::RIGID_SLOT_BYTES;
pub(crate) use clerk::SnarkClerk;
pub(crate) use eligibility::{
    compute_target_value_for_snark_lottery, compute_winning_lottery_indices,
};
pub(crate) use message::build_snark_message;
pub use proof::SnarkProof;
pub(crate) use proof::SnarkProver;
pub use setup::SnarkVerifierData;
pub(crate) use setup::{SnarkProverSetup, SnarkVerifierSetup};
pub(crate) use signer::SnarkProofSigner;
pub(crate) use single_signature::SingleSignatureForSnark;

/// Fixed merkle tree depth used of the merkle tree
/// of signers for the SNARK proof. It is used to compute
/// the necessary padding of the merkle path.
///
/// Important: Changing this value means changing the circuit and the circuit verification key
///
/// For now set to 13 to allow for 2^13 = 8192 signers
pub const MERKLE_TREE_DEPTH_FOR_SNARK: u32 = 13;

/// Errors which can be outputted by the snark proof creation or verification.
#[cfg(feature = "future_snark")]
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SnarkError {
    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    /// The SNARK proof failed to verify
    #[error("The SNARK proof failed to verify.")]
    VerifyProofFail,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        ClosedRegistrationEntry, KeyRegistration, MithrilMembershipDigest, Parameters,
        RegistrationEntry, VerificationKeyForSnark,
        VerificationKeyProofOfPossessionForConcatenation,
        proof_system::halo2_snark::eligibility::{check_lottery_for_index, compute_lottery_prefix},
        protocol::RegistrationEntryForSnark,
        signature_scheme::{BlsSigningKey, SchnorrSigningKey},
    };

    use super::{
        AggregateVerificationKeyForSnark, SingleSignatureForSnark, SnarkProofSigner,
        build_snark_message, compute_winning_lottery_indices,
    };

    type D = MithrilMembershipDigest;

    /// Setup a `SnarkProofSigner` and `AggregateVerificationKeyForSnark` from a given
    /// number of parties, protocol parameters, and a deterministic RNG.
    ///
    /// Returns the signer for the first registered party along with the aggregate
    /// verification key derived from the full registration.
    fn setup_snark_signer(
        params: Parameters,
        nparties: usize,
        rng: &mut ChaCha20Rng,
    ) -> (SnarkProofSigner<D>, AggregateVerificationKeyForSnark<D>) {
        let mut key_reg = KeyRegistration::initialize();

        let mut first_schnorr_sk = None;
        let mut first_schnorr_vk = None;
        let mut first_entry = None;

        for i in 0..nparties {
            let bls_sk = BlsSigningKey::generate(rng);
            let bls_vk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);
            let schnorr_sk = SchnorrSigningKey::generate(rng);
            let schnorr_vk = VerificationKeyForSnark::new_from_signing_key(schnorr_sk.clone());

            let entry = RegistrationEntry::new(
                bls_vk,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_vk),
            )
            .unwrap();
            key_reg.register_by_entry(&entry).unwrap();

            if i == 0 {
                first_schnorr_sk = Some(schnorr_sk);
                first_schnorr_vk = Some(schnorr_vk);
                first_entry = Some(entry);
            }
        }

        let closed_reg = key_reg.close_registration(&params).unwrap();
        let entry = first_entry.unwrap();

        let merkle_tree = closed_reg
            .to_merkle_tree::<<D as crate::MembershipDigest>::SnarkHash, RegistrationEntryForSnark>(
            )
            .to_merkle_tree_commitment();
        let lottery_target_value =
            ClosedRegistrationEntry::try_from((entry, closed_reg.get_total_stake(), params.phi_f))
                .unwrap()
                .get_lottery_target_value()
                .unwrap();

        let snark_signer = SnarkProofSigner::<D>::new(
            params,
            first_schnorr_sk.unwrap(),
            first_schnorr_vk.unwrap(),
            lottery_target_value,
            merkle_tree,
        );

        let aggregate_key = AggregateVerificationKeyForSnark::<D>::from(&closed_reg);

        (snark_signer, aggregate_key)
    }

    /// Circuit-compatibility tests for the SNARK signature flow.
    ///
    /// These tests verify that CPU-side signature generation and verification
    /// produce intermediate values compatible with the circuit in
    /// `circuits::halo2`. They serve as a **compatibility contract**: if the
    /// CPU code diverges from the circuit's expectations, these tests will
    /// catch it.
    mod circuit_compatibility {
        use super::*;
        use crate::signature_scheme::{
            BaseFieldElement, DOMAIN_SEPARATION_TAG_LOTTERY,
            DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE, PrimeOrderProjectivePoint, ProjectivePoint,
            ScalarFieldElement, compute_poseidon_digest,
        };
        use sha2::{Digest, Sha256};

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]

            /// Verifies that `build_snark_message` encodes the Merkle root
            /// consistently with the circuit's public-input encoding.
            ///
            /// The circuit golden helpers decode the root via
            /// `BaseFieldElement::from_bytes`
            /// (see `circuits::halo2::golden::helpers::decode_merkle_root`),
            /// while `build_snark_message` uses `BaseFieldElement::from_raw`.
            /// For Poseidon-produced roots (always canonical field elements),
            /// both must yield the same field element.
            #[test]
            fn message_encoding_matches_circuit(
                sha_input in any::<[u8; 32]>(),
                seed in any::<[u8; 32]>(),
            ) {
                let mut rng = ChaCha20Rng::from_seed(seed);
                let params = Parameters {
                    m: 10,
                    k: 5,
                    phi_f: 0.2,
                };
                let (_signer, avk) = setup_snark_signer(params, 3, &mut rng);

                let commitment = avk.get_merkle_tree_commitment();
                let root_bytes = commitment.root.as_slice();
                let msg: [u8; 32] = Sha256::digest(sha_input).into();

                // CPU encoding via build_snark_message (uses from_raw)
                let [root_cpu, _] = build_snark_message(&commitment.root, &msg).unwrap();

                // Circuit encoding: golden helpers use from_bytes for the root
                assert_eq!(32, root_bytes.len());
                let root_circuit = BaseFieldElement::from_bytes(root_bytes)
                    .expect("Poseidon root must be canonical");

                assert_eq!(
                    root_cpu, root_circuit,
                    "build_snark_message (from_raw) must match the circuit's \
                     from_bytes for Poseidon roots"
                );
            }
        }

        /// Verifies that the CPU's Schnorr challenge uses the same Poseidon
        /// input ordering as the circuit's `verify_unique_signature` gadget.
        ///
        /// Circuit ordering (`circuits::halo2::gadgets::verify_unique_signature`):
        /// ```text
        /// Poseidon(DST_SIG, H_x, H_y, vk_x, vk_y, σ_x, σ_y, R1_x, R1_y, R2_x, R2_y)
        /// ```
        /// where `H = hash_to_curve([root, msg])`,
        ///       `R1 = [s]H + [c]σ`,
        ///       `R2 = [s]G + [c]vk`.
        #[test]
        fn schnorr_challenge_matches_circuit_ordering() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.2,
            };
            let (signer, avk) = setup_snark_signer(params, 3, &mut rng);

            let msg = [0u8; 32];
            let sig = signer.create_single_signature(&msg, &mut rng).unwrap();
            let schnorr = sig.get_schnorr_signature();

            let message_to_sign =
                build_snark_message(&avk.get_merkle_tree_commitment().root, &msg).unwrap();

            // H = hash_to_curve([root, msg])
            let h = ProjectivePoint::hash_to_projective_point(&message_to_sign).unwrap();
            let (h_x, h_y) = h.get_coordinates();

            // vk
            let vk = signer.get_verification_key();
            let (vk_x, vk_y) = ProjectivePoint::from(vk.0).get_coordinates();

            // σ (commitment_point)
            let (sigma_x, sigma_y) = schnorr.commitment_point.get_coordinates();

            // R1 = s * H + c * σ
            let c_scalar = ScalarFieldElement::from_base_field(&schnorr.challenge).unwrap();
            let r1 = schnorr.response * h + c_scalar * schnorr.commitment_point;
            let (r1_x, r1_y) = r1.get_coordinates();

            // R2 = s * G + c * vk
            let g = PrimeOrderProjectivePoint::create_generator();
            let r2 = schnorr.response * g + c_scalar * vk.0;
            let (r2_x, r2_y) = ProjectivePoint::from(r2).get_coordinates();

            // Recompute challenge with the circuit's exact input order
            let challenge_recomputed = compute_poseidon_digest(&[
                DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
                h_x,
                h_y,
                vk_x,
                vk_y,
                sigma_x,
                sigma_y,
                r1_x,
                r1_y,
                r2_x,
                r2_y,
            ]);

            assert_eq!(
                schnorr.challenge, challenge_recomputed,
                "CPU challenge must match the circuit's Poseidon input ordering"
            );
        }

        /// Verifies the lottery prefix structure matches the circuit's
        /// computation at `circuits::halo2::circuit` lines 77-79:
        /// ```text
        /// prefix = Poseidon(DST_LOTTERY, merkle_root, msg)
        /// ```
        #[test]
        fn lottery_prefix_structure_matches_circuit() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.2,
            };
            let (_signer, avk) = setup_snark_signer(params, 3, &mut rng);

            let msg = [0u8; 32];
            let message_to_sign =
                build_snark_message(&avk.get_merkle_tree_commitment().root, &msg).unwrap();

            // CPU's compute_lottery_prefix
            let cpu_prefix = compute_lottery_prefix(&message_to_sign);

            // Manual reconstruction: Poseidon(DOMAIN_SEPARATION_TAG_LOTTERY, root, msg)
            let [root, msg_fe] = message_to_sign;
            let manual_prefix =
                compute_poseidon_digest(&[DOMAIN_SEPARATION_TAG_LOTTERY, root, msg_fe]);

            assert_eq!(
                cpu_prefix, manual_prefix,
                "compute_lottery_prefix must equal Poseidon(DOMAIN_SEPARATION_TAG_LOTTERY, root, msg)"
            );
        }

        /// Verifies the lottery evaluation structure matches the circuit's
        /// `assert_lottery_won` gadget (`circuits::halo2::gadgets`):
        /// ```text
        /// ev = Poseidon(prefix, σ_x, σ_y, index)
        /// ```
        /// Cross-checks the manual computation against
        /// `assert_lottery_won` by setting `target = ev` (which must
        /// pass under `ev <= target`).
        #[test]
        fn lottery_evaluation_structure_matches_circuit() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.2,
            };
            let (signer, avk) = setup_snark_signer(params, 3, &mut rng);

            let msg = [0u8; 32];
            let sig = signer.create_single_signature(&msg, &mut rng).unwrap();
            let schnorr = sig.get_schnorr_signature();

            let message_to_sign =
                build_snark_message(&avk.get_merkle_tree_commitment().root, &msg).unwrap();

            // Obtain a winning indices via check_lottery
            let winning_indices = compute_winning_lottery_indices(
                params.m,
                &message_to_sign,
                &schnorr,
                signer.get_lottery_target_value(),
            )
            .expect("check_lottery should find at least one winning index");
            let index = winning_indices[0];

            let (sigma_x, sigma_y) = schnorr.commitment_point.get_coordinates();
            let index_fe = BaseFieldElement::from(index);

            // Verify evaluation structure: ev = Poseidon(prefix, σ_x, σ_y, index)
            let prefix = compute_lottery_prefix(&message_to_sign);
            let ev = compute_poseidon_digest(&[prefix, sigma_x, sigma_y, index_fe]);

            // Cross-check: assert_lottery_won must pass
            // when target = manually computed evaluation
            assert!(
                check_lottery_for_index(&schnorr, index, params.m, prefix, ev).is_ok(),
                "Lottery must pass when target equals the manually \
                 computed evaluation"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

        #[test]
        fn sign_then_verify_roundtrip(
            nparties in 2_usize..10,
            m in 10_u64..20,
            k in 1_u64..5,
            msg in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
        ) {
            let params = Parameters { m, k, phi_f: 1.0 };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let (signer, avk) = setup_snark_signer(params, nparties, &mut rng);

            let sig = signer.create_single_signature(&msg, &mut rng).unwrap();

            sig.verify::<D>(
                &signer.get_verification_key(),
                &msg,
                &avk,
            )
            .expect("sign then verify roundtrip should succeed");
        }

        #[test]
        fn wrong_message_fails_verification(
            nparties in 2_usize..10,
            m in 10_u64..20,
            k in 1_u64..5,
            msg1 in any::<[u8; 32]>(),
            msg2 in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
        ) {
            prop_assume!(msg1 != msg2);
            let params = Parameters { m, k, phi_f: 1.0 };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let (signer, avk) = setup_snark_signer(params, nparties, &mut rng);

            let sig = signer.create_single_signature(&msg1, &mut rng).unwrap();

            sig.verify::<D>(
                &signer.get_verification_key(),
                &msg2,
                &avk,
            )
            .expect_err("Verification with wrong message should fail");
        }

        #[test]
        fn wrong_verification_key_fails(
            nparties in 2_usize..10,
            m in 10_u64..20,
            k in 1_u64..5,
            msg in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
        ) {
            let params = Parameters { m, k, phi_f: 1.0 };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let (signer, avk) = setup_snark_signer(params, nparties, &mut rng);
            let sig = signer.create_single_signature(&msg, &mut rng).unwrap();

            let wrong_sk = SchnorrSigningKey::generate(&mut rng);
            let wrong_vk = VerificationKeyForSnark::new_from_signing_key(wrong_sk);

            sig.verify::<D>(
                &wrong_vk,
                &msg,
                &avk,
            )
            .expect_err("Verification with wrong key should fail");
        }

        #[test]
        fn serde_roundtrip(
            nparties in 2_usize..10,
            m in 10_u64..20,
            k in 1_u64..5,
            msg in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
        ) {
            let params = Parameters { m, k, phi_f: 1.0 };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let (signer, _) = setup_snark_signer(params, nparties, &mut rng);

            let sig = signer.create_single_signature(&msg, &mut rng).unwrap();

            let serialized = serde_json::to_string(&sig).unwrap();
            let deserialized: SingleSignatureForSnark =
                serde_json::from_str(&serialized).unwrap();

            // Check both fields explicitly
            assert_eq!(
                sig.get_schnorr_signature(),
                deserialized.get_schnorr_signature()
            );
            assert_eq!(
                sig.get_indices(),
                deserialized.get_indices()
            );
        }
    }

    #[test]
    fn check_lottery_returns_all_winning_indices() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let params = Parameters {
            m: 10,
            k: 5,
            phi_f: 0.2,
        };
        let (signer, avk) = setup_snark_signer(params, 3, &mut rng);

        let msg = [0u8; 32];
        let sig = signer.create_single_signature(&msg, &mut rng).unwrap();
        let schnorr = sig.get_schnorr_signature();

        let message_to_sign =
            build_snark_message(&avk.get_merkle_tree_commitment().root, &msg).unwrap();
        let target = signer.get_lottery_target_value();

        let winning_indices =
            compute_winning_lottery_indices(params.m, &message_to_sign, &schnorr, target)
                .expect("check_lottery should find at least one winning index");

        let prefix = compute_lottery_prefix(&message_to_sign);

        // Every returned index must pass assert_lottery_won
        for &index in &winning_indices {
            assert!(
                index < params.m,
                "Winning index {index} should be less than m={}",
                params.m
            );
            assert!(
                check_lottery_for_index(&schnorr, index, params.m, prefix, target).unwrap(),
                "Winning index {index} should pass check_lottery_for_index"
            );
        }

        // Every index NOT in the winning set must fail check_lottery_for_index
        for index in 0..params.m {
            if !winning_indices.contains(&index) {
                let result =
                    check_lottery_for_index(&schnorr, index, params.m, prefix, target).unwrap();
                assert!(
                    !result,
                    "Expected LotteryLost for index {index}, got: {result:?}"
                );
            }
        }
    }
}
