use rand_core::{CryptoRng, RngCore};

use crate::{
    LotteryTargetValue, MembershipDigest, Parameters, SchnorrSigningKey, StmResult,
    VerificationKeyForSnark, membership_commitment::MerkleTreeCommitment,
    protocol::RegistrationEntryForSnark,
};

use super::{SingleSignatureForSnark, build_snark_message, compute_winning_lottery_indices};

/// A signer for the SNARK proof system, responsible for generating signatures
/// that can be used in SNARK proofs.
#[derive(Debug, Clone)]
pub(crate) struct SnarkProofSigner<D: MembershipDigest> {
    parameters: Parameters,
    signing_key: SchnorrSigningKey,
    verification_key: VerificationKeyForSnark,
    lottery_target_value: LotteryTargetValue,
    key_registration_commitment: MerkleTreeCommitment<D::SnarkHash, RegistrationEntryForSnark>,
}

impl<D: MembershipDigest> SnarkProofSigner<D> {
    /// Creates a new `SnarkProofSigner` with the given protocol parameters, keys,
    /// lottery target value, and Merkle tree commitment of the key registration.
    pub fn new(
        parameters: Parameters,
        signing_key: SchnorrSigningKey,
        verification_key: VerificationKeyForSnark,
        lottery_target_value: LotteryTargetValue,
        key_registration_commitment: MerkleTreeCommitment<D::SnarkHash, RegistrationEntryForSnark>,
    ) -> Self {
        Self {
            parameters,
            signing_key,
            verification_key,
            lottery_target_value,
            key_registration_commitment,
        }
    }

    /// Generates a single signature for the SNARK proof system.
    /// Computes a unique Schnorr signature over `[merkle_tree_commitment, msg]` and checks the
    /// lottery. Returns `SingleSignatureForSnark` if at least one lottery index won,
    /// or `SignatureError::LotteryLost` otherwise. The winning indices are not stored
    /// in the signature at this stage; they are computed and assigned during aggregation.
    pub fn create_single_signature<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> StmResult<SingleSignatureForSnark> {
        let message_to_sign = build_snark_message(&self.key_registration_commitment.root, message)?;
        let signature = self.signing_key.sign_unique(&message_to_sign, rng)?;

        compute_winning_lottery_indices(
            self.parameters.m,
            &message_to_sign,
            &signature,
            self.lottery_target_value,
        )?;

        Ok(SingleSignatureForSnark::new(signature, vec![]))
    }

    /// Gets the lottery target value
    pub fn get_lottery_target_value(&self) -> LotteryTargetValue {
        self.lottery_target_value
    }

    /// Gets the verification key for SNARK.
    pub fn get_verification_key(&self) -> VerificationKeyForSnark {
        self.verification_key
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        KeyRegistration, MembershipDigest, MithrilMembershipDigest, Parameters, RegistrationEntry,
        SignatureError, VerificationKeyForSnark, VerificationKeyProofOfPossessionForConcatenation,
        membership_commitment::{MerkleTreeCommitment, MerkleTreeSnarkLeaf},
        proof_system::halo2_snark::eligibility::{check_lottery_for_index, compute_lottery_prefix},
        protocol::RegistrationEntryForSnark,
        signature_scheme::{
            BaseFieldElement, BlsSigningKey, SchnorrSigningKey, compute_poseidon_digest,
        },
    };

    use super::{SnarkProofSigner, build_snark_message};

    type D = MithrilMembershipDigest;

    /// Helper function to create a `SnarkProofSigner` with a single registered party and a custom lottery target.
    fn setup_signer_with_target(
        target: BaseFieldElement,
        rng: &mut ChaCha20Rng,
    ) -> SnarkProofSigner<D> {
        let params = Parameters {
            m: 10,
            k: 5,
            phi_f: 0.2,
        };
        let bls_sk = BlsSigningKey::generate(rng);
        let bls_vk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);
        let schnorr_sk = SchnorrSigningKey::generate(rng);
        let schnorr_vk = VerificationKeyForSnark::new_from_signing_key(schnorr_sk.clone());

        let mut key_reg = KeyRegistration::initialize();
        let entry = RegistrationEntry::new(
            bls_vk,
            1,
            #[cfg(feature = "future_snark")]
            Some(schnorr_vk),
        )
        .unwrap();
        key_reg.register_by_entry(&entry).unwrap();
        let closed_reg = key_reg.close_registration(&params).unwrap();

        let merkle_tree = closed_reg
            .to_merkle_tree::<<D as MembershipDigest>::SnarkHash, RegistrationEntryForSnark>()
            .to_merkle_tree_commitment();

        SnarkProofSigner::<D>::new(params, schnorr_sk, schnorr_vk, target, merkle_tree)
    }

    #[test]
    fn lottery_prefix_differs_for_one_bit_change() {
        type SnarkHash = <D as MembershipDigest>::SnarkHash;

        let root = [0u8; 32];
        let msg = [0u8; 32];

        let commitment =
            MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(&root).unwrap();
        let message_to_sign = build_snark_message(&commitment.root, &msg).unwrap();
        let prefix1 = compute_lottery_prefix(&message_to_sign);

        // Flip bit 0 of the commitment root
        let mut root_flipped = root;
        root_flipped[0] ^= 1;
        let commitment_flipped =
            MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(&root_flipped)
                .unwrap();
        let message_to_sign_flipped = build_snark_message(&commitment_flipped.root, &msg).unwrap();
        let prefix2 = compute_lottery_prefix(&message_to_sign_flipped);

        assert_ne!(prefix1, prefix2);
    }

    #[test]
    fn index_bound_check() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let msg = [BaseFieldElement::from(1u64)];
        let signature = sk.sign_unique(&msg, &mut rng).unwrap();

        let prefix = BaseFieldElement::from(0u64);
        let target = BaseFieldElement::from(u64::MAX);
        let m = 10u64;

        let err = check_lottery_for_index(&signature, m + 1, m, prefix, target)
            .expect_err("Index above m should fail");
        assert!(
            matches!(
                err.downcast_ref::<SignatureError>(),
                Some(SignatureError::IndexBoundFailed(idx, bound)) if *idx == m + 1 && *bound == m
            ),
            "Expected IndexBoundFailed({}, {m}), got: {err:?}",
            m + 1
        );
    }

    #[test]
    fn evaluation_boundary() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = SchnorrSigningKey::generate(&mut rng);
        let msg = [BaseFieldElement::from(42u64)];
        let signature = sk.sign_unique(&msg, &mut rng).unwrap();

        let prefix = compute_lottery_prefix(&msg);
        let lottery_index = 5u64;
        let m = 10u64;

        // Compute the evaluation value manually
        let (cx, cy) = signature.commitment_point.get_coordinates();
        let ev = compute_poseidon_digest(&[prefix, cx, cy, BaseFieldElement::from(lottery_index)]);

        // With target = ev, the lottery should pass
        assert!(
            check_lottery_for_index(&signature, lottery_index, m, prefix, ev).unwrap(),
            "Lottery should pass when evaluation equals target"
        );
    }

    #[test]
    fn target_zero_means_lottery_lost() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let target = BaseFieldElement::from(0u64);
        let signer = setup_signer_with_target(target, &mut rng);

        let msg = [0u8; 32];
        let err = signer
            .create_single_signature(&msg, &mut rng)
            .expect_err("Lottery with target = 0 should lose");
        assert!(
            matches!(
                err.downcast_ref::<SignatureError>(),
                Some(SignatureError::LotteryLost)
            ),
            "Expected LotteryLost, got: {err:?}"
        );
    }

    #[test]
    fn target_max_guarantees_win() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        // p - 1 is the maximum field element: 0 - 1 in the field wraps to p - 1
        let target = &BaseFieldElement::from(0u64) - &BaseFieldElement::from(1u64);
        let signer = setup_signer_with_target(target, &mut rng);

        let msg = [0u8; 32];
        assert!(
            signer.create_single_signature(&msg, &mut rng).is_ok(),
            "Lottery with target = p - 1 should always win"
        );
    }
}
