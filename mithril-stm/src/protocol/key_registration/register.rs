use std::collections::{BTreeSet, HashSet};

use digest::{Digest, FixedOutput};

use crate::{
    Parameters, RegisterError, SignerIndex, Stake, StmResult, VerificationKeyForConcatenation,
    VerificationKeyProofOfPossessionForConcatenation,
    membership_commitment::{MerkleTree, MerkleTreeLeaf},
    protocol::key_registration::ClosedRegistrationEntry,
};

#[cfg(feature = "future_snark")]
use crate::VerificationKeyForSnark;

use super::RegistrationEntry;

/// Key Registration
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KeyRegistration {
    registration_entries: BTreeSet<RegistrationEntry>,
    registered_keys_for_concatenation: HashSet<VerificationKeyForConcatenation>,
    #[cfg(feature = "future_snark")]
    registered_keys_for_snark: HashSet<VerificationKeyForSnark>,
}

impl KeyRegistration {
    /// Initialize an empty registration
    pub fn initialize() -> Self {
        Self {
            registration_entries: Default::default(),
            registered_keys_for_concatenation: Default::default(),
            #[cfg(feature = "future_snark")]
            registered_keys_for_snark: Default::default(),
        }
    }

    /// Check whether the given `RegistrationEntry` is already registered.
    /// Insert the new entry if all checks pass.
    ///
    /// This is `pub(crate)` rather than `pub`: it trusts that `entry` was produced through a
    /// path that already verified proof of possession (`RegistrationEntry::new`), which every
    /// internal caller does. Exposing it publicly would let external callers register an entry
    /// obtained without that verification (e.g. via deserialization), so external registration
    /// must go through [`KeyRegistration::register`] instead, which always constructs the entry
    /// itself via `RegistrationEntry::new`.
    /// # Error
    /// The function fails when the entry is already registered.
    pub(crate) fn register_by_entry(&mut self, entry: &RegistrationEntry) -> StmResult<()> {
        let vk_concatenation = entry.get_verification_key_for_concatenation();
        let is_already_registered =
            self.registered_keys_for_concatenation.contains(&vk_concatenation);

        #[cfg(feature = "future_snark")]
        let is_already_registered = is_already_registered
            || entry
                .get_verification_key_for_snark()
                .is_some_and(|vk_snark| self.registered_keys_for_snark.contains(&vk_snark));

        if is_already_registered {
            return Err(RegisterError::EntryAlreadyRegistered(Box::new(*entry)).into());
        }

        self.registered_keys_for_concatenation.insert(vk_concatenation);
        #[cfg(feature = "future_snark")]
        if let Some(vk_snark) = entry.get_verification_key_for_snark() {
            self.registered_keys_for_snark.insert(vk_snark);
        }
        self.registration_entries.insert(*entry);

        Ok(())
    }

    /// Registers a new signer with the given verification key proof of possession and stake.
    /// This function only works for concatenation proof system.
    /// The purpose of this function is to simplify the process for the rest of the codebase.
    pub fn register(
        &mut self,
        stake: Stake,
        vk_pop: &VerificationKeyProofOfPossessionForConcatenation,
        #[cfg(feature = "future_snark")] schnorr_verification_key: Option<VerificationKeyForSnark>,
    ) -> StmResult<()> {
        let entry = RegistrationEntry::new(
            *vk_pop,
            stake,
            #[cfg(feature = "future_snark")]
            schnorr_verification_key,
        )?;
        self.register_by_entry(&entry)
    }

    /// Closes the registration
    /// Computes the total stake and converts the registration entries into closed registration
    /// entries.
    ///
    /// Returns the `ClosedKeyRegistration`.
    pub fn close_registration(self, params: &Parameters) -> StmResult<ClosedKeyRegistration> {
        let total_stake: Stake =
            self.registration_entries.iter().try_fold(0u64, |acc, entry| {
                acc.checked_add(entry.get_stake())
                    .ok_or(RegisterError::TotalStakeOverflow {
                        accumulated_stake: acc,
                        stake: entry.get_stake(),
                    })
            })?;
        if total_stake == 0 {
            return Err(RegisterError::ZeroTotalStake.into());
        }
        let closed_registration_entries: StmResult<BTreeSet<ClosedRegistrationEntry>> = self
            .registration_entries
            .iter()
            .map(|entry| ClosedRegistrationEntry::try_from((*entry, total_stake, params.phi_f)))
            .collect();

        Ok(ClosedKeyRegistration::new(closed_registration_entries?, total_stake))
    }
}

/// Closed Key Registration
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClosedKeyRegistration {
    closed_registration_entries: BTreeSet<ClosedRegistrationEntry>,
    total_stake: Stake,
}

impl ClosedKeyRegistration {
    /// Creates a new `ClosedKeyRegistration`.
    ///
    /// This is `pub(crate)` rather than `pub`: `closed_registration_entries` carries
    /// verification keys with no guarantee of proof of possession unless it was built from a
    /// [`KeyRegistration`], which only ever admits verified entries. Exposing this publicly
    /// would let external callers assemble a forged registration (e.g. with a rogue key) and
    /// feed it directly into the aggregation/verification pipeline, bypassing `KeyRegistration`
    /// entirely.
    pub(crate) fn new(
        closed_registration_entries: BTreeSet<ClosedRegistrationEntry>,
        total_stake: Stake,
    ) -> Self {
        Self {
            closed_registration_entries,
            total_stake,
        }
    }

    /// Gets the closed registration entries.
    pub fn get_closed_registration_entries(&self) -> &BTreeSet<ClosedRegistrationEntry> {
        &self.closed_registration_entries
    }

    /// Gets the total stake registered.
    pub fn get_total_stake(&self) -> Stake {
        self.total_stake
    }

    /// Creates a Merkle tree from the closed registration entries
    pub fn to_merkle_tree<D: Digest + FixedOutput, L: MerkleTreeLeaf>(&self) -> MerkleTree<D, L>
    where
        Option<L>: From<ClosedRegistrationEntry>,
    {
        MerkleTree::new(
            &self
                .closed_registration_entries
                .iter()
                .filter_map(|entry| (*entry).clone().into())
                .collect::<Vec<L>>(),
        )
    }

    /// Gets the index of given closed registration entry.
    pub fn get_signer_index_for_registration(
        &self,
        entry: &ClosedRegistrationEntry,
    ) -> Option<SignerIndex> {
        self.closed_registration_entries
            .iter()
            .position(|r| r == entry)
            .map(|s| s as u64)
    }

    /// Check if any registration entry has a SNARK verification key.
    #[cfg(feature = "future_snark")]
    pub fn has_snark_verification_keys(&self) -> bool {
        self.closed_registration_entries
            .iter()
            .any(|entry| entry.get_verification_key_for_snark().is_some())
    }

    /// Return the number of registered parties.
    pub fn number_of_registered_parties(&self) -> usize {
        self.closed_registration_entries.len()
    }

    /// Get the closed registration entry for a given signer index.
    pub fn get_registration_entry_for_index(
        &self,
        signer_index: &SignerIndex,
    ) -> StmResult<ClosedRegistrationEntry> {
        self.closed_registration_entries
            .iter()
            .nth(*signer_index as usize)
            .cloned()
            .ok_or_else(|| RegisterError::UnregisteredIndex.into())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    #[cfg(feature = "future_snark")]
    use rand::random_range;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[cfg(feature = "future_snark")]
    use crate::{
        Initializer, MithrilMembershipDigest, SchnorrSigningKey, SchnorrVerificationKey,
        proof_system::compute_target_value_for_snark_lottery,
    };
    use crate::{
        Parameters, VerificationKeyProofOfPossessionForConcatenation,
        signature_scheme::BlsSigningKey,
    };

    use super::*;

    #[cfg(feature = "future_snark")]
    fn prepare_key_registration_with_stakes(stakes: Vec<u64>) -> KeyRegistration {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut kr = KeyRegistration::initialize();

        for stake in stakes {
            let bls_vk = VerificationKeyProofOfPossessionForConcatenation::from(
                &BlsSigningKey::generate(&mut rng),
            );
            let schnorr_vk =
                SchnorrVerificationKey::new_from_signing_key(SchnorrSigningKey::generate(&mut rng));
            let entry = RegistrationEntry::new(bls_vk, stake, Some(schnorr_vk)).unwrap();
            kr.register_by_entry(&entry)
                .expect("Registering an entry in tests should succeed.");
        }
        kr
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn close_registration_computes_same_target_value() {
        let nb_entries = 5;
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 0.2,
        };

        let stakes: Vec<u64> = (0..nb_entries).map(|_| random_range(10..100)).collect();
        let kr = prepare_key_registration_with_stakes(stakes);
        let closed_registration = kr.clone().close_registration(&params).unwrap();
        let total_stake = closed_registration.total_stake;

        for (closed_entry, entry) in closed_registration
            .closed_registration_entries
            .iter()
            .zip(kr.registration_entries)
        {
            let stake = closed_entry.get_stake();
            let target_value_from_registration = closed_entry.get_lottery_target_value().unwrap();

            let target_value_from_try_from =
                ClosedRegistrationEntry::try_from((entry, total_stake, params.phi_f))
                    .unwrap()
                    .get_lottery_target_value()
                    .unwrap();

            let target_value_from_eligibility =
                compute_target_value_for_snark_lottery(params.phi_f, stake, total_stake).unwrap();

            assert_eq!(
                target_value_from_eligibility,
                target_value_from_registration
            );
            assert_eq!(target_value_from_eligibility, target_value_from_try_from);
        }
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn close_registration_zero_total_stake_fails() {
        let nb_entries = 5;
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 0.2,
        };
        let stakes: Vec<u64> = vec![0; nb_entries];
        let kr = prepare_key_registration_with_stakes(stakes);
        let closed_registration = kr.close_registration(&params);

        assert!(closed_registration.is_err());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn closing_registration_without_entries_fails() {
        let kr = KeyRegistration::initialize();
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 0.2,
        };

        let closed_registration = kr.close_registration(&params);

        assert!(closed_registration.is_err());
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn signer_creation_fails_for_initializer_with_diff_param() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut kr = KeyRegistration::initialize();
        let nkeys = 5;
        let params = Parameters {
            m: 100,
            k: 10,
            phi_f: 0.2,
        };
        let stakes: Vec<u64> = (0..nkeys).map(|_| random_range(10..100)).collect();
        let mut initializers = vec![];
        let forged_params = Parameters {
            phi_f: 1.0,
            ..params
        };
        for (i, stake) in stakes.into_iter().enumerate() {
            let init = if i == 0 {
                Initializer::new(forged_params, stake, &mut rng)
            } else {
                Initializer::new(params, stake, &mut rng)
            };
            let entry = RegistrationEntry::new(
                init.get_verification_key_proof_of_possession_for_concatenation(),
                stake,
                init.get_verification_key_for_snark(),
            )
            .unwrap();
            kr.register_by_entry(&entry).unwrap();
            initializers.push(init);
        }

        let closed_registration = kr.clone().close_registration(&params).unwrap();

        for (i, init) in initializers.into_iter().enumerate() {
            if i == 0 {
                let result_signer =
                    init.try_create_signer::<MithrilMembershipDigest>(&closed_registration);

                assert!(result_signer.is_err());
            } else {
                let result_signer =
                    init.try_create_signer::<MithrilMembershipDigest>(&closed_registration);

                assert!(result_signer.is_ok());
            }
        }
    }

    #[test]
    fn register_by_entry_rejects_same_verification_key_with_different_stake() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut kr = KeyRegistration::initialize();
        let vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
            &BlsSigningKey::generate(&mut rng),
        );

        let first_entry = RegistrationEntry::new(
            vk_pop,
            100,
            #[cfg(feature = "future_snark")]
            None,
        )
        .unwrap();
        kr.register_by_entry(&first_entry)
            .expect("registering a new verification key should succeed");

        let second_entry = RegistrationEntry::new(
            vk_pop,
            200,
            #[cfg(feature = "future_snark")]
            None,
        )
        .unwrap();
        let result = kr.register_by_entry(&second_entry);

        assert!(matches!(
            result.unwrap_err().downcast_ref::<RegisterError>(),
            Some(RegisterError::EntryAlreadyRegistered(_))
        ));
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn register_by_entry_rejects_same_snark_key_with_different_concatenation_key() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut kr = KeyRegistration::initialize();
        let schnorr_vk =
            SchnorrVerificationKey::new_from_signing_key(SchnorrSigningKey::generate(&mut rng));

        let first_vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
            &BlsSigningKey::generate(&mut rng),
        );
        let first_entry = RegistrationEntry::new(first_vk_pop, 100, Some(schnorr_vk)).unwrap();
        kr.register_by_entry(&first_entry)
            .expect("registering a new verification key pair should succeed");

        let second_vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
            &BlsSigningKey::generate(&mut rng),
        );
        let second_entry = RegistrationEntry::new(second_vk_pop, 200, Some(schnorr_vk)).unwrap();
        let result = kr.register_by_entry(&second_entry);

        assert!(matches!(
            result.unwrap_err().downcast_ref::<RegisterError>(),
            Some(RegisterError::EntryAlreadyRegistered(_))
        ));
    }

    proptest! {
        #[test]
        fn test_keyreg(stake in vec(1..1u64 << 60, 2..=10),
                       nkeys in 2..10_usize,
                       fake_it in 0..4usize,
                       seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut kr = KeyRegistration::initialize();

            let params = Parameters {
                m: 20,
                k: 10,
                phi_f: 0.2
            };

            let gen_keys = (1..nkeys).map(|_| {
                let sk = BlsSigningKey::generate(&mut rng);
                VerificationKeyProofOfPossessionForConcatenation::from(&sk)
            }).collect::<Vec<_>>();

            let fake_key = {
                let sk = BlsSigningKey::generate(&mut rng);
                VerificationKeyProofOfPossessionForConcatenation::from(&sk)
            };

            // Record successful registrations, keyed by verification key since that's
            // the uniqueness criterion enforced by register_by_entry
            let mut keys = BTreeSet::new();
            let mut registered_entries = BTreeSet::new();

            for (i, &stake) in stake.iter().enumerate() {
                let mut pk = gen_keys[i % gen_keys.len()];

                if fake_it == 0 {
                    pk.pop = fake_key.pop;
                }

                let entry_result = RegistrationEntry::new(pk, stake,
                    #[cfg(feature = "future_snark")]
                    None,
                );

                match entry_result {
                    Ok(entry) => {
                        let vk = entry.get_verification_key_for_concatenation();
                        let reg = kr.register_by_entry(&entry);
                        match reg {
                            Ok(_) => {
                                assert!(keys.insert(vk));
                                assert!(registered_entries.insert(entry));
                            },
                            Err(error) => match error.downcast_ref::<RegisterError>(){
                                Some(RegisterError::EntryAlreadyRegistered(e1)) => {
                                    assert!(e1.as_ref() == &entry);
                                    assert!(keys.contains(&vk));
                                },
                                _ => {panic!("Unexpected error: {error}")}
                            }
                        }
                    },
                    Err(error) =>  match error.downcast_ref::<RegisterError>(){
                        Some(RegisterError::ConcatenationKeyInvalid(a)) => {
                            assert_eq!(fake_it, 0);
                            assert!(pk.verify_proof_of_possession().is_err());
                            assert!(a.as_ref() == &pk.vk);
                        },
                        _ => {panic!("Unexpected error: {error}")}
                    }
                }
            }

            if !kr.registration_entries.is_empty() {
                let closed = kr.close_registration(&params).unwrap();
                let retrieved_keys = closed.closed_registration_entries.iter()
                    .map(|entry| (*entry).clone().into())
                    .collect::<BTreeSet<RegistrationEntry>>();
                assert!(retrieved_keys == registered_entries);
            }
        }
    }

    mod golden_concatenation {
        use blake2::{Blake2b, digest::consts::U32};

        use crate::{
            Initializer, Parameters,
            membership_commitment::{MerkleTreeBatchCommitment, MerkleTreeConcatenationLeaf},
        };

        use super::*;

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_JSON: &str = r#"
        {
            "root":[4, 3, 108, 183, 145, 65, 166, 69, 250, 202, 51, 64, 90, 232, 45, 103, 56, 138, 102, 63, 209, 245, 81, 22, 120, 16, 6, 96, 140, 204, 210, 55],
            "nr_leaves":4,
            "hasher":null
        }"#;

        #[cfg(feature = "future_snark")]
        const GOLDEN_JSON: &str = r#"
        {
            "root":[158, 184, 253, 192, 166, 114, 131, 175, 47, 113, 177, 244, 199, 200, 209, 129, 182, 191, 192, 91, 213, 10, 28, 172, 164, 139, 212, 51, 248, 66, 158, 36],
            "nr_leaves":4,
            "hasher":null
        }"#;

        fn golden_value() -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let number_of_parties = 4;

            let mut key_reg = KeyRegistration::initialize();
            for stake in 0..number_of_parties {
                let initializer = Initializer::new(params, stake, &mut rng);
                key_reg
                    .register_by_entry(&initializer.clone().try_into().unwrap())
                    .unwrap();
            }

            let closed_key_reg: ClosedKeyRegistration =
                key_reg.close_registration(&params).unwrap();
            closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment()
        }

        #[test]
        fn golden_conversions() {
            let value = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_value(), value);

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }
    }

    #[cfg(feature = "future_snark")]
    mod golden_snark {

        use crate::{
            Initializer, MidnightPoseidonDigest, Parameters,
            membership_commitment::{MerkleTreeCommitment, MerkleTreeSnarkLeaf},
        };

        use super::*;

        const GOLDEN_JSON: &str = r#"
        {
            "root":[165,121,179,134,45,169,200,53,27,170,110,123,40,15,191,138,219,249,100,108,146,170,70,116,200,250,155,134,5,242,23,63],
            "hasher":null
        }"#;

        fn golden_value() -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let number_of_parties = 4;

            let mut key_reg = KeyRegistration::initialize();
            for stake in 0..number_of_parties {
                let initializer = Initializer::new(params, stake, &mut rng);
                key_reg
                    .register_by_entry(&initializer.clone().try_into().unwrap())
                    .unwrap();
            }

            let closed_key_reg: ClosedKeyRegistration =
                key_reg.close_registration(&params).unwrap();
            closed_key_reg
                .to_merkle_tree::<MidnightPoseidonDigest, MerkleTreeSnarkLeaf>()
                .to_merkle_tree_commitment()
        }

        #[test]
        fn golden_conversions() {
            let value = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_value(), value);

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }
    }
}
