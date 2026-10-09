use std::collections::{BTreeSet, HashSet};

use digest::{Digest, FixedOutput};

use crate::{
    Parameters, RegisterError, SignerIndex, Stake, StmResult, VerificationKeyForConcatenation,
    VerificationKeyProofOfPossessionForConcatenation,
    membership_commitment::{MerkleTree, MerkleTreeLeaf},
    protocol::key_registration::ClosedRegistrationEntry,
};

#[cfg(feature = "snark")]
use crate::VerificationKeyForSnark;

use super::RegistrationEntry;

/// Key Registration
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KeyRegistration {
    registration_entries: BTreeSet<RegistrationEntry>,
    registered_keys_for_concatenation: HashSet<VerificationKeyForConcatenation>,
    #[cfg(feature = "snark")]
    registered_keys_for_snark: HashSet<VerificationKeyForSnark>,
}

impl KeyRegistration {
    /// Initialize an empty registration
    pub fn initialize() -> Self {
        Self {
            registration_entries: Default::default(),
            registered_keys_for_concatenation: Default::default(),
            #[cfg(feature = "snark")]
            registered_keys_for_snark: Default::default(),
        }
    }

    /// Check whether the given `RegistrationEntry` is already registered by looking
    /// at its BLS key.
    /// Insert the new entry if the BLS key is not registered already and return
    /// an error if it is.
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
        if self.registered_keys_for_concatenation.contains(&vk_concatenation) {
            return Err(RegisterError::EntryAlreadyRegistered.into());
        }

        self.registered_keys_for_concatenation.insert(vk_concatenation);
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
        #[cfg(feature = "snark")] schnorr_verification_key: Option<VerificationKeyForSnark>,
    ) -> StmResult<()> {
        let entry = RegistrationEntry::new(
            *vk_pop,
            stake,
            #[cfg(feature = "snark")]
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
        let closed_registration_entries: BTreeSet<ClosedRegistrationEntry> = self
            .registration_entries
            .iter()
            .map(|entry| ClosedRegistrationEntry::try_from((*entry, total_stake, params.phi_f)))
            .collect::<StmResult<BTreeSet<_>>>()?;

        #[cfg(feature = "snark")]
        let closed_registration_entries =
            Self::dedup_snark_verification_keys(closed_registration_entries);

        Ok(ClosedKeyRegistration::new(
            closed_registration_entries,
            total_stake,
        ))
    }

    /// Takes the full list of registered entries and deduplicates the SNARK keys
    /// of those entries, leaving only the entry with the highest stake with the
    /// duplicated snark key.
    #[cfg(feature = "snark")]
    fn dedup_snark_verification_keys(
        entries: BTreeSet<ClosedRegistrationEntry>,
    ) -> BTreeSet<ClosedRegistrationEntry> {
        // `entries` is ordered by (stake, concatenation key): iterating in reverse means the first
        // entry seen for a given SNARK key is the one with the highest stake, so it keeps its key.
        let mut registered_snark_keys = HashSet::new();
        entries
            .into_iter()
            .rev()
            .map(|entry| {
                let is_loser = entry
                    .get_verification_key_for_snark()
                    .is_some_and(|vk_snark| !registered_snark_keys.insert(vk_snark));
                if is_loser {
                    entry.without_snark_fields()
                } else {
                    entry
                }
            })
            .collect()
    }
}

/// Closed Key Registration
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClosedKeyRegistration {
    /// The closed key registration entries
    closed_registration_entries: BTreeSet<ClosedRegistrationEntry>,
    /// The total stake registered
    total_stake: Stake,
}

impl ClosedKeyRegistration {
    pub(crate) fn new(
        closed_registration_entries: BTreeSet<ClosedRegistrationEntry>,
        total_stake: Stake,
    ) -> Self {
        Self {
            closed_registration_entries,
            total_stake,
        }
    }

    /// Gets the total stake registered.
    pub(crate) fn get_total_stake(&self) -> Stake {
        self.total_stake
    }

    /// Creates a Merkle tree from the closed registration entries
    pub(crate) fn to_merkle_tree<D: Digest + FixedOutput, L: MerkleTreeLeaf>(
        &self,
    ) -> MerkleTree<D, L>
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
    pub(crate) fn get_signer_index_for_registration(
        &self,
        entry: &ClosedRegistrationEntry,
    ) -> Option<SignerIndex> {
        self.closed_registration_entries
            .iter()
            .position(|r| r == entry)
            .map(|s| s as u64)
    }

    /// Check if any registration entry has a SNARK verification key.
    #[cfg(feature = "snark")]
    pub(crate) fn has_snark_verification_keys(&self) -> bool {
        self.closed_registration_entries
            .iter()
            .any(|entry| entry.get_verification_key_for_snark().is_some())
    }

    /// Return the number of registered parties.
    #[cfg(feature = "snark")]
    pub(crate) fn number_of_registered_parties(&self) -> usize {
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
    #[cfg(feature = "snark")]
    use rand::random_range;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[cfg(feature = "snark")]
    use crate::{
        Initializer, MithrilMembershipDigest, SchnorrSigningKey, SchnorrVerificationKey,
        proof_system::compute_target_value_for_snark_lottery,
    };
    use crate::{
        Parameters, VerificationKeyProofOfPossessionForConcatenation,
        signature_scheme::BlsSigningKey,
    };

    use super::*;

    #[cfg(feature = "snark")]
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

    #[cfg(feature = "snark")]
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

    #[cfg(feature = "snark")]
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

    #[cfg(feature = "snark")]
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

    #[cfg(feature = "snark")]
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
            #[cfg(feature = "snark")]
            None,
        )
        .unwrap();
        kr.register_by_entry(&first_entry)
            .expect("registering a new verification key should succeed");

        let second_entry = RegistrationEntry::new(
            vk_pop,
            200,
            #[cfg(feature = "snark")]
            None,
        )
        .unwrap();
        let result = kr.register_by_entry(&second_entry);

        assert!(matches!(
            result.unwrap_err().downcast_ref::<RegisterError>(),
            Some(RegisterError::EntryAlreadyRegistered)
        ));
    }

    #[cfg(feature = "snark")]
    #[test]
    fn register_by_entry_accepts_same_snark_key_with_different_concatenation_key() {
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

        kr.register_by_entry(&second_entry)
            .expect("a SNARK key shared with another party should not prevent registration");
    }

    #[cfg(feature = "snark")]
    mod dedup_snark_verification_keys {
        use super::*;

        fn new_schnorr_vk(rng: &mut ChaCha20Rng) -> SchnorrVerificationKey {
            SchnorrVerificationKey::new_from_signing_key(SchnorrSigningKey::generate(rng))
        }

        fn closed_entry(
            stake: Stake,
            schnorr_vk: Option<SchnorrVerificationKey>,
            rng: &mut ChaCha20Rng,
        ) -> ClosedRegistrationEntry {
            let vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
                &BlsSigningKey::generate(rng),
            );
            let entry = RegistrationEntry::new(vk_pop, stake, schnorr_vk).unwrap();
            ClosedRegistrationEntry::try_from((entry, 1_000, 0.2)).unwrap()
        }

        // `BTreeSet` equality compares elements with `PartialEq`, which includes the SNARK
        // fields, so these assertions do distinguish a stripped entry from a kept one.

        #[test]
        fn keeps_the_snark_key_only_on_the_highest_stake_entry() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk = new_schnorr_vk(&mut rng);
            let lower = closed_entry(100, Some(shared_vk), &mut rng);
            let higher = closed_entry(200, Some(shared_vk), &mut rng);

            let result = KeyRegistration::dedup_snark_verification_keys(BTreeSet::from([
                higher.clone(),
                lower.clone(),
            ]));

            assert_eq!(
                BTreeSet::from([lower.without_snark_fields(), higher]),
                result
            );
        }

        #[test]
        fn strips_every_colliding_entry_but_the_highest_stake_one() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk = new_schnorr_vk(&mut rng);
            let lowest = closed_entry(100, Some(shared_vk), &mut rng);
            let middle = closed_entry(200, Some(shared_vk), &mut rng);
            let highest = closed_entry(300, Some(shared_vk), &mut rng);

            let result = KeyRegistration::dedup_snark_verification_keys(BTreeSet::from([
                middle.clone(),
                highest.clone(),
                lowest.clone(),
            ]));

            assert_eq!(
                BTreeSet::from([
                    lowest.without_snark_fields(),
                    highest,
                    middle.without_snark_fields(),
                ]),
                result
            );
        }

        #[test]
        fn breaks_stake_ties_with_the_concatenation_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk = new_schnorr_vk(&mut rng);
            let first = closed_entry(100, Some(shared_vk), &mut rng);
            let second = closed_entry(100, Some(shared_vk), &mut rng);
            let (loser, winner) = if first < second {
                (first, second)
            } else {
                (second, first)
            };

            let result = KeyRegistration::dedup_snark_verification_keys(BTreeSet::from([
                loser.clone(),
                winner.clone(),
            ]));

            assert_eq!(
                BTreeSet::from([winner, loser.without_snark_fields(),]),
                result
            );
        }

        #[test]
        fn leaves_entries_without_collision_untouched() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let without_snark_key = closed_entry(100, None, &mut rng);
            let first_unique_vk = new_schnorr_vk(&mut rng);
            let first_unique = closed_entry(200, Some(first_unique_vk), &mut rng);
            let second_unique_vk = new_schnorr_vk(&mut rng);
            let second_unique = closed_entry(300, Some(second_unique_vk), &mut rng);
            let entries = BTreeSet::from([without_snark_key, first_unique, second_unique]);

            let result = KeyRegistration::dedup_snark_verification_keys(entries.clone());

            assert_eq!(entries, result);
        }
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
                    #[cfg(feature = "snark")]
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
                                Some(RegisterError::EntryAlreadyRegistered) => {
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

        #[cfg(not(feature = "snark"))]
        const GOLDEN_JSON: &str = r#"
        {
            "root":[4, 3, 108, 183, 145, 65, 166, 69, 250, 202, 51, 64, 90, 232, 45, 103, 56, 138, 102, 63, 209, 245, 81, 22, 120, 16, 6, 96, 140, 204, 210, 55],
            "nr_leaves":4,
            "hasher":null
        }"#;

        #[cfg(feature = "snark")]
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

    #[cfg(feature = "snark")]
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

    mod golden_avk_computation {
        use blake2::{Blake2b, digest::consts::U32};

        use crate::{
            Initializer, Parameters,
            membership_commitment::{MerkleTreeBatchCommitment, MerkleTreeConcatenationLeaf},
        };
        #[cfg(feature = "snark")]
        use crate::{
            MidnightPoseidonDigest,
            membership_commitment::{MerkleTreeCommitment, MerkleTreeSnarkLeaf},
        };

        use super::*;

        const GOLDEN_CONCATENATION_AVK_NO_COLLISION: &str = r#"
        {
            "root":[13, 114, 165, 123, 88, 179, 198, 14, 4, 145, 236, 245, 78, 124, 123, 144, 109, 215, 155, 54, 192, 230, 67, 115, 171, 79, 203, 46, 107, 211, 221, 3],
            "nr_leaves":10,
            "hasher":null
        }"#;

        #[cfg(feature = "snark")]
        const GOLDEN_SNARK_AVK_NO_COLLISION: &str = r#"
        {
            "root":[118, 68, 108, 35, 117, 100, 134, 230, 170, 118, 106, 64, 97, 210, 41, 103, 127, 247, 125, 13, 199, 159, 186, 246, 221, 67, 143, 155, 41, 250, 165, 115],
            "hasher":null
        }"#;

        #[cfg(feature = "snark")]
        const GOLDEN_SNARK_AVK_SNARK_KEY_COLLISION: &str = r#"
        {
            "root":[177, 91, 236, 76, 232, 38, 63, 64, 251, 150, 98, 201, 65, 144, 60, 162, 255, 209, 57, 127, 183, 113, 217, 172, 220, 6, 181, 95, 217, 169, 147, 38],
            "hasher":null
        }"#;

        fn closed_key_registration_no_collision() -> ClosedKeyRegistration {
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let number_of_parties = 10;

            let mut key_reg = KeyRegistration::initialize();
            for stake in 0..number_of_parties {
                // rng is recreated for each initializer to prevent the snark feature
                // from modifying the AVK
                let mut rng = ChaCha20Rng::seed_from_u64(stake);
                let initializer = Initializer::new(params, stake, &mut rng);
                key_reg
                    .register_by_entry(&initializer.clone().try_into().unwrap())
                    .unwrap();
            }

            key_reg.close_registration(&params).unwrap()
        }

        /// Same parties as `closed_key_registration_no_collision` (party `i` has stake `i`), with
        /// two SNARK key collisions:
        /// - 3-way: parties 2 and 5 are given the SNARK key of party 8, which keeps it.
        /// - 2-way: party 1 is given the SNARK key of party 6, which keeps it.
        #[cfg(feature = "snark")]
        fn closed_key_registration_snark_key_collision() -> ClosedKeyRegistration {
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let number_of_parties = 10;

            let mut initializers: Vec<Initializer> = (0..number_of_parties)
                .map(|stake| {
                    // rng is recreated for each initializer to prevent the snark feature
                    // from modifying the AVK
                    let mut rng = ChaCha20Rng::seed_from_u64(stake);
                    Initializer::new(params, stake, &mut rng)
                })
                .collect();
            for (receiver, owner) in [(2, 8), (5, 8), (1, 6)] {
                initializers[receiver].schnorr_signing_key =
                    initializers[owner].schnorr_signing_key.clone();
                initializers[receiver].schnorr_verification_key =
                    initializers[owner].schnorr_verification_key;
            }

            let mut key_reg = KeyRegistration::initialize();
            for initializer in initializers {
                key_reg.register_by_entry(&initializer.try_into().unwrap()).unwrap();
            }

            key_reg.close_registration(&params).unwrap()
        }

        fn golden_concatenation_avk_no_collision()
        -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
            closed_key_registration_no_collision()
                .to_merkle_tree()
                .to_merkle_tree_batch_commitment()
        }

        #[cfg(feature = "snark")]
        fn golden_snark_avk_no_collision()
        -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
            closed_key_registration_no_collision()
                .to_merkle_tree()
                .to_merkle_tree_commitment()
        }

        fn golden_concatenation_avk_snark_key_collision()
        -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
            closed_key_registration_snark_key_collision()
                .to_merkle_tree()
                .to_merkle_tree_batch_commitment()
        }

        #[cfg(feature = "snark")]
        fn golden_snark_avk_snark_key_collision()
        -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
            closed_key_registration_snark_key_collision()
                .to_merkle_tree()
                .to_merkle_tree_commitment()
        }

        #[test]
        fn golden_concatenation_computation_no_collision() {
            let value = serde_json::from_str(GOLDEN_CONCATENATION_AVK_NO_COLLISION)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_concatenation_avk_no_collision(), value);
        }

        #[test]
        fn golden_snark_computation_no_collision() {
            let value = serde_json::from_str(GOLDEN_SNARK_AVK_NO_COLLISION)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_snark_avk_no_collision(), value);
        }

        #[test]
        fn golden_concatenation_computation_snark_key_collision() {
            let value = serde_json::from_str(GOLDEN_CONCATENATION_AVK_NO_COLLISION)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_concatenation_avk_snark_key_collision(), value);
        }

        #[test]
        fn golden_snark_computation_snark_key_collision() {
            let value = serde_json::from_str(GOLDEN_SNARK_AVK_SNARK_KEY_COLLISION)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_snark_avk_snark_key_collision(), value);
        }
    }
}
