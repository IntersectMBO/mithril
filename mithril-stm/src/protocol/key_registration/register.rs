use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::{Digest, FixedOutput};

use crate::{
    Parameters, RegisterError, SignerIndex, Stake, StmResult,
    VerificationKeyProofOfPossessionForConcatenation,
    membership_commitment::{MerkleTree, MerkleTreeLeaf},
    protocol::key_registration::ClosedRegistrationEntry,
};

#[cfg(feature = "snark")]
use crate::VerificationKeyForSnark;

#[cfg(feature = "snark")]
use super::RegistrationEntryForSnark;
use super::{RegistrationEntry, RegistrationEntryForConcatenation};

/// Key Registration
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KeyRegistration {
    registration_entries: BTreeSet<RegistrationEntry>,
}

impl KeyRegistration {
    /// Initialize an empty registration
    pub fn initialize() -> Self {
        Self {
            registration_entries: Default::default(),
        }
    }

    /// Insert the given `RegistrationEntry`.
    ///
    /// Entries sharing a key are all accepted, the key collisions are resolved when closing the
    /// registration.
    ///
    /// This is `pub(crate)` rather than `pub`: it trusts that `entry` was produced through a
    /// path that already verified proof of possession (`RegistrationEntry::new`), which every
    /// internal caller does. Exposing it publicly would let external callers register an entry
    /// obtained without that verification (e.g. via deserialization), so external registration
    /// must go through [`KeyRegistration::register`] instead, which always constructs the entry
    /// itself via `RegistrationEntry::new`.
    pub(crate) fn register_by_entry(&mut self, entry: &RegistrationEntry) {
        self.registration_entries.insert(*entry);
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
        self.register_by_entry(&entry);

        Ok(())
    }

    /// Closes the registration.
    ///
    /// Each proof system keeps, for each of its keys, the entry with the highest stake holding
    /// it, computes its total stake on the kept entries and closes them. The SNARK proof system
    /// is absent when no entry with a SNARK key has any stake.
    ///
    /// # Error
    /// The function fails when there is no entry, when the parameters are invalid, when the total
    /// stake of all the entries overflows or when the Concatenation total stake is zero.
    pub fn close_registration(self, params: &Parameters) -> StmResult<ClosedKeyRegistration> {
        // TODO: decide whether entries with a zero stake should be rejected at registration. They
        // never win a lottery, but still get a leaf in the Merkle trees.
        if self.registration_entries.is_empty() {
            return Err(RegisterError::EmptyRegistration.into());
        }
        params.validate()?;
        self.check_total_stake_registered()?;

        let deduplicated_entries_for_concatenation =
            Self::deduplicate_concatenation_keys_from_entries(&self.registration_entries);

        let closed_key_registration_for_concatenation = ClosedRegistrationForProofSystem::try_new(
            params,
            &deduplicated_entries_for_concatenation,
        )?;

        #[cfg(feature = "snark")]
        let deduplicated_entries_for_snark =
            Self::deduplicate_snark_keys_from_entries(&self.registration_entries);

        // TODO: Once the SNARK registration is mandatory, return the error instead of
        // converting to an option.
        #[cfg(feature = "snark")]
        let closed_key_registration_for_snark =
            ClosedRegistrationForProofSystem::try_new(params, &deduplicated_entries_for_snark).ok();

        Ok(ClosedKeyRegistration::new(
            closed_key_registration_for_concatenation,
            #[cfg(feature = "snark")]
            closed_key_registration_for_snark,
        ))
    }

    /// Keeps only the entries with a SNARK key and with the highest stake.
    #[cfg(feature = "snark")]
    fn deduplicate_snark_keys_from_entries(
        entries: &BTreeSet<RegistrationEntry>,
    ) -> BTreeSet<RegistrationEntry> {
        let mut already_registered_keys = HashSet::new();
        entries
            .iter()
            .rev()
            .filter(|entry| {
                entry
                    .get_verification_key_for_snark()
                    .is_some_and(|vk_snark| already_registered_keys.insert(vk_snark))
            })
            .cloned()
            .collect()
    }

    /// Keeps, for each Concatenation key, the entry with the highest stake.
    fn deduplicate_concatenation_keys_from_entries(
        entries: &BTreeSet<RegistrationEntry>,
    ) -> BTreeSet<RegistrationEntry> {
        let mut already_registered_keys = HashSet::new();
        entries
            .iter()
            .rev()
            .filter(|entry| {
                already_registered_keys.insert(entry.get_verification_key_for_concatenation())
            })
            .cloned()
            .collect()
    }

    /// Checks that the total stake registered does not overflow the `u64` limit
    fn check_total_stake_registered(&self) -> StmResult<()> {
        self.registration_entries.iter().try_fold(0u64, |acc, entry| {
            acc.checked_add(entry.get_stake())
                .ok_or(RegisterError::TotalStakeOverflow {
                    accumulated_stake: acc,
                    stake: entry.get_stake(),
                })
        })?;
        Ok(())
    }
}

/// Structure holding the ClosedRegistration of each proof system
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClosedKeyRegistration {
    /// The closed registration of the Concatenation proof system
    closed_key_registration_for_concatenation:
        ClosedRegistrationForProofSystem<RegistrationEntryForConcatenation>,
    /// The closed registration of the SNARK proof system, `None` when it cannot be closed
    #[cfg(feature = "snark")]
    closed_key_registration_for_snark:
        Option<ClosedRegistrationForProofSystem<RegistrationEntryForSnark>>,
}

impl ClosedKeyRegistration {
    pub(crate) fn new(
        closed_key_registration_for_concatenation: ClosedRegistrationForProofSystem<
            RegistrationEntryForConcatenation,
        >,
        #[cfg(feature = "snark")] closed_key_registration_for_snark: Option<
            ClosedRegistrationForProofSystem<RegistrationEntryForSnark>,
        >,
    ) -> Self {
        Self {
            closed_key_registration_for_concatenation,
            #[cfg(feature = "snark")]
            closed_key_registration_for_snark,
        }
    }

    /// Gets the closed registration of the Concatenation proof system.
    pub(crate) fn get_closed_key_registration_for_concatenation(
        &self,
    ) -> &ClosedRegistrationForProofSystem<RegistrationEntryForConcatenation> {
        &self.closed_key_registration_for_concatenation
    }

    /// Gets the closed registration of the SNARK proof system, `None` when no entry with a SNARK
    /// key has any stake.
    #[cfg(feature = "snark")]
    pub(crate) fn get_closed_key_registration_for_snark(
        &self,
    ) -> Option<&ClosedRegistrationForProofSystem<RegistrationEntryForSnark>> {
        self.closed_key_registration_for_snark.as_ref()
    }
}

/// Closed registration of a proof system: its deduplicated entries and their total stake.
pub struct ClosedRegistrationForProofSystem<L: MerkleTreeLeaf> {
    deduplicated_entries: BTreeSet<ClosedRegistrationEntry>,
    total_stake: Stake,
    leaf_type: PhantomData<L>,
}

impl<L: MerkleTreeLeaf> ClosedRegistrationForProofSystem<L> {
    /// Computes the total stake of the given deduplicated entries and closes them with it.
    ///
    /// # Error
    /// The function fails when the total stake is zero, or when a lottery target cannot be
    /// computed.
    pub(crate) fn try_new(
        params: &Parameters,
        deduplicated_entries: &BTreeSet<RegistrationEntry>,
    ) -> StmResult<Self> {
        let total_stake: Stake = deduplicated_entries.iter().map(|entry| entry.get_stake()).sum();

        if total_stake == 0 {
            return Err(RegisterError::ZeroTotalStake.into());
        }

        Ok(Self {
            deduplicated_entries: deduplicated_entries
                .iter()
                .map(|entry| ClosedRegistrationEntry::try_from((*entry, total_stake, params.phi_f)))
                .collect::<StmResult<BTreeSet<_>>>()?,
            total_stake,
            leaf_type: PhantomData,
        })
    }

    /// Gets the total stake of the entries.
    pub(crate) fn get_total_stake(&self) -> Stake {
        self.total_stake
    }

    /// Creates the Merkle tree of the proof system.
    pub(crate) fn to_merkle_tree<D: Digest + FixedOutput>(&self) -> MerkleTree<D, L>
    where
        L: MerkleTreeLeaf,
        Option<L>: From<ClosedRegistrationEntry>,
    {
        MerkleTree::new(
            &self
                .deduplicated_entries
                .iter()
                .filter_map(|entry| entry.clone().into())
                .collect::<Vec<L>>(),
        )
    }

    /// Return the number of leaves of the Merkle tree.
    #[cfg(feature = "snark")]
    pub(crate) fn number_of_leaves(&self) -> usize {
        self.deduplicated_entries.len()
    }

    /// Gets the index of the given closed registration entry, which is also its leaf position in
    /// the Merkle tree.
    pub(crate) fn get_signer_index_for_registration(
        &self,
        entry: &ClosedRegistrationEntry,
    ) -> Option<SignerIndex> {
        self.deduplicated_entries
            .iter()
            .position(|registered_entry| registered_entry == entry)
            .map(|index| index as SignerIndex)
    }

    /// Get the closed registration entry for a given index.
    pub(crate) fn get_registration_entry_for_index(
        &self,
        signer_index: &SignerIndex,
    ) -> StmResult<ClosedRegistrationEntry> {
        self.deduplicated_entries
            .iter()
            .nth(*signer_index as usize)
            .cloned()
            .ok_or_else(|| RegisterError::UnregisteredIndex.into())
    }
}

impl<L: MerkleTreeLeaf> Clone for ClosedRegistrationForProofSystem<L> {
    fn clone(&self) -> Self {
        Self {
            deduplicated_entries: self.deduplicated_entries.clone(),
            total_stake: self.total_stake,
            leaf_type: PhantomData,
        }
    }
}

impl<L: MerkleTreeLeaf> Debug for ClosedRegistrationForProofSystem<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosedRegistrationForProofSystem")
            .field("deduplicated_entries", &self.deduplicated_entries)
            .field("total_stake", &self.total_stake)
            .finish()
    }
}

impl<L: MerkleTreeLeaf> PartialEq for ClosedRegistrationForProofSystem<L> {
    fn eq(&self, other: &Self) -> bool {
        self.deduplicated_entries == other.deduplicated_entries
            && self.total_stake == other.total_stake
    }
}

impl<L: MerkleTreeLeaf> Eq for ClosedRegistrationForProofSystem<L> {}

impl<L: MerkleTreeLeaf> PartialOrd for ClosedRegistrationForProofSystem<L> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<L: MerkleTreeLeaf> Ord for ClosedRegistrationForProofSystem<L> {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.deduplicated_entries, self.total_stake)
            .cmp(&(&other.deduplicated_entries, other.total_stake))
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
    const PHI_F: f64 = 0.2;

    fn new_vk_pop(rng: &mut ChaCha20Rng) -> VerificationKeyProofOfPossessionForConcatenation {
        VerificationKeyProofOfPossessionForConcatenation::from(&BlsSigningKey::generate(rng))
    }

    #[cfg(feature = "snark")]
    fn new_schnorr_vk(rng: &mut ChaCha20Rng) -> SchnorrVerificationKey {
        SchnorrVerificationKey::new_from_signing_key(SchnorrSigningKey::generate(rng))
    }

    fn entry(
        vk_pop: VerificationKeyProofOfPossessionForConcatenation,
        stake: Stake,
    ) -> RegistrationEntry {
        RegistrationEntry::new(
            vk_pop,
            stake,
            #[cfg(feature = "snark")]
            None,
        )
        .unwrap()
    }

    #[cfg(feature = "snark")]
    fn entry_with_snark_key(
        vk_pop: VerificationKeyProofOfPossessionForConcatenation,
        stake: Stake,
        schnorr_vk: SchnorrVerificationKey,
    ) -> RegistrationEntry {
        RegistrationEntry::new(vk_pop, stake, Some(schnorr_vk)).unwrap()
    }

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
            kr.register_by_entry(&entry);
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
        let total_stake = closed_registration
            .closed_key_registration_for_concatenation
            .total_stake;

        for (closed_entry, entry) in closed_registration
            .closed_key_registration_for_concatenation
            .deduplicated_entries
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

    #[test]
    fn closing_registration_without_entries_fails() {
        let kr = KeyRegistration::initialize();
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 0.2,
        };

        let error = kr
            .close_registration(&params)
            .expect_err("closing a registration without entry should fail");

        assert!(matches!(
            error.downcast_ref::<RegisterError>(),
            Some(RegisterError::EmptyRegistration)
        ));
    }

    #[test]
    fn closing_registration_with_invalid_parameters_fails() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut kr = KeyRegistration::initialize();
        kr.register_by_entry(&entry(new_vk_pop(&mut rng), 100));
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 1.5,
        };

        let error = kr
            .close_registration(&params)
            .expect_err("closing a registration with invalid parameters should fail");

        assert!(matches!(
            error.downcast_ref::<crate::protocol::ProtocolError>(),
            Some(crate::protocol::ProtocolError::PhiFValueOutOfRange(_))
        ));
    }

    #[test]
    fn closing_registration_fails_when_the_total_stake_of_all_entries_overflows() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let shared_vk_pop = new_vk_pop(&mut rng);
        // The BLS key collision loser is dropped from the Concatenation entries, so the
        // deduplicated total stake alone would not overflow.
        let winner = entry(shared_vk_pop, u64::MAX);
        let loser = entry(shared_vk_pop, 1);
        let mut kr = KeyRegistration::initialize();
        kr.register_by_entry(&winner);
        kr.register_by_entry(&loser);
        let params = Parameters {
            m: 20,
            k: 10,
            phi_f: 0.2,
        };

        let error = kr
            .close_registration(&params)
            .expect_err("an overflowing total stake should be rejected");

        assert!(matches!(
            error.downcast_ref::<RegisterError>(),
            Some(RegisterError::TotalStakeOverflow { .. })
        ));
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
            kr.register_by_entry(&entry);
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
    fn register_by_entry_accepts_same_verification_key_with_different_stake() {
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
        kr.register_by_entry(&first_entry);

        let second_entry = RegistrationEntry::new(
            vk_pop,
            200,
            #[cfg(feature = "snark")]
            None,
        )
        .unwrap();

        kr.register_by_entry(&second_entry);
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
        kr.register_by_entry(&first_entry);

        let second_vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
            &BlsSigningKey::generate(&mut rng),
        );
        let second_entry = RegistrationEntry::new(second_vk_pop, 200, Some(schnorr_vk)).unwrap();

        kr.register_by_entry(&second_entry);
    }

    mod deduplicate_concatenation_keys {
        use super::*;

        #[test]
        fn keeps_only_the_highest_stake_entry_for_a_shared_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let lowest = entry(shared_vk_pop, 100);
            let middle = entry(shared_vk_pop, 200);
            let highest = entry(shared_vk_pop, 300);

            let result =
                KeyRegistration::deduplicate_concatenation_keys_from_entries(&BTreeSet::from([
                    middle, highest, lowest,
                ]));

            assert_eq!(BTreeSet::from([highest]), result);
        }

        #[test]
        fn only_removes_entries_sharing_a_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let colliding_lower = entry(shared_vk_pop, 100);
            let colliding_higher = entry(shared_vk_pop, 300);
            let unique = entry(new_vk_pop(&mut rng), 200);

            let result =
                KeyRegistration::deduplicate_concatenation_keys_from_entries(&BTreeSet::from([
                    colliding_lower,
                    unique,
                    colliding_higher,
                ]));

            assert_eq!(BTreeSet::from([unique, colliding_higher]), result);
        }

        #[test]
        fn leaves_entries_without_collision_untouched() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entries = BTreeSet::from([
                entry(new_vk_pop(&mut rng), 100),
                entry(new_vk_pop(&mut rng), 200),
                entry(new_vk_pop(&mut rng), 300),
            ]);

            let result = KeyRegistration::deduplicate_concatenation_keys_from_entries(&entries);

            assert_eq!(entries, result);
        }

        #[cfg(feature = "snark")]
        #[test]
        fn keeps_the_snark_fields_of_the_winning_entry() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let schnorr_vk = new_schnorr_vk(&mut rng);
            let lower = entry(shared_vk_pop, 100);
            let higher = entry_with_snark_key(shared_vk_pop, 200, schnorr_vk);

            let result =
                KeyRegistration::deduplicate_concatenation_keys_from_entries(&BTreeSet::from([
                    lower, higher,
                ]));

            assert_eq!(BTreeSet::from([higher]), result);
        }
    }

    #[cfg(feature = "snark")]
    mod deduplicate_snark_keys {
        use super::*;

        #[test]
        fn keeps_only_the_highest_stake_entry_for_a_shared_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk = new_schnorr_vk(&mut rng);
            let lowest = entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_vk);
            let middle = entry_with_snark_key(new_vk_pop(&mut rng), 200, shared_vk);
            let highest = entry_with_snark_key(new_vk_pop(&mut rng), 300, shared_vk);

            let result = KeyRegistration::deduplicate_snark_keys_from_entries(&BTreeSet::from([
                middle, highest, lowest,
            ]));

            assert_eq!(BTreeSet::from([highest]), result);
        }

        #[test]
        fn breaks_stake_ties_with_the_concatenation_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk = new_schnorr_vk(&mut rng);
            let first = entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_vk);
            let second = entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_vk);
            let (loser, winner) = if first < second {
                (first, second)
            } else {
                (second, first)
            };

            let result = KeyRegistration::deduplicate_snark_keys_from_entries(&BTreeSet::from([
                loser, winner,
            ]));

            assert_eq!(BTreeSet::from([winner]), result);
        }

        #[test]
        fn drops_entries_without_snark_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let without_snark_key = entry(new_vk_pop(&mut rng), 100);
            let with_snark_key =
                entry_with_snark_key(new_vk_pop(&mut rng), 200, new_schnorr_vk(&mut rng));

            let result = KeyRegistration::deduplicate_snark_keys_from_entries(&BTreeSet::from([
                without_snark_key,
                with_snark_key,
            ]));

            assert_eq!(BTreeSet::from([with_snark_key]), result);
        }

        #[test]
        fn leaves_entries_without_collision_untouched() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let first_unique_vk = new_schnorr_vk(&mut rng);
            let first_unique = entry_with_snark_key(new_vk_pop(&mut rng), 200, first_unique_vk);
            let second_unique_vk = new_schnorr_vk(&mut rng);
            let second_unique = entry_with_snark_key(new_vk_pop(&mut rng), 300, second_unique_vk);
            let entries = BTreeSet::from([first_unique, second_unique]);

            let result = KeyRegistration::deduplicate_snark_keys_from_entries(&entries);

            assert_eq!(entries, result);
        }
    }

    #[cfg(feature = "snark")]
    mod close_registration_with_combined_collisions {
        use super::*;

        fn close(entries: &[RegistrationEntry]) -> ClosedKeyRegistration {
            let mut key_registration = KeyRegistration::initialize();
            for entry in entries {
                key_registration.register_by_entry(entry);
            }
            let params = Parameters {
                m: 20,
                k: 10,
                phi_f: PHI_F,
            };

            key_registration.close_registration(&params).unwrap()
        }

        fn expected_entries(
            closed_registration: &ClosedKeyRegistration,
            entries: &[RegistrationEntry],
        ) -> BTreeSet<ClosedRegistrationEntry> {
            entries
                .iter()
                .map(|entry| {
                    ClosedRegistrationEntry::try_from((
                        *entry,
                        closed_registration
                            .closed_key_registration_for_concatenation
                            .total_stake,
                        PHI_F,
                    ))
                    .unwrap()
                })
                .collect()
        }

        fn expected_snark_entries(
            closed_registration: &ClosedKeyRegistration,
            entries: &[RegistrationEntry],
        ) -> BTreeSet<ClosedRegistrationEntry> {
            entries
                .iter()
                .map(|entry| {
                    ClosedRegistrationEntry::try_from((
                        *entry,
                        closed_registration
                            .closed_key_registration_for_snark
                            .as_ref()
                            .unwrap()
                            .total_stake,
                        PHI_F,
                    ))
                    .unwrap()
                })
                .collect()
        }

        #[test]
        fn party_copying_both_keys_is_removed_from_both_sides() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let first_vk_pop = new_vk_pop(&mut rng);
            let first_schnorr_vk = new_schnorr_vk(&mut rng);
            let second_vk_pop = new_vk_pop(&mut rng);
            let second_schnorr_vk = new_schnorr_vk(&mut rng);
            let first = entry_with_snark_key(first_vk_pop, 100, first_schnorr_vk);
            let second = entry_with_snark_key(second_vk_pop, 200, second_schnorr_vk);
            let copier = entry_with_snark_key(second_vk_pop, 50, second_schnorr_vk);

            let closed_registration = close(&[first, second, copier]);

            assert_eq!(
                expected_entries(&closed_registration, &[first, second]),
                closed_registration
                    .closed_key_registration_for_concatenation
                    .deduplicated_entries
            );
            assert_eq!(
                expected_snark_entries(&closed_registration, &[first, second]),
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .deduplicated_entries
            );
        }

        #[test]
        fn bls_key_collision_loser_keeps_its_snark_leaf() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let first_vk_pop = new_vk_pop(&mut rng);
            let second_vk_pop = new_vk_pop(&mut rng);
            let first_schnorr_vk = new_schnorr_vk(&mut rng);
            let second_schnorr_vk = new_schnorr_vk(&mut rng);
            // Loses `first_schnorr_vk` to `middle`, which has more stake.
            let low = entry_with_snark_key(first_vk_pop, 10, first_schnorr_vk);
            // Loses `second_vk_pop` to `high`, but keeps `first_schnorr_vk`.
            let middle = entry_with_snark_key(second_vk_pop, 20, first_schnorr_vk);
            let high = entry_with_snark_key(second_vk_pop, 30, second_schnorr_vk);

            let closed_registration = close(&[low, middle, high]);

            assert_eq!(
                expected_entries(&closed_registration, &[low, high]),
                closed_registration
                    .closed_key_registration_for_concatenation
                    .deduplicated_entries
            );
            assert_eq!(
                expected_snark_entries(&closed_registration, &[middle, high]),
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .deduplicated_entries
            );
        }

        #[test]
        fn same_stake_and_concatenation_key_does_not_depend_on_registration_order() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let first_schnorr_vk = new_schnorr_vk(&mut rng);
            let second_schnorr_vk = new_schnorr_vk(&mut rng);
            let first = entry_with_snark_key(shared_vk_pop, 100, first_schnorr_vk);
            let second = entry_with_snark_key(shared_vk_pop, 100, second_schnorr_vk);
            let winner = if first_schnorr_vk > second_schnorr_vk {
                first
            } else {
                second
            };

            let closed_registration = close(&[first, second]);
            let closed_registration_reversed = close(&[second, first]);

            assert_eq!(closed_registration, closed_registration_reversed);
            assert_eq!(
                expected_entries(&closed_registration, &[winner]),
                closed_registration
                    .closed_key_registration_for_concatenation
                    .deduplicated_entries
            );
            assert_eq!(
                expected_snark_entries(&closed_registration, &[first, second]),
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .deduplicated_entries
            );
        }

        #[test]
        fn same_stake_and_concatenation_key_with_and_without_snark_registers_snark() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let without_snark_key = entry(shared_vk_pop, 100);
            let with_snark_key = entry_with_snark_key(shared_vk_pop, 100, new_schnorr_vk(&mut rng));

            let closed_registration = close(&[without_snark_key, with_snark_key]);
            let closed_registration_reversed = close(&[with_snark_key, without_snark_key]);

            assert_eq!(closed_registration, closed_registration_reversed);
            assert_eq!(
                expected_entries(&closed_registration, &[with_snark_key]),
                closed_registration
                    .closed_key_registration_for_concatenation
                    .deduplicated_entries
            );
            assert_eq!(
                expected_snark_entries(&closed_registration, &[with_snark_key]),
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .deduplicated_entries
            );
        }

        #[test]
        fn same_stake_and_snark_key_goes_to_the_highest_concatenation_key() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_schnorr_vk = new_schnorr_vk(&mut rng);
            let first = entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_schnorr_vk);
            let second = entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_schnorr_vk);
            let (loser, winner) = if first < second {
                (first, second)
            } else {
                (second, first)
            };

            let closed_registration = close(&[first, second]);

            let expected_for_concatenation =
                expected_entries(&closed_registration, &[loser, winner]);
            assert_eq!(
                expected_for_concatenation,
                closed_registration
                    .closed_key_registration_for_concatenation
                    .deduplicated_entries
            );
            assert_eq!(
                expected_snark_entries(&closed_registration, &[winner]),
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .deduplicated_entries
            );
        }

        #[test]
        fn total_stake_of_each_proof_system_only_counts_its_deduplicated_entries() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let shared_vk_pop = new_vk_pop(&mut rng);
            let shared_schnorr_vk = new_schnorr_vk(&mut rng);
            let snark_key_collision_loser =
                entry_with_snark_key(new_vk_pop(&mut rng), 100, shared_schnorr_vk);
            let snark_key_collision_winner =
                entry_with_snark_key(shared_vk_pop, 200, shared_schnorr_vk);
            // Loses `shared_vk_pop` to `snark_key_collision_winner`, but keeps its own SNARK key.
            let bls_key_collision_loser =
                entry_with_snark_key(shared_vk_pop, 30, new_schnorr_vk(&mut rng));
            let without_snark_key = entry(new_vk_pop(&mut rng), 50);

            let closed_registration = close(&[
                snark_key_collision_loser,
                snark_key_collision_winner,
                bls_key_collision_loser,
                without_snark_key,
            ]);

            assert_eq!(
                350,
                closed_registration
                    .closed_key_registration_for_concatenation
                    .total_stake
            );
            assert_eq!(
                230,
                closed_registration
                    .closed_key_registration_for_snark
                    .as_ref()
                    .unwrap()
                    .total_stake
            );
        }

        #[test]
        fn registration_without_snark_key_closes_with_no_snark_entry() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let first = entry(new_vk_pop(&mut rng), 100);
            let second = entry(new_vk_pop(&mut rng), 200);

            let closed_registration = close(&[first, second]);

            assert_eq!(
                300,
                closed_registration
                    .closed_key_registration_for_concatenation
                    .total_stake
            );
            assert!(closed_registration.closed_key_registration_for_snark.is_none());
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

            // Every entry with a valid proof of possession is registered, the BLS key collisions
            // are resolved when closing the registration.
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
                        kr.register_by_entry(&entry);
                        registered_entries.insert(entry);
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

                // One entry per BLS key, the one with the highest stake.
                let mut highest_stake_by_key = std::collections::BTreeMap::new();
                for entry in &registered_entries {
                    let stake = highest_stake_by_key
                        .entry(entry.get_verification_key_for_concatenation())
                        .or_insert(0);
                    *stake = (*stake).max(entry.get_stake());
                }
                let retrieved_stake_by_key = closed.closed_key_registration_for_concatenation.deduplicated_entries.iter()
                    .map(|entry| (entry.get_verification_key_for_concatenation(), entry.get_stake()))
                    .collect::<std::collections::BTreeMap<_, _>>();
                assert_eq!(highest_stake_by_key, retrieved_stake_by_key);
                assert_eq!(
                    closed.closed_key_registration_for_concatenation.deduplicated_entries.len(),
                    retrieved_stake_by_key.len()
                );
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
                key_reg.register_by_entry(&initializer.clone().try_into().unwrap());
            }

            let closed_key_reg: ClosedKeyRegistration =
                key_reg.close_registration(&params).unwrap();
            closed_key_reg
                .get_closed_key_registration_for_concatenation()
                .to_merkle_tree()
                .to_merkle_tree_batch_commitment()
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
            "root":[179,125,202,109,44,249,230,131,105,29,29,244,87,250,43,130,252,55,26,91,46,235,16,50,56,91,153,70,94,20,246,11],
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
                key_reg.register_by_entry(&initializer.clone().try_into().unwrap());
            }

            let closed_key_reg: ClosedKeyRegistration =
                key_reg.close_registration(&params).unwrap();
            closed_key_reg
                .get_closed_key_registration_for_snark()
                .unwrap()
                .to_merkle_tree::<MidnightPoseidonDigest>()
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
        const GOLDEN_CONCATENATION_AVK_CONCATENATION_KEY_COLLISION: &str = r#"
        {
            "root":[113, 63, 85, 161, 147, 27, 125, 100, 11, 1, 179, 222, 48, 249, 13, 91, 62, 223, 167, 129, 182, 183, 253, 11, 193, 94, 42, 102, 229, 190, 67, 171],
            "nr_leaves":7,
            "hasher":null
        }"#;

        #[cfg(feature = "snark")]
        const GOLDEN_SNARK_AVK_NO_COLLISION: &str = r#"
        {
            "root":[129, 54, 200, 172, 152, 74, 30, 165, 237, 56, 170, 136, 253, 113, 65, 200, 203, 249, 129, 223, 91, 74, 66, 6, 27, 43, 222, 176, 34, 111, 0, 110],
            "hasher":null
        }"#;

        #[cfg(feature = "snark")]
        const GOLDEN_SNARK_AVK_SNARK_KEY_COLLISION: &str = r#"
        {
            "root":[71, 71, 148, 180, 196, 125, 121, 203, 119, 187, 83, 184, 18, 239, 10, 106, 16, 212, 240, 107, 0, 116, 153, 178, 214, 41, 106, 83, 166, 149, 161, 18],
            "hasher":null
        }"#;

        /// Party `i` has stake `i`, so party 0 has a zero stake and the golden values also cover
        /// an entry with a zero stake, which never wins a lottery but still gets a leaf in both
        /// Merkle trees.
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
                key_reg.register_by_entry(&initializer.clone().try_into().unwrap());
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
                key_reg.register_by_entry(&initializer.try_into().unwrap());
            }

            key_reg.close_registration(&params).unwrap()
        }

        /// Same parties as `closed_key_registration_no_collision` (party `i` has stake `i`), with
        /// two BLS key collisions:
        /// - 3-way: parties 2 and 5 are given the BLS key of party 8, which keeps it.
        /// - 2-way: party 1 is given the BLS key of party 6, which keeps it.
        fn closed_key_registration_concatenation_key_collision() -> ClosedKeyRegistration {
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
                initializers[receiver].bls_signing_key =
                    initializers[owner].bls_signing_key.clone();
                initializers[receiver].bls_verification_key_proof_of_possession =
                    initializers[owner].bls_verification_key_proof_of_possession;
            }

            let mut key_reg = KeyRegistration::initialize();
            for initializer in initializers {
                key_reg.register_by_entry(&initializer.try_into().unwrap());
            }

            key_reg.close_registration(&params).unwrap()
        }

        /// Same parties as `closed_key_registration_no_collision` (party `i` has stake `i`), with
        /// both the BLS key collisions of `closed_key_registration_concatenation_key_collision`
        /// and the SNARK key collisions of `closed_key_registration_snark_key_collision`.
        /// Each proof system only depends on its own collisions, so each side is expected to match
        /// the scenario with only its own collisions.
        #[cfg(feature = "snark")]
        fn closed_key_registration_double_key_collision() -> ClosedKeyRegistration {
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
                initializers[receiver].bls_signing_key =
                    initializers[owner].bls_signing_key.clone();
                initializers[receiver].bls_verification_key_proof_of_possession =
                    initializers[owner].bls_verification_key_proof_of_possession;
                initializers[receiver].schnorr_signing_key =
                    initializers[owner].schnorr_signing_key.clone();
                initializers[receiver].schnorr_verification_key =
                    initializers[owner].schnorr_verification_key;
            }

            let mut key_reg = KeyRegistration::initialize();
            for initializer in initializers {
                key_reg.register_by_entry(&initializer.try_into().unwrap());
            }

            key_reg.close_registration(&params).unwrap()
        }

        mod golden_test_no_collision {
            use super::*;

            fn golden_concatenation_avk_no_collision()
            -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
                closed_key_registration_no_collision()
                    .get_closed_key_registration_for_concatenation()
                    .to_merkle_tree()
                    .to_merkle_tree_batch_commitment()
            }

            #[cfg(feature = "snark")]
            fn golden_snark_avk_no_collision()
            -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
                closed_key_registration_no_collision()
                    .get_closed_key_registration_for_snark()
                    .unwrap()
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
            #[cfg(feature = "snark")]
            fn golden_snark_computation_no_collision() {
                let value = serde_json::from_str(GOLDEN_SNARK_AVK_NO_COLLISION)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_snark_avk_no_collision(), value);
            }
        }

        #[cfg(feature = "snark")]
        mod golden_test_snark_key_collision {
            use super::*;

            #[cfg(feature = "snark")]
            fn golden_concatenation_avk_snark_key_collision()
            -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
                closed_key_registration_snark_key_collision()
                    .get_closed_key_registration_for_concatenation()
                    .to_merkle_tree()
                    .to_merkle_tree_batch_commitment()
            }

            #[cfg(feature = "snark")]
            fn golden_snark_avk_snark_key_collision()
            -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
                closed_key_registration_snark_key_collision()
                    .get_closed_key_registration_for_snark()
                    .unwrap()
                    .to_merkle_tree()
                    .to_merkle_tree_commitment()
            }

            #[test]
            #[cfg(feature = "snark")]
            fn golden_concatenation_computation_snark_key_collision() {
                let value = serde_json::from_str(GOLDEN_CONCATENATION_AVK_NO_COLLISION)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_concatenation_avk_snark_key_collision(), value);
            }

            #[test]
            #[cfg(feature = "snark")]
            fn golden_snark_computation_snark_key_collision() {
                let value = serde_json::from_str(GOLDEN_SNARK_AVK_SNARK_KEY_COLLISION)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_snark_avk_snark_key_collision(), value);
            }
        }

        mod golden_test_concatenation_key_collision {
            use super::*;

            fn golden_concatenation_avk_concatenation_key_collision()
            -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
                closed_key_registration_concatenation_key_collision()
                    .get_closed_key_registration_for_concatenation()
                    .to_merkle_tree()
                    .to_merkle_tree_batch_commitment()
            }

            #[cfg(feature = "snark")]
            fn golden_snark_avk_concatenation_key_collision()
            -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
                closed_key_registration_concatenation_key_collision()
                    .get_closed_key_registration_for_snark()
                    .unwrap()
                    .to_merkle_tree()
                    .to_merkle_tree_commitment()
            }

            #[test]
            fn golden_concatenation_computation_concatenation_key_collision() {
                let value =
                    serde_json::from_str(GOLDEN_CONCATENATION_AVK_CONCATENATION_KEY_COLLISION)
                        .expect("This JSON deserialization should not fail");
                assert_eq!(
                    golden_concatenation_avk_concatenation_key_collision(),
                    value
                );
            }

            #[test]
            #[cfg(feature = "snark")]
            fn golden_snark_computation_concatenation_key_collision() {
                let value = serde_json::from_str(GOLDEN_SNARK_AVK_NO_COLLISION)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_snark_avk_concatenation_key_collision(), value);
            }
        }

        #[cfg(feature = "snark")]
        mod golden_test_double_key_collision {
            use super::*;

            fn golden_concatenation_avk_double_key_collision()
            -> MerkleTreeBatchCommitment<Blake2b<U32>, MerkleTreeConcatenationLeaf> {
                closed_key_registration_double_key_collision()
                    .get_closed_key_registration_for_concatenation()
                    .to_merkle_tree()
                    .to_merkle_tree_batch_commitment()
            }

            fn golden_snark_avk_double_key_collision()
            -> MerkleTreeCommitment<MidnightPoseidonDigest, MerkleTreeSnarkLeaf> {
                closed_key_registration_double_key_collision()
                    .get_closed_key_registration_for_snark()
                    .unwrap()
                    .to_merkle_tree()
                    .to_merkle_tree_commitment()
            }

            #[test]
            fn golden_concatenation_computation_double_key_collision() {
                let value =
                    serde_json::from_str(GOLDEN_CONCATENATION_AVK_CONCATENATION_KEY_COLLISION)
                        .expect("This JSON deserialization should not fail");
                assert_eq!(golden_concatenation_avk_double_key_collision(), value);
            }

            #[test]
            fn golden_snark_computation_double_key_collision() {
                let value = serde_json::from_str(GOLDEN_SNARK_AVK_SNARK_KEY_COLLISION)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_snark_avk_double_key_collision(), value);
            }
        }
    }
}
