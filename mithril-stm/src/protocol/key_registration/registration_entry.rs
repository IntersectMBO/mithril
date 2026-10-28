use std::cmp::Ordering;
use std::hash::Hash;

#[cfg(feature = "snark")]
use crate::VerificationKeyForSnark;
use crate::{
    Initializer, RegisterError, Stake, StmResult, VerificationKeyForConcatenation,
    VerificationKeyProofOfPossessionForConcatenation,
};

use super::ClosedRegistrationEntry;

/// Represents a signer registration entry
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub(crate) struct RegistrationEntry(
    VerificationKeyForConcatenation,
    Stake,
    #[cfg(feature = "snark")] Option<VerificationKeyForSnark>,
);

impl RegistrationEntry {
    /// Creates a new registration entry. Verifies the proof of possession of verification key for
    /// concatenation before creating the entry.
    ///
    /// An invalid schnorr verification key is dropped, so the entry is still registered for the
    /// Concatenation proof system, without a SNARK key. This behavior is temporary and here to
    /// support the ramp-up adoption of SNARK capable signers. It will be removed once enough
    /// signers adopt the SNARK variant.
    pub(crate) fn new(
        bls_verification_key_proof_of_possession: VerificationKeyProofOfPossessionForConcatenation,
        stake: Stake,
        #[cfg(feature = "snark")] schnorr_verification_key: Option<VerificationKeyForSnark>,
    ) -> StmResult<Self> {
        bls_verification_key_proof_of_possession
            .verify_proof_of_possession()
            .map_err(|_| {
                RegisterError::ConcatenationKeyInvalid(Box::new(
                    bls_verification_key_proof_of_possession.vk,
                ))
            })?;

        // TODO: Once the SNARK registration is mandatory, return `RegisterError::SnarkKeyInvalid`
        // instead of dropping the key.
        #[cfg(feature = "snark")]
        let schnorr_verification_key =
            schnorr_verification_key.filter(|schnorr_vk| schnorr_vk.validate().is_ok());

        Ok(RegistrationEntry(
            bls_verification_key_proof_of_possession.vk,
            stake,
            #[cfg(feature = "snark")]
            schnorr_verification_key,
        ))
    }

    /// Gets the verification key for concatenation.
    pub(crate) fn get_verification_key_for_concatenation(&self) -> VerificationKeyForConcatenation {
        self.0
    }

    #[cfg(feature = "snark")]
    /// Gets the verification key for snark.
    pub(crate) fn get_verification_key_for_snark(&self) -> Option<VerificationKeyForSnark> {
        self.2
    }

    /// Gets the stake associated with the registration entry.
    pub(crate) fn get_stake(&self) -> Stake {
        self.1
    }
}

impl From<ClosedRegistrationEntry> for RegistrationEntry {
    fn from(entry: ClosedRegistrationEntry) -> Self {
        RegistrationEntry(
            entry.get_verification_key_for_concatenation(),
            entry.get_stake(),
            #[cfg(feature = "snark")]
            entry.get_verification_key_for_snark(),
        )
    }
}

impl TryFrom<Initializer> for RegistrationEntry {
    type Error = anyhow::Error;

    fn try_from(initializer: Initializer) -> StmResult<Self> {
        Self::new(
            initializer.bls_verification_key_proof_of_possession,
            initializer.stake,
            #[cfg(feature = "snark")]
            initializer.schnorr_verification_key,
        )
    }
}

impl Hash for RegistrationEntry {
    /// Hashes the registration entry by hashing the stake first, then the verification key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.1.hash(state);
        self.0.hash(state);
        #[cfg(feature = "snark")]
        self.2.hash(state);
    }

    fn hash_slice<H: std::hash::Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        for piece in data {
            piece.hash(state)
        }
    }
}

impl PartialOrd for RegistrationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for RegistrationEntry {
    /// Compares the registration entries by comparing the stake first, then the verification key
    /// for concatenation, then (with the `snark` feature) the verification key for SNARK.
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.1.cmp(&other.1).then(self.0.cmp(&other.0));
        #[cfg(feature = "snark")]
        let ordering = ordering.then(self.2.cmp(&other.2));
        ordering
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::cmp::Ordering;

    use crate::{
        VerificationKeyProofOfPossessionForConcatenation, signature_scheme::BlsSigningKey,
    };

    #[cfg(feature = "snark")]
    use crate::{VerificationKeyForSnark, signature_scheme::SchnorrSigningKey};

    use super::*;

    fn create_registration_entry(rng: &mut ChaCha20Rng, stake: Stake) -> RegistrationEntry {
        let bls_sk = BlsSigningKey::generate(rng);
        let bls_pk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);

        #[cfg(feature = "snark")]
        let schnorr_verification_key = {
            let sk = SchnorrSigningKey::generate(rng);
            VerificationKeyForSnark::new_from_signing_key(sk)
        };
        RegistrationEntry::new(
            bls_pk,
            stake,
            #[cfg(feature = "snark")]
            Some(schnorr_verification_key),
        )
        .unwrap()
    }

    #[test]
    fn test_ord_different_stakes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let entry_low_stake = create_registration_entry(&mut rng, 100);
        let entry_high_stake = create_registration_entry(&mut rng, 200);

        assert_eq!(entry_low_stake.cmp(&entry_high_stake), Ordering::Less);
        assert_eq!(entry_high_stake.cmp(&entry_low_stake), Ordering::Greater);
    }

    #[test]
    fn test_ord_same_stake_different_keys() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let entry1 = create_registration_entry(&mut rng, 100);
        let entry2 = create_registration_entry(&mut rng, 100);

        let cmp_result = entry1.cmp(&entry2);
        assert!(cmp_result == Ordering::Less || cmp_result == Ordering::Greater);

        assert_eq!(entry2.cmp(&entry1), cmp_result.reverse());
    }

    #[cfg(feature = "snark")]
    #[test]
    fn an_invalid_snark_key_is_dropped() {
        use crate::signature_scheme::ScalarFieldElement;

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let vk_pop = VerificationKeyProofOfPossessionForConcatenation::from(
            &BlsSigningKey::generate(&mut rng),
        );
        let invalid_schnorr_vk = VerificationKeyForSnark::new_from_signing_key(SchnorrSigningKey(
            ScalarFieldElement::get_zero(),
        ));

        let entry = RegistrationEntry::new(vk_pop, 100, Some(invalid_schnorr_vk))
            .expect("an invalid SNARK key should not prevent the registration");

        assert_eq!(None, entry.get_verification_key_for_snark());
    }

    mod golden_ordering {
        use super::*;

        /// Creation index of each entry, in the sorted order.
        const GOLDEN_ORDER: [usize; 8] = [6, 3, 1, 2, 5, 4, 0, 7];

        /// Entries with repeated stakes, so that their order also depends on the verification key
        /// for concatenation. Each key comes from its own random generator, so the verification
        /// keys for concatenation do not depend on the `snark` feature.
        fn entries() -> Vec<RegistrationEntry> {
            let mut concatenation_rng = ChaCha20Rng::from_seed([2u8; 32]);
            #[cfg(feature = "snark")]
            let mut snark_rng = ChaCha20Rng::from_seed([1u8; 32]);

            [300, 100, 200, 100, 300, 200, 100, 500]
                .into_iter()
                .map(|stake| {
                    RegistrationEntry::new(
                        VerificationKeyProofOfPossessionForConcatenation::from(
                            &BlsSigningKey::generate(&mut concatenation_rng),
                        ),
                        stake,
                        #[cfg(feature = "snark")]
                        Some(VerificationKeyForSnark::new_from_signing_key(
                            SchnorrSigningKey::generate(&mut snark_rng),
                        )),
                    )
                    .unwrap()
                })
                .collect()
        }

        #[test]
        fn ordering_is_stable() {
            let entries = entries();
            let mut sorted_entries = entries.clone();
            sorted_entries.sort();

            let order: Vec<usize> = sorted_entries
                .iter()
                .map(|sorted_entry| entries.iter().position(|entry| entry == sorted_entry).unwrap())
                .collect();

            assert_eq!(GOLDEN_ORDER.as_slice(), order.as_slice());
        }
    }

    mod ordering_properties {
        use proptest::{collection::vec, prelude::*};

        use super::*;

        /// Picks a stake, a verification key for concatenation and a verification key for SNARK
        /// from small pools, so that entries often tie on their stake and on their verification
        /// key for concatenation. The last SNARK key choice stands for no SNARK key.
        fn entry_choice() -> impl Strategy<Value = (Stake, usize, usize)> {
            (0..3u64, 0..3usize, 0..4usize)
        }

        fn entries(choices: &[(Stake, usize, usize)]) -> Vec<RegistrationEntry> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let concatenation_keys: Vec<_> = (0..3)
                .map(|_| {
                    VerificationKeyProofOfPossessionForConcatenation::from(
                        &BlsSigningKey::generate(&mut rng),
                    )
                })
                .collect();
            #[cfg(feature = "snark")]
            let snark_keys: Vec<_> = (0..3)
                .map(|_| {
                    VerificationKeyForSnark::new_from_signing_key(SchnorrSigningKey::generate(
                        &mut rng,
                    ))
                })
                .collect();

            choices
                .iter()
                .map(|&(stake, concatenation_key, snark_key)| {
                    #[cfg(not(feature = "snark"))]
                    let _ = snark_key;
                    RegistrationEntry::new(
                        concatenation_keys[concatenation_key],
                        stake,
                        #[cfg(feature = "snark")]
                        snark_keys.get(snark_key).copied(),
                    )
                    .unwrap()
                })
                .collect()
        }

        proptest! {
            #[test]
            fn only_equal_entries_compare_equal(choices in vec(entry_choice(), 2)) {
                let entries = entries(&choices);

                prop_assert_eq!(entries[0] == entries[1], entries[0].cmp(&entries[1]).is_eq());
            }

            #[test]
            fn a_higher_stake_sorts_after_a_lower_stake(choices in vec(entry_choice(), 2)) {
                let entries = entries(&choices);
                prop_assume!(entries[0].get_stake() < entries[1].get_stake());

                prop_assert!(entries[0] < entries[1]);
            }

            #[test]
            fn sorting_does_not_depend_on_the_input_order(
                (choices, shuffled_choices) in vec(entry_choice(), 1..10)
                    .prop_flat_map(|choices| (Just(choices.clone()), Just(choices).prop_shuffle()))
            ) {
                let mut sorted_entries = entries(&choices);
                sorted_entries.sort();
                let mut sorted_shuffled_entries = entries(&shuffled_choices);
                sorted_shuffled_entries.sort();

                prop_assert_eq!(sorted_entries, sorted_shuffled_entries);
            }
        }
    }
}
