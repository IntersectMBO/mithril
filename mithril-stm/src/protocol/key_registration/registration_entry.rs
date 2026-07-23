use std::cmp::Ordering;
use std::hash::Hash;

#[cfg(feature = "future_snark")]
use crate::VerificationKeyForSnark;
use crate::{
    Initializer, RegisterError, Stake, StmResult, VerificationKeyForConcatenation,
    VerificationKeyProofOfPossessionForConcatenation,
};

use super::ClosedRegistrationEntry;

/// Represents a signer registration entry
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct RegistrationEntry(
    VerificationKeyForConcatenation,
    Stake,
    #[cfg(feature = "future_snark")] Option<VerificationKeyForSnark>,
);

impl RegistrationEntry {
    /// Creates a new registration entry. Verifies the proof of possession of verification key for
    /// concatenation and validates the schnorr verification key before creating the entry.
    pub fn new(
        bls_verification_key_proof_of_possession: VerificationKeyProofOfPossessionForConcatenation,
        stake: Stake,
        #[cfg(feature = "future_snark")] schnorr_verification_key: Option<VerificationKeyForSnark>,
    ) -> StmResult<Self> {
        bls_verification_key_proof_of_possession
            .verify_proof_of_possession()
            .map_err(|_| {
                RegisterError::ConcatenationKeyInvalid(Box::new(
                    bls_verification_key_proof_of_possession.vk,
                ))
            })?;

        #[cfg(feature = "future_snark")]
        schnorr_verification_key
            .map(|schnorr_vk| {
                schnorr_vk
                    .is_valid()
                    .map_err(|_| RegisterError::SnarkKeyInvalid(Box::new(schnorr_vk)))
            })
            .transpose()?;

        Ok(RegistrationEntry(
            bls_verification_key_proof_of_possession.vk,
            stake,
            #[cfg(feature = "future_snark")]
            schnorr_verification_key,
        ))
    }

    /// Gets the verification key for concatenation.
    pub fn get_verification_key_for_concatenation(&self) -> VerificationKeyForConcatenation {
        self.0
    }

    #[cfg(feature = "future_snark")]
    /// Gets the verification key for snark.
    pub fn get_verification_key_for_snark(&self) -> Option<VerificationKeyForSnark> {
        self.2
    }

    /// Gets the stake associated with the registration entry.
    pub fn get_stake(&self) -> Stake {
        self.1
    }
}

impl From<ClosedRegistrationEntry> for RegistrationEntry {
    fn from(entry: ClosedRegistrationEntry) -> Self {
        RegistrationEntry(
            entry.get_verification_key_for_concatenation(),
            entry.get_stake(),
            #[cfg(feature = "future_snark")]
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
            #[cfg(feature = "future_snark")]
            initializer.schnorr_verification_key,
        )
    }
}

impl Hash for RegistrationEntry {
    /// Hashes the registration entry by hashing the stake first, then the verification key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.1.hash(state);
        self.0.hash(state);
        #[cfg(feature = "future_snark")]
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
    /// Compares the registration entries by comparing the stake first, then the verification key.
    fn cmp(&self, other: &Self) -> Ordering {
        self.1.cmp(&other.1).then(self.0.cmp(&other.0))
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

    #[cfg(feature = "future_snark")]
    use crate::{VerificationKeyForSnark, signature_scheme::SchnorrSigningKey};

    use super::*;

    fn create_registration_entry(rng: &mut ChaCha20Rng, stake: Stake) -> RegistrationEntry {
        let bls_sk = BlsSigningKey::generate(rng);
        let bls_pk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);

        #[cfg(feature = "future_snark")]
        let schnorr_verification_key = {
            let sk = SchnorrSigningKey::generate(rng);
            VerificationKeyForSnark::new_from_signing_key(sk)
        };
        RegistrationEntry::new(
            bls_pk,
            stake,
            #[cfg(feature = "future_snark")]
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
}
