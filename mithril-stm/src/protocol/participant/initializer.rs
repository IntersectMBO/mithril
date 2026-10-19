use anyhow::anyhow;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    ClosedKeyRegistration, ClosedRegistrationEntry, MembershipDigest, Parameters, RegisterError,
    RegistrationEntry, SignerIndex, Stake, StmResult,
    VerificationKeyProofOfPossessionForConcatenation, proof_system::ConcatenationProofSigner,
    signature_scheme::BlsSigningKey,
};
#[cfg(feature = "snark")]
use crate::{
    ProofOfBoundPossessionPrefixBytes, StandardSchnorrSignature, VerificationKeyForSnark,
    proof_system::SnarkProofSigner, signature_scheme::SchnorrSigningKey,
};

use crate::codec;

use super::Signer;

/// Structure responsible of creating a signer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Initializer {
    /// Stake of the participant
    pub stake: Stake,
    /// Protocol parameters.
    #[serde(rename = "params")]
    pub parameters: Parameters,
    /// Signing key for concatenation proof system.
    #[serde(rename = "sk")]
    pub bls_signing_key: BlsSigningKey,
    /// Verification key for concatenation proof system.
    #[serde(rename = "pk")]
    pub bls_verification_key_proof_of_possession: VerificationKeyProofOfPossessionForConcatenation,
    /// Signing key for snark proof system.
    #[cfg(feature = "snark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schnorr_signing_key: Option<SchnorrSigningKey>,
    /// Verification key for snark proof system.
    #[cfg(feature = "snark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schnorr_verification_key: Option<VerificationKeyForSnark>,
}

impl Initializer {
    /// Creates a new initializer
    pub fn new<R: RngCore + CryptoRng>(parameters: Parameters, stake: Stake, rng: &mut R) -> Self {
        let bls_signing_key = BlsSigningKey::generate(rng);
        let bls_verification_key_proof_of_possession =
            VerificationKeyProofOfPossessionForConcatenation::from(&bls_signing_key);
        #[cfg(feature = "snark")]
        let (schnorr_signing_key, schnorr_verification_key) = {
            let sk = SchnorrSigningKey::generate(rng);
            let vk = VerificationKeyForSnark::new_from_signing_key(sk.clone());
            (Some(sk), Some(vk))
        };
        Self {
            stake,
            parameters,
            bls_signing_key,
            bls_verification_key_proof_of_possession,
            #[cfg(feature = "snark")]
            schnorr_signing_key,
            #[cfg(feature = "snark")]
            schnorr_verification_key,
        }
    }

    /// Attempts to generate a new signer from the current registration state.
    ///
    /// # Process
    /// 1. Verifies that registration is closed (determined by total stake threshold)
    /// 2. Confirms the initializer is registered and retrieves its signer index
    /// 3. Constructs the Merkle tree commitment for each proof system (concatenation and snark)
    /// 4. Creates the underlying proof system signer
    ///
    /// # Errors
    /// Returns an error if:
    /// - Registration is not yet closed
    /// - The initializer is not registered
    pub fn try_create_signer<D: MembershipDigest>(
        self,
        closed_key_registration: &ClosedKeyRegistration,
    ) -> StmResult<Signer<D>> {
        let registration_entry = RegistrationEntry::new(
            self.bls_verification_key_proof_of_possession,
            self.stake,
            #[cfg(feature = "snark")]
            self.schnorr_verification_key,
        )?;

        let (signer_index, concatenation_proof_signer) = self
            .try_create_concatenation_proof_signer(registration_entry, closed_key_registration)?;

        #[cfg(feature = "snark")]
        let snark_proof_signer =
            self.create_snark_proof_signer(registration_entry, closed_key_registration);

        // Create and return signer
        Ok(Signer::new(
            signer_index,
            concatenation_proof_signer,
            closed_key_registration.clone(),
            self.parameters,
            registration_entry.get_stake(),
            #[cfg(feature = "snark")]
            snark_proof_signer,
        ))
    }

    /// Tries to create the Concatenation proof signer
    ///
    /// First tries to find the signer index in the deduplicated Concatenation entries then
    /// creates the Concatenation proof signer and returns both values. Fails when the
    /// verification key is not registered or the ClosedRegistrationEntry cannot be created.
    fn try_create_concatenation_proof_signer<D: MembershipDigest>(
        &self,
        registration_entry: RegistrationEntry,
        closed_key_registration: &ClosedKeyRegistration,
    ) -> StmResult<(SignerIndex, ConcatenationProofSigner<D>)> {
        let closed_key_registration_for_concatenation =
            closed_key_registration.get_closed_key_registration_for_concatenation();

        let closed_registration_entry = ClosedRegistrationEntry::try_from((
            registration_entry,
            closed_key_registration_for_concatenation.get_total_stake(),
            self.parameters.phi_f,
        ))?;

        let signer_index = closed_key_registration_for_concatenation
            .get_signer_index_for_registration(&closed_registration_entry)
            .ok_or_else(|| anyhow!(RegisterError::UnregisteredInitializer))?;

        let key_registration_commitment = closed_key_registration_for_concatenation
            .to_merkle_tree::<D::ConcatenationHash>()
            .to_merkle_tree_batch_commitment();

        Ok((
            signer_index,
            ConcatenationProofSigner::new(
                self.stake,
                closed_key_registration_for_concatenation.get_total_stake(),
                self.parameters,
                self.bls_signing_key.clone(),
                self.bls_verification_key_proof_of_possession.vk,
                key_registration_commitment,
            ),
        ))
    }

    /// Creates the SNARK proof signer or returns `None`
    ///
    /// Returns `None` when the initializer has no SNARK key, lost it during deduplication,
    /// or when there is no SNARK entry at all.
    #[cfg(feature = "snark")]
    fn create_snark_proof_signer<D: MembershipDigest>(
        &self,
        registration_entry: RegistrationEntry,
        closed_key_registration: &ClosedKeyRegistration,
    ) -> Option<SnarkProofSigner<D>> {
        let schnorr_signing_key = self.schnorr_signing_key.clone()?;
        let schnorr_verification_key = self.schnorr_verification_key?;
        let closed_key_registration_for_snark =
            closed_key_registration.get_closed_key_registration_for_snark()?;

        let snark_registration_entry = ClosedRegistrationEntry::try_from((
            registration_entry,
            closed_key_registration_for_snark.get_total_stake(),
            self.parameters.phi_f,
        ))
        .ok()?;

        let signer_index = closed_key_registration_for_snark
            .get_signer_index_for_registration(&snark_registration_entry)?;

        let lottery_target_value = snark_registration_entry.get_lottery_target_value()?;

        let key_registration_commitment = closed_key_registration_for_snark
            .to_merkle_tree::<D::SnarkHash>()
            .to_merkle_tree_commitment();

        Some(SnarkProofSigner::new(
            self.parameters,
            schnorr_signing_key,
            schnorr_verification_key,
            lottery_target_value,
            key_registration_commitment,
            signer_index,
        ))
    }

    /// Creates a Proof of Bound Possession for the Schnorr signing key of the
    /// Initializer for a given prefix if there is one
    #[cfg(feature = "snark")]
    pub fn create_proof_of_bound_possession<R: RngCore + CryptoRng>(
        &self,
        prefix: &ProofOfBoundPossessionPrefixBytes,
        rng: &mut R,
    ) -> StmResult<Option<StandardSchnorrSignature>> {
        self.schnorr_signing_key
            .as_ref()
            .map(|schnorr_signing_key| {
                schnorr_signing_key.create_proof_of_bound_possession(prefix, rng)
            })
            .transpose()
    }

    /// Extract the verification key with proof of possession.
    pub fn get_verification_key_proof_of_possession_for_concatenation(
        &self,
    ) -> VerificationKeyProofOfPossessionForConcatenation {
        self.bls_verification_key_proof_of_possession
    }

    /// Extract the verification key for snark.
    #[cfg(feature = "snark")]
    pub fn get_verification_key_for_snark(&self) -> Option<VerificationKeyForSnark> {
        self.schnorr_verification_key
    }

    /// Remove the SNARK-related keys (Schnorr signing and verification keys) from this
    /// initializer.
    ///
    /// This is used during eras that do not yet support SNARK proofs to ensure the
    /// initializer's registration entry matches the closed key registration built from
    /// signers without SNARK verification keys.
    #[cfg(feature = "snark")]
    pub fn strip_snark_keys(&mut self) {
        self.schnorr_signing_key = None;
        self.schnorr_verification_key = None;
    }

    /// Convert to bytes using CBOR encoding with a version prefix.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Convert a slice of bytes to an `Initializer`.
    ///
    /// Supports both CBOR-encoded (version-prefixed) and legacy big-endian byte formats.
    ///
    /// # Error
    /// The function fails if the given bytes cannot be decoded in either format.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Initializer> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Decode an `Initializer` from the legacy big-endian byte-packed format.
    ///
    /// # Layout
    /// * Stake (u64)
    /// * Parameters
    /// * BLS signing key
    /// * BLS verification key (including PoP)
    /// * [Snark - Schnorr Signing Key]
    /// * [Snark - Schnorr Verification Key]
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Initializer> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(RegisterError::SerializationError)?);
        let stake = u64::from_be_bytes(u64_bytes);
        let params =
            Parameters::from_bytes(bytes.get(8..32).ok_or(RegisterError::SerializationError)?)?;
        let bls_signing_key = BlsSigningKey::from_canonical_bytes(
            bytes.get(32..64).ok_or(RegisterError::SerializationError)?,
        )?;
        let bls_verification_key_proof_of_possession =
            VerificationKeyProofOfPossessionForConcatenation::from_canonical_bytes(
                bytes.get(64..256).ok_or(RegisterError::SerializationError)?,
            )?;

        #[cfg(feature = "snark")]
        let (schnorr_signing_key, schnorr_verification_key) = {
            let schnorr_signing_key = bytes
                .get(256..288)
                .map(SchnorrSigningKey::from_canonical_bytes)
                .transpose()?;
            let schnorr_verification_key = bytes
                .get(288..352)
                .map(VerificationKeyForSnark::from_canonical_bytes)
                .transpose()?;

            match (&schnorr_signing_key, &schnorr_verification_key) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(RegisterError::SerializationError.into());
                }
                _ => {}
            }
            (schnorr_signing_key, schnorr_verification_key)
        };

        Ok(Self {
            stake,
            parameters: params,
            bls_signing_key,
            bls_verification_key_proof_of_possession,
            #[cfg(feature = "snark")]
            schnorr_signing_key,
            #[cfg(feature = "snark")]
            schnorr_verification_key,
        })
    }
}

impl PartialEq for Initializer {
    fn eq(&self, other: &Self) -> bool {
        let base_eq = self.stake == other.stake
            && self.parameters == other.parameters
            && self.bls_signing_key.to_canonical_bytes()
                == other.bls_signing_key.to_canonical_bytes()
            && self.get_verification_key_proof_of_possession_for_concatenation()
                == other.get_verification_key_proof_of_possession_for_concatenation();

        #[cfg(feature = "snark")]
        let base_eq = base_eq
            && self.schnorr_signing_key == other.schnorr_signing_key
            && self.schnorr_verification_key == other.schnorr_verification_key;

        base_eq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "snark")]
    mod proof_of_bound_possession {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::Parameters;

        use super::*;

        fn test_parameters() -> Parameters {
            Parameters {
                m: 100,
                k: 5,
                phi_f: 0.2,
            }
        }

        #[test]
        fn returns_some_signature_when_schnorr_key_present_and_it_verifies() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let initializer = Initializer::new(test_parameters(), 100, &mut rng);
            let prefix = b"stake=100|epoch=5|pool_id=pool1a";

            let signature = initializer
                .create_proof_of_bound_possession(prefix, &mut rng)
                .expect("Proof of Bound Possession creation should not fail")
                .expect(
                    "Initializer::new always creates a schnorr key when future_snark is enabled",
                );

            initializer
                .schnorr_verification_key
                .expect("schnorr verification key should be present")
                .verify_proof_of_bound_possession(prefix, &signature)
                .expect(
                    "Proof of Bound Possession produced by Initializer should verify successfully",
                );
        }

        #[test]
        fn returns_none_when_schnorr_key_absent() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut initializer = Initializer::new(test_parameters(), 100, &mut rng);
            initializer.strip_snark_keys();
            let prefix = b"stake=100|epoch=5|pool_id=pool1a";

            let result = initializer.create_proof_of_bound_possession(prefix, &mut rng).expect(
                "Proof of Bound Possession creation should not fail even without a schnorr key",
            );

            assert!(
                result.is_none(),
                "No schnorr key means no Proof of Bound Possession should be created"
            );
        }
    }

    mod try_create_signer_with_key_collisions {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        #[cfg(feature = "snark")]
        use crate::membership_commitment::{MerkleTree, MerkleTreeSnarkLeaf};
        use crate::{KeyRegistration, MithrilMembershipDigest};

        use super::*;

        fn test_parameters() -> Parameters {
            Parameters {
                m: 100,
                k: 5,
                phi_f: 0.2,
            }
        }

        fn close_registration(initializers: &[Initializer]) -> ClosedKeyRegistration {
            let mut key_registration = KeyRegistration::initialize();
            for initializer in initializers {
                key_registration.register_by_entry(&initializer.clone().try_into().unwrap());
            }

            key_registration.close_registration(&test_parameters()).unwrap()
        }

        #[test]
        fn only_the_bls_key_collision_loser_fails_to_create_a_signer() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let owner = Initializer::new(test_parameters(), 200, &mut rng);
            let unrelated = Initializer::new(test_parameters(), 150, &mut rng);
            let mut copier = Initializer::new(test_parameters(), 100, &mut rng);
            copier.bls_signing_key = owner.bls_signing_key.clone();
            copier.bls_verification_key_proof_of_possession =
                owner.bls_verification_key_proof_of_possession;

            let closed_key_registration =
                close_registration(&[owner.clone(), unrelated.clone(), copier.clone()]);

            owner
                .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                .expect("the highest stake holder of a BLS key should get a signer");
            unrelated
                .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                .expect("a party without collision should get a signer");
            let error = copier
                .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                .expect_err("the loser of a BLS key collision should not get a signer");
            assert!(matches!(
                error.downcast_ref::<RegisterError>(),
                Some(RegisterError::UnregisteredInitializer)
            ));
        }

        #[cfg(feature = "snark")]
        #[test]
        fn only_the_snark_key_collision_winner_gets_a_snark_signer() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let owner = Initializer::new(test_parameters(), 200, &mut rng);
            let mut copier = Initializer::new(test_parameters(), 100, &mut rng);
            copier.schnorr_signing_key = owner.schnorr_signing_key.clone();
            copier.schnorr_verification_key = owner.schnorr_verification_key;

            let closed_key_registration = close_registration(&[owner.clone(), copier.clone()]);

            let owner_signer = owner
                .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                .expect("the highest stake holder of a SNARK key should get a signer");
            let copier_signer = copier
                .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                .expect("the loser of a SNARK key collision should still get a signer");

            assert!(
                owner_signer.snark_proof_signer.is_some(),
                "the highest stake holder of a SNARK key should get a SNARK signer"
            );
            assert!(
                copier_signer.snark_proof_signer.is_none(),
                "the loser of a SNARK key collision should not get a SNARK signer"
            );
        }

        #[cfg(feature = "snark")]
        #[test]
        fn snark_signer_index_opens_correct_signer_leaf() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

            let mut without_snark_key = Initializer::new(test_parameters(), 1, &mut rng);
            without_snark_key.strip_snark_keys();
            let mut snark_key_copier = Initializer::new(test_parameters(), 2, &mut rng);
            let mut bls_key_copier = Initializer::new(test_parameters(), 3, &mut rng);
            let snark_key_owner = Initializer::new(test_parameters(), 4, &mut rng);
            let bls_key_owner = Initializer::new(test_parameters(), 5, &mut rng);
            let unrelated = Initializer::new(test_parameters(), 6, &mut rng);

            snark_key_copier.schnorr_signing_key = snark_key_owner.schnorr_signing_key.clone();
            snark_key_copier.schnorr_verification_key = snark_key_owner.schnorr_verification_key;
            bls_key_copier.bls_signing_key = bls_key_owner.bls_signing_key.clone();
            bls_key_copier.bls_verification_key_proof_of_possession =
                bls_key_owner.bls_verification_key_proof_of_possession;

            let snark_signers = [snark_key_owner, bls_key_owner, unrelated];
            let initializers: Vec<Initializer> =
                [without_snark_key, snark_key_copier, bls_key_copier]
                    .into_iter()
                    .chain(snark_signers.clone())
                    .collect();

            let closed_key_registration = close_registration(&initializers);
            let closed_key_registration_for_snark = closed_key_registration
                .get_closed_key_registration_for_snark()
                .unwrap();
            let merkle_tree: MerkleTree<
                <MithrilMembershipDigest as MembershipDigest>::SnarkHash,
                MerkleTreeSnarkLeaf,
            > = closed_key_registration_for_snark.to_merkle_tree();
            let commitment = merkle_tree.to_merkle_tree_commitment();

            assert_eq!(
                snark_signers.len() + 1,
                closed_key_registration_for_snark.number_of_leaves(),
                "the SNARK leaves should be the SNARK signers and the BLS key copier"
            );
            for snark_signer in snark_signers {
                let signer = snark_signer
                    .try_create_signer::<MithrilMembershipDigest>(&closed_key_registration)
                    .expect("a party holding a SNARK leaf should get a signer");
                let snark_proof_signer = signer
                    .snark_proof_signer
                    .expect("a party holding a SNARK leaf should get a SNARK signer");
                let snark_signer_index = snark_proof_signer.get_snark_signer_index();
                assert_ne!(
                    signer.signer_index, snark_signer_index,
                    "the setup should give different Concatenation and SNARK indices"
                );
                let leaf = MerkleTreeSnarkLeaf(
                    snark_proof_signer.get_verification_key(),
                    snark_proof_signer.get_lottery_target_value(),
                );
                let path = merkle_tree.compute_merkle_tree_path(snark_signer_index as usize);

                commitment
                    .verify_leaf_membership_from_path(&leaf, &path)
                    .expect("the SNARK signer index should open the signer's own leaf");
            }
        }
    }

    mod golden {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::*;

        const GOLDEN_JSON: &str = r#"
            {
                "stake":1,
                "params":
                {
                    "m":20973,
                    "k":2422,
                    "phi_f":0.2
                },
                "sk":[64,129,87,121,27,239,221,215,2,103,45,207,207,201,157,163,81,47,156,14,168,24,137,15,203,106,183,73,88,14,242,207],
                "pk":
                {
                    "vk":[143,161,255,48,78,57,204,220,25,221,164,252,248,14,56,126,186,135,228,188,145,181,52,200,97,99,213,46,0,199,193,89,187,88,29,135,173,244,86,36,83,54,67,164,6,137,94,72,6,105,128,128,93,48,176,11,4,246,138,48,180,133,90,142,192,24,193,111,142,31,76,111,110,234,153,90,208,192,31,124,95,102,49,158,99,52,220,165,94,251,68,69,121,16,224,194],
                    "pop":[168,50,233,193,15,136,65,72,123,148,129,176,38,198,209,47,28,204,176,144,57,251,42,28,66,76,89,97,158,63,54,198,194,176,135,221,14,185,197,225,202,98,243,74,233,225,143,151,147,177,170,117,66,165,66,62,33,216,232,75,68,114,195,22,100,65,44,198,4,166,102,233,253,240,59,175,60,117,142,114,140,122,17,87,110,187,1,17,10,195,154,13,249,86,54,226]
                }
            }
        "#;

        fn golden_value() -> Initializer {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = BlsSigningKey::generate(&mut rng);
            let pk = VerificationKeyProofOfPossessionForConcatenation::from(&sk);
            Initializer {
                stake: 1,
                parameters: Parameters {
                    m: 20973,
                    k: 2422,
                    phi_f: 0.2,
                },
                bls_signing_key: sk,
                bls_verification_key_proof_of_possession: pk,
                #[cfg(feature = "snark")]
                schnorr_signing_key: None,
                #[cfg(feature = "snark")]
                schnorr_verification_key: None,
            }
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

        const GOLDEN_CBOR_BYTES: &[u8; 490] = &[
            1, 164, 101, 115, 116, 97, 107, 101, 1, 102, 112, 97, 114, 97, 109, 115, 163, 97, 109,
            25, 81, 237, 97, 107, 25, 9, 118, 101, 112, 104, 105, 95, 102, 251, 63, 201, 153, 153,
            153, 153, 153, 154, 98, 115, 107, 152, 32, 24, 64, 24, 129, 24, 87, 24, 121, 24, 27,
            24, 239, 24, 221, 24, 215, 2, 24, 103, 24, 45, 24, 207, 24, 207, 24, 201, 24, 157, 24,
            163, 24, 81, 24, 47, 24, 156, 14, 24, 168, 24, 24, 24, 137, 15, 24, 203, 24, 106, 24,
            183, 24, 73, 24, 88, 14, 24, 242, 24, 207, 98, 112, 107, 162, 98, 118, 107, 152, 96,
            24, 143, 24, 161, 24, 255, 24, 48, 24, 78, 24, 57, 24, 204, 24, 220, 24, 25, 24, 221,
            24, 164, 24, 252, 24, 248, 14, 24, 56, 24, 126, 24, 186, 24, 135, 24, 228, 24, 188, 24,
            145, 24, 181, 24, 52, 24, 200, 24, 97, 24, 99, 24, 213, 24, 46, 0, 24, 199, 24, 193,
            24, 89, 24, 187, 24, 88, 24, 29, 24, 135, 24, 173, 24, 244, 24, 86, 24, 36, 24, 83, 24,
            54, 24, 67, 24, 164, 6, 24, 137, 24, 94, 24, 72, 6, 24, 105, 24, 128, 24, 128, 24, 93,
            24, 48, 24, 176, 11, 4, 24, 246, 24, 138, 24, 48, 24, 180, 24, 133, 24, 90, 24, 142,
            24, 192, 24, 24, 24, 193, 24, 111, 24, 142, 24, 31, 24, 76, 24, 111, 24, 110, 24, 234,
            24, 153, 24, 90, 24, 208, 24, 192, 24, 31, 24, 124, 24, 95, 24, 102, 24, 49, 24, 158,
            24, 99, 24, 52, 24, 220, 24, 165, 24, 94, 24, 251, 24, 68, 24, 69, 24, 121, 16, 24,
            224, 24, 194, 99, 112, 111, 112, 152, 96, 24, 168, 24, 50, 24, 233, 24, 193, 15, 24,
            136, 24, 65, 24, 72, 24, 123, 24, 148, 24, 129, 24, 176, 24, 38, 24, 198, 24, 209, 24,
            47, 24, 28, 24, 204, 24, 176, 24, 144, 24, 57, 24, 251, 24, 42, 24, 28, 24, 66, 24, 76,
            24, 89, 24, 97, 24, 158, 24, 63, 24, 54, 24, 198, 24, 194, 24, 176, 24, 135, 24, 221,
            14, 24, 185, 24, 197, 24, 225, 24, 202, 24, 98, 24, 243, 24, 74, 24, 233, 24, 225, 24,
            143, 24, 151, 24, 147, 24, 177, 24, 170, 24, 117, 24, 66, 24, 165, 24, 66, 24, 62, 24,
            33, 24, 216, 24, 232, 24, 75, 24, 68, 24, 114, 24, 195, 22, 24, 100, 24, 65, 24, 44,
            24, 198, 4, 24, 166, 24, 102, 24, 233, 24, 253, 24, 240, 24, 59, 24, 175, 24, 60, 24,
            117, 24, 142, 24, 114, 24, 140, 24, 122, 17, 24, 87, 24, 110, 24, 187, 1, 17, 10, 24,
            195, 24, 154, 13, 24, 249, 24, 86, 24, 54, 24, 226,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = Initializer::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = golden_value()
                .to_bytes()
                .expect("Initializer serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }
}
