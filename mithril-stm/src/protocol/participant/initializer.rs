#[cfg(feature = "future_snark")]
use anyhow::Context;
use anyhow::anyhow;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    ClosedKeyRegistration, MembershipDigest, Parameters, RegisterError, RegistrationEntry,
    RegistrationEntryForConcatenation, Stake, StmResult,
    VerificationKeyProofOfPossessionForConcatenation, proof_system::ConcatenationProofSigner,
    signature_scheme::BlsSigningKey,
};
#[cfg(feature = "future_snark")]
use crate::{
    ClosedRegistrationEntry, RegistrationEntryForSnark, VerificationKeyForSnark,
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
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schnorr_signing_key: Option<SchnorrSigningKey>,
    /// Verification key for snark proof system.
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schnorr_verification_key: Option<VerificationKeyForSnark>,
}

impl Initializer {
    /// Creates a new initializer
    pub fn new<R: RngCore + CryptoRng>(parameters: Parameters, stake: Stake, rng: &mut R) -> Self {
        let bls_signing_key = BlsSigningKey::generate(rng);
        let bls_verification_key_proof_of_possession =
            VerificationKeyProofOfPossessionForConcatenation::from(&bls_signing_key);
        #[cfg(feature = "future_snark")]
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
            #[cfg(feature = "future_snark")]
            schnorr_signing_key,
            #[cfg(feature = "future_snark")]
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
            #[cfg(feature = "future_snark")]
            self.schnorr_verification_key,
        )?;

        let signer_index = closed_key_registration
            .get_signer_index_for_registration(
                &(
                    registration_entry,
                    closed_key_registration.get_total_stake(),
                    self.parameters.phi_f,
                )
                    .try_into()?,
            )
            .ok_or_else(|| anyhow!(RegisterError::UnregisteredInitializer))?;

        let key_registration_commitment_for_concatenation = closed_key_registration
            .to_merkle_tree::<D::ConcatenationHash, RegistrationEntryForConcatenation>()
            .to_merkle_tree_batch_commitment();
        let concatenation_proof_signer = ConcatenationProofSigner::new(
            registration_entry.get_stake(),
            closed_key_registration.get_total_stake(),
            self.parameters,
            self.bls_signing_key,
            self.bls_verification_key_proof_of_possession.vk,
            key_registration_commitment_for_concatenation,
        );

        #[cfg(feature = "future_snark")]
        let snark_proof_signer = {
            match (self.schnorr_signing_key, self.schnorr_verification_key) {
                (Some(schnorr_signing_key), Some(schnorr_verification_key)) => {
                    let key_registration_commitment_for_snark = closed_key_registration
                        .to_merkle_tree::<D::SnarkHash, RegistrationEntryForSnark>()
                        .to_merkle_tree_commitment();
                    let lottery_target_value = ClosedRegistrationEntry::try_from((
                        registration_entry,
                        closed_key_registration.get_total_stake(),
                        self.parameters.phi_f,
                    ))?
                    .get_lottery_target_value()
                    .ok_or(RegisterError::SnarkProofSignerCreation)
                    .with_context(|| "missing lottery target value")?;
                    Some(SnarkProofSigner::new(
                        self.parameters,
                        schnorr_signing_key,
                        schnorr_verification_key,
                        lottery_target_value,
                        key_registration_commitment_for_snark,
                    ))
                }
                _ => None,
            }
        };

        // Create and return signer
        Ok(Signer::new(
            signer_index,
            concatenation_proof_signer,
            closed_key_registration.clone(),
            self.parameters,
            registration_entry.get_stake(),
            #[cfg(feature = "future_snark")]
            snark_proof_signer,
        ))
    }

    /// Extract the verification key with proof of possession.
    pub fn get_verification_key_proof_of_possession_for_concatenation(
        &self,
    ) -> VerificationKeyProofOfPossessionForConcatenation {
        self.bls_verification_key_proof_of_possession
    }

    /// Extract the verification key for snark.
    #[cfg(feature = "future_snark")]
    pub fn get_verification_key_for_snark(&self) -> Option<VerificationKeyForSnark> {
        self.schnorr_verification_key
    }

    /// Remove the SNARK-related keys (Schnorr signing and verification keys) from this
    /// initializer.
    ///
    /// This is used during eras that do not yet support SNARK proofs to ensure the
    /// initializer's registration entry matches the closed key registration built from
    /// signers without SNARK verification keys.
    #[cfg(feature = "future_snark")]
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
    /// * [Future Snark - Schnorr Signing Key]
    /// * [Future Snark - Schnorr Verification Key]
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Initializer> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(RegisterError::SerializationError)?);
        let stake = u64::from_be_bytes(u64_bytes);
        let params =
            Parameters::from_bytes(bytes.get(8..32).ok_or(RegisterError::SerializationError)?)?;
        let bls_signing_key =
            BlsSigningKey::from_bytes(bytes.get(32..64).ok_or(RegisterError::SerializationError)?)?;
        let bls_verification_key_proof_of_possession =
            VerificationKeyProofOfPossessionForConcatenation::from_bytes(
                bytes.get(64..256).ok_or(RegisterError::SerializationError)?,
            )?;

        #[cfg(feature = "future_snark")]
        let (schnorr_signing_key, schnorr_verification_key) = {
            let schnorr_signing_key =
                bytes.get(256..288).map(SchnorrSigningKey::from_bytes).transpose()?;
            let schnorr_verification_key = bytes
                .get(288..352)
                .map(VerificationKeyForSnark::from_bytes)
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
            #[cfg(feature = "future_snark")]
            schnorr_signing_key,
            #[cfg(feature = "future_snark")]
            schnorr_verification_key,
        })
    }
}

impl PartialEq for Initializer {
    fn eq(&self, other: &Self) -> bool {
        let base_eq = self.stake == other.stake
            && self.parameters == other.parameters
            && self.bls_signing_key.to_bytes() == other.bls_signing_key.to_bytes()
            && self.get_verification_key_proof_of_possession_for_concatenation()
                == other.get_verification_key_proof_of_possession_for_concatenation();

        #[cfg(feature = "future_snark")]
        let base_eq = base_eq
            && self.schnorr_signing_key == other.schnorr_signing_key
            && self.schnorr_verification_key == other.schnorr_verification_key;

        base_eq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                #[cfg(feature = "future_snark")]
                schnorr_signing_key: None,
                #[cfg(feature = "future_snark")]
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
