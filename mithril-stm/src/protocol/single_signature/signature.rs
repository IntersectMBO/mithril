use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use crate::{
    AggregateVerificationKey, LotteryIndex, MembershipDigest, Parameters, SignerIndex, Stake,
    StmResult, VerificationKeyForConcatenation, codec,
    proof_system::SingleSignatureForConcatenation, signature_scheme::BlsSignature,
};
#[cfg(feature = "future_snark")]
use crate::{RegistrationEntryForSnark, proof_system::SingleSignatureForSnark};

use super::SignatureError;

/// Single signature created by a single party who has won the lottery.
/// Contains the underlying signature for the proof system and the registration index of the signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSignature {
    /// Underlying signature for concatenation proof system.
    #[serde(flatten)]
    pub(crate) concatenation_signature: SingleSignatureForConcatenation,
    /// Merkle tree index of the signer.
    pub signer_index: SignerIndex,
    /// Underlying signature for snark proof system.
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) snark_signature: Option<SingleSignatureForSnark>,
}

impl SingleSignature {
    /// Verify a `SingleSignature` by validating the underlying single signature for proof system.
    pub fn verify<D: MembershipDigest>(
        &self,
        params: &Parameters,
        pk: &VerificationKeyForConcatenation,
        stake: &Stake,
        avk: &AggregateVerificationKey<D>,
        msg: &[u8],
        #[cfg(feature = "future_snark")] snark_registration_entry: Option<
            RegistrationEntryForSnark,
        >,
    ) -> StmResult<()> {
        #[cfg(feature = "future_snark")]
        if let (Some(snark_signature), Some(entry), Some(snark_avk)) = (
            &self.snark_signature,
            snark_registration_entry,
            avk.to_snark_aggregate_verification_key(),
        ) {
            snark_signature.verify(&entry.0, msg, snark_avk)?;
        }

        self.concatenation_signature.verify(
            params,
            pk,
            stake,
            avk.to_concatenation_aggregate_verification_key(),
            msg,
        )
    }

    /// Verify that all lottery indices of the concatenation signature are valid.
    ///
    /// This only applies to the concatenation proof system, which checks that the signature indices
    /// won the lottery and are within the valid range. The SNARK proof system does not need
    /// equivalent checking here, its lottery validity is handled during the aggregation process.
    pub(crate) fn check_indices(
        &self,
        params: &Parameters,
        stake: &Stake,
        msg: &[u8],
        total_stake: &Stake,
    ) -> StmResult<()> {
        self.concatenation_signature
            .check_indices(params, stake, msg, total_stake)
    }

    /// Convert a `SingleSignature` into bytes using CBOR encoding.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Extract a `SingleSignature` from a byte slice.
    ///
    /// Supports both CBOR-encoded (version-prefixed) and legacy manually packed formats.
    pub fn from_bytes<D: MembershipDigest>(bytes: &[u8]) -> StmResult<SingleSignature> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Extract a `SingleSignature` from a legacy manually packed byte slice.
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<SingleSignature> {
        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(bytes.get(0..8).ok_or(SignatureError::SerializationError)?);
        let nr_indexes = u64::from_be_bytes(u64_bytes) as usize;

        let mut indexes = Vec::new();
        let mut offset = 8usize;
        for _ in 0..nr_indexes {
            let index_end =
                offset.checked_add(8).ok_or(SignatureError::SerializationError)?;
            u64_bytes.copy_from_slice(
                bytes
                    .get(offset..index_end)
                    .ok_or(SignatureError::SerializationError)?,
            );
            indexes.push(u64::from_be_bytes(u64_bytes));
            offset = index_end;
        }

        let sigma_end = offset.checked_add(48).ok_or(SignatureError::SerializationError)?;
        let sigma = BlsSignature::from_bytes(
            bytes
                .get(offset..sigma_end)
                .ok_or(SignatureError::SerializationError)?,
        )?;

        let signer_index_end =
            sigma_end.checked_add(8).ok_or(SignatureError::SerializationError)?;
        u64_bytes.copy_from_slice(
            bytes
                .get(sigma_end..signer_index_end)
                .ok_or(SignatureError::SerializationError)?,
        );
        let signer_index = u64::from_be_bytes(u64_bytes);

        #[cfg(feature = "future_snark")]
        let snark_signature = {
            let snark_offset = signer_index_end;
            if snark_offset < bytes.len() {
                let schnorr_signature_end = snark_offset
                    .checked_add(96)
                    .ok_or(SignatureError::SerializationError)?;
                let schnorr_signature = crate::UniqueSchnorrSignature::from_bytes(
                    bytes
                        .get(snark_offset..schnorr_signature_end)
                        .ok_or(SignatureError::SerializationError)?,
                )?;
                let nr_snark_indices_end = schnorr_signature_end
                    .checked_add(8)
                    .ok_or(SignatureError::SerializationError)?;
                u64_bytes.copy_from_slice(
                    bytes
                        .get(schnorr_signature_end..nr_snark_indices_end)
                        .ok_or(SignatureError::SerializationError)?,
                );
                let nr_snark_indices = u64::from_be_bytes(u64_bytes) as usize;

                let mut snark_indices = Vec::new();
                let mut snark_idx_offset = nr_snark_indices_end;
                for _ in 0..nr_snark_indices {
                    let snark_index_end = snark_idx_offset
                        .checked_add(8)
                        .ok_or(SignatureError::SerializationError)?;
                    u64_bytes.copy_from_slice(
                        bytes
                            .get(snark_idx_offset..snark_index_end)
                            .ok_or(SignatureError::SerializationError)?,
                    );
                    snark_indices.push(u64::from_be_bytes(u64_bytes));
                    snark_idx_offset = snark_index_end;
                }

                Some(SingleSignatureForSnark::new(
                    schnorr_signature,
                    snark_indices,
                ))
            } else {
                None
            }
        };

        Ok(SingleSignature {
            concatenation_signature: SingleSignatureForConcatenation::new(sigma, indexes),
            signer_index,
            #[cfg(feature = "future_snark")]
            snark_signature,
        })
    }

    /// Get indices of the single signature for concatenation proof system.
    pub fn get_concatenation_signature_indices(&self) -> Vec<LotteryIndex> {
        self.concatenation_signature.get_indices().to_vec()
    }

    /// Get underlying BLS signature of the concatenation single signature.
    pub fn get_concatenation_signature_sigma(&self) -> BlsSignature {
        self.concatenation_signature.get_sigma()
    }

    /// Set the indices of the single signature for concatenation proof system.
    pub fn set_concatenation_signature_indices(&mut self, indices: &[LotteryIndex]) {
        self.concatenation_signature.set_indices(indices)
    }

    /// Set the indices of the single signature for snark proof system.
    #[cfg(feature = "future_snark")]
    pub fn set_snark_signature_indices(&mut self, indices: &[LotteryIndex]) {
        if let Some(snark_signature) = &mut self.snark_signature {
            snark_signature.set_indices(indices);
        }
    }

    /// Get indices of the single signature for snark proof system.
    #[cfg(feature = "future_snark")]
    pub fn get_snark_signature_indices(&self) -> Option<Vec<LotteryIndex>> {
        self.snark_signature.as_ref().map(|s| s.get_indices().to_vec())
    }
}

impl Hash for SingleSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash_slice(&self.concatenation_signature.get_sigma().to_bytes(), state)
    }
}

impl PartialEq for SingleSignature {
    fn eq(&self, other: &Self) -> bool {
        self.concatenation_signature == other.concatenation_signature
    }
}

impl Eq for SingleSignature {}

impl PartialOrd for SingleSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for SingleSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.signer_index.cmp(&other.signer_index)
    }
}

#[cfg(test)]
mod tests {

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[cfg(feature = "future_snark")]
    use crate::{
        ClosedRegistrationEntry, MembershipDigest, VerificationKeyForSnark,
        proof_system::SnarkProofSigner, protocol::RegistrationEntryForSnark,
        signature_scheme::SchnorrSigningKey,
    };

    use crate::{
        KeyRegistration, MithrilMembershipDigest, Parameters, RegistrationEntry, SingleSignature,
        VerificationKeyProofOfPossessionForConcatenation, proof_system::ConcatenationProofSigner,
        signature_scheme::BlsSigningKey,
    };

    mod golden {
        use super::*;

        type D = MithrilMembershipDigest;

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_BYTES: &[u8; 96] = &[
            0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0,
            0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 8, 149, 157, 201, 187, 140, 54, 0, 128, 209, 88, 16, 203,
            61, 78, 77, 98, 161, 133, 58, 152, 29, 74, 217, 113, 64, 100, 10, 161, 186, 167, 133,
            114, 211, 153, 218, 56, 223, 84, 105, 242, 41, 54, 224, 170, 208, 185, 126, 83, 0, 0,
            0, 0, 0, 0, 0, 1,
        ];

        #[cfg(feature = "future_snark")]
        const GOLDEN_BYTES: &[u8; 208] = &[
            0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0,
            0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 140, 18, 156, 86, 86, 16, 179,
            117, 148, 17, 195, 177, 207, 235, 93, 252, 78, 244, 112, 94, 47, 18, 158, 15, 78, 76,
            80, 43, 116, 242, 116, 205, 252, 21, 194, 58, 162, 117, 201, 62, 40, 190, 21, 183, 178,
            186, 196, 136, 0, 0, 0, 0, 0, 0, 0, 1, 137, 215, 216, 65, 180, 96, 160, 51, 223, 205,
            207, 72, 126, 244, 123, 254, 158, 173, 49, 64, 2, 89, 94, 217, 101, 233, 98, 174, 110,
            16, 119, 210, 31, 131, 67, 139, 239, 68, 151, 50, 252, 1, 16, 202, 248, 152, 179, 131,
            85, 107, 185, 90, 47, 252, 229, 113, 101, 42, 149, 0, 244, 60, 113, 10, 8, 157, 99,
            181, 204, 141, 102, 113, 104, 162, 218, 158, 147, 6, 158, 179, 52, 210, 159, 147, 1,
            83, 70, 199, 198, 0, 238, 93, 62, 180, 10, 43, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        fn golden_value() -> SingleSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            #[cfg(not(feature = "future_snark"))]
            let message = [0u8; 16];

            #[cfg(feature = "future_snark")]
            let message = [0u8; 32];

            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let sk_1 = BlsSigningKey::generate(&mut rng);
            let sk_2 = BlsSigningKey::generate(&mut rng);
            let pk_1 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_1);
            let pk_2 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_2);

            #[cfg(feature = "future_snark")]
            let (schnorr_sk_1, schnorr_vk_1) = {
                let sk = SchnorrSigningKey::generate(&mut rng);
                let vk = VerificationKeyForSnark::new_from_signing_key(sk.clone());
                (sk, vk)
            };
            #[cfg(feature = "future_snark")]
            let schnorr_vk_2 = {
                let sk = SchnorrSigningKey::generate(&mut rng);
                VerificationKeyForSnark::new_from_signing_key(sk)
            };

            let mut registration = KeyRegistration::initialize();
            let entry1 = RegistrationEntry::new(
                pk_1,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_vk_1),
            )
            .unwrap();
            let entry2 = RegistrationEntry::new(
                pk_2,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_vk_2),
            )
            .unwrap();
            registration.register_by_entry(&entry1).unwrap();
            registration.register_by_entry(&entry2).unwrap();
            let closed_key_registration = registration.close_registration(&params).unwrap();

            let concatenation_proof_signer: ConcatenationProofSigner<D> =
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    pk_1.vk,
                    closed_key_registration
                        .to_merkle_tree()
                        .to_merkle_tree_batch_commitment(),
                );
            let concatenation_signature =
                concatenation_proof_signer.create_single_signature(&message).unwrap();

            #[cfg(feature = "future_snark")]
            let snark_signature = {
                let key_registration_commitment = closed_key_registration
                    .to_merkle_tree::<<D as MembershipDigest>::SnarkHash, RegistrationEntryForSnark>(
                ).to_merkle_tree_commitment();
                let closed_registration_entry = ClosedRegistrationEntry::try_from((
                    entry1,
                    closed_key_registration.get_total_stake(),
                    params.phi_f,
                ))
                .unwrap();
                let lottery_target_value =
                    closed_registration_entry.get_lottery_target_value().unwrap();
                let snark_proof_signer = SnarkProofSigner::<D>::new(
                    params,
                    schnorr_sk_1,
                    schnorr_vk_1,
                    lottery_target_value,
                    key_registration_commitment,
                );
                Some(
                    snark_proof_signer
                        .create_single_signature(&message, &mut rng)
                        .unwrap(),
                )
            };

            SingleSignature {
                concatenation_signature,
                signer_index: 1,
                #[cfg(feature = "future_snark")]
                snark_signature,
            }
        }

        #[test]
        fn golden_conversions() {
            let value = SingleSignature::from_bytes::<D>(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = SingleSignature::to_bytes(&value)
                .expect("SingleSignature serialization should not fail");
            let golden_serialized = SingleSignature::to_bytes(&golden_value())
                .expect("SingleSignature serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_CBOR_BYTES: &[u8; 131] = &[
            1, 191, 101, 115, 105, 103, 109, 97, 152, 48, 24, 149, 24, 157, 24, 201, 24, 187, 24,
            140, 24, 54, 0, 24, 128, 24, 209, 24, 88, 16, 24, 203, 24, 61, 24, 78, 24, 77, 24, 98,
            24, 161, 24, 133, 24, 58, 24, 152, 24, 29, 24, 74, 24, 217, 24, 113, 24, 64, 24, 100,
            10, 24, 161, 24, 186, 24, 167, 24, 133, 24, 114, 24, 211, 24, 153, 24, 218, 24, 56, 24,
            223, 24, 84, 24, 105, 24, 242, 24, 41, 24, 54, 24, 224, 24, 170, 24, 208, 24, 185, 24,
            126, 24, 83, 103, 105, 110, 100, 101, 120, 101, 115, 132, 1, 4, 5, 8, 108, 115, 105,
            103, 110, 101, 114, 95, 105, 110, 100, 101, 120, 1, 255,
        ];

        #[cfg(feature = "future_snark")]
        const GOLDEN_CBOR_BYTES: &[u8; 396] = &[
            1, 191, 101, 115, 105, 103, 109, 97, 152, 48, 24, 140, 18, 24, 156, 24, 86, 24, 86, 16,
            24, 179, 24, 117, 24, 148, 17, 24, 195, 24, 177, 24, 207, 24, 235, 24, 93, 24, 252, 24,
            78, 24, 244, 24, 112, 24, 94, 24, 47, 18, 24, 158, 15, 24, 78, 24, 76, 24, 80, 24, 43,
            24, 116, 24, 242, 24, 116, 24, 205, 24, 252, 21, 24, 194, 24, 58, 24, 162, 24, 117, 24,
            201, 24, 62, 24, 40, 24, 190, 21, 24, 183, 24, 178, 24, 186, 24, 196, 24, 136, 103,
            105, 110, 100, 101, 120, 101, 115, 133, 3, 4, 5, 6, 7, 108, 115, 105, 103, 110, 101,
            114, 95, 105, 110, 100, 101, 120, 1, 111, 115, 110, 97, 114, 107, 95, 115, 105, 103,
            110, 97, 116, 117, 114, 101, 162, 113, 115, 99, 104, 110, 111, 114, 114, 95, 115, 105,
            103, 110, 97, 116, 117, 114, 101, 163, 112, 99, 111, 109, 109, 105, 116, 109, 101, 110,
            116, 95, 112, 111, 105, 110, 116, 152, 32, 24, 137, 24, 215, 24, 216, 24, 65, 24, 180,
            24, 96, 24, 160, 24, 51, 24, 223, 24, 205, 24, 207, 24, 72, 24, 126, 24, 244, 24, 123,
            24, 254, 24, 158, 24, 173, 24, 49, 24, 64, 2, 24, 89, 24, 94, 24, 217, 24, 101, 24,
            233, 24, 98, 24, 174, 24, 110, 16, 24, 119, 24, 210, 104, 114, 101, 115, 112, 111, 110,
            115, 101, 152, 32, 24, 31, 24, 131, 24, 67, 24, 139, 24, 239, 24, 68, 24, 151, 24, 50,
            24, 252, 1, 16, 24, 202, 24, 248, 24, 152, 24, 179, 24, 131, 24, 85, 24, 107, 24, 185,
            24, 90, 24, 47, 24, 252, 24, 229, 24, 113, 24, 101, 24, 42, 24, 149, 0, 24, 244, 24,
            60, 24, 113, 10, 105, 99, 104, 97, 108, 108, 101, 110, 103, 101, 152, 32, 8, 24, 157,
            24, 99, 24, 181, 24, 204, 24, 141, 24, 102, 24, 113, 24, 104, 24, 162, 24, 218, 24,
            158, 24, 147, 6, 24, 158, 24, 179, 24, 52, 24, 210, 24, 159, 24, 147, 1, 24, 83, 24,
            70, 24, 199, 24, 198, 0, 24, 238, 24, 93, 24, 62, 24, 180, 10, 24, 43, 103, 105, 110,
            100, 105, 99, 101, 115, 128, 255,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = SingleSignature::from_bytes::<D>(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = golden_value()
                .to_bytes()
                .expect("SingleSignature serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }

    mod golden_json {
        use super::*;

        type D = MithrilMembershipDigest;

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_JSON: &str = r#"
        {
            "sigma": [
                149, 157, 201, 187, 140, 54, 0, 128, 209, 88, 16, 203, 61, 78, 77, 98, 161,
                133, 58, 152, 29, 74, 217, 113, 64, 100, 10, 161, 186, 167, 133, 114, 211,
                153, 218, 56, 223, 84, 105, 242, 41, 54, 224, 170, 208, 185, 126, 83
            ],
            "indexes": [1, 4, 5, 8],
            "signer_index": 1
        }"#;

        #[cfg(feature = "future_snark")]
        const GOLDEN_JSON: &str = r#"
        {
            "sigma": [
                140, 18, 156, 86, 86, 16, 179, 117, 148, 17, 195, 177, 207, 235, 93, 252,
                78, 244, 112, 94, 47, 18, 158, 15, 78, 76, 80, 43, 116, 242, 116, 205,
                252, 21, 194, 58, 162, 117, 201, 62, 40, 190, 21, 183, 178, 186, 196, 136
            ],
            "indexes": [3, 4, 5, 6, 7],
            "signer_index": 1,
            "snark_signature": {
                "schnorr_signature": {
                    "commitment_point": [
                        137, 215, 216, 65, 180, 96, 160, 51, 223, 205, 207, 72, 126, 
                        244, 123, 254, 158, 173, 49, 64, 2, 89, 94, 217, 101, 233, 98, 
                        174, 110, 16, 119, 210
                    ], 
                    "response": [
                        31, 131, 67, 139, 239, 68, 151, 50, 252, 1, 16, 202, 248, 152,
                        179, 131, 85, 107, 185, 90, 47, 252, 229, 113, 101, 42, 149, 0,
                        244, 60, 113, 10
                    ], 
                    "challenge": [
                        8, 157, 99, 181, 204, 141, 102, 113, 104, 162, 218, 158, 147, 
                        6, 158, 179, 52, 210, 159, 147, 1, 83, 70, 199, 198, 0, 238, 
                        93, 62, 180, 10, 43
                    ]
                },
                "indices": []
            }
        }"#;

        fn golden_value() -> SingleSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            #[cfg(not(feature = "future_snark"))]
            let message = [0u8; 16];

            #[cfg(feature = "future_snark")]
            let message = [0u8; 32];

            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let sk_1 = BlsSigningKey::generate(&mut rng);
            let sk_2 = BlsSigningKey::generate(&mut rng);
            let pk_1 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_1);
            let pk_2 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_2);

            #[cfg(feature = "future_snark")]
            let (schnorr_sk_1, schnorr_vk_1) = {
                let sk = SchnorrSigningKey::generate(&mut rng);
                let vk = VerificationKeyForSnark::new_from_signing_key(sk.clone());
                (sk, vk)
            };
            #[cfg(feature = "future_snark")]
            let schnorr_vk_2 = {
                let sk = SchnorrSigningKey::generate(&mut rng);
                VerificationKeyForSnark::new_from_signing_key(sk)
            };

            let mut registration = KeyRegistration::initialize();
            let entry1 = RegistrationEntry::new(
                pk_1,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_vk_1),
            )
            .unwrap();
            let entry2 = RegistrationEntry::new(
                pk_2,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_vk_2),
            )
            .unwrap();
            registration.register_by_entry(&entry1).unwrap();
            registration.register_by_entry(&entry2).unwrap();

            let closed_key_registration = registration.close_registration(&params).unwrap();

            let concatenation_proof_signer: ConcatenationProofSigner<D> =
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    pk_1.vk,
                    closed_key_registration
                        .to_merkle_tree()
                        .to_merkle_tree_batch_commitment(),
                );
            let concatenation_signature =
                concatenation_proof_signer.create_single_signature(&message).unwrap();

            #[cfg(feature = "future_snark")]
            let snark_signature = {
                let key_registration_commitment = closed_key_registration
                    .to_merkle_tree::<<D as MembershipDigest>::SnarkHash, RegistrationEntryForSnark>(
                ).to_merkle_tree_commitment();
                let closed_registration_entry = ClosedRegistrationEntry::try_from((
                    entry1,
                    closed_key_registration.get_total_stake(),
                    params.phi_f,
                ))
                .unwrap();
                let lottery_target_value =
                    closed_registration_entry.get_lottery_target_value().unwrap();
                let snark_proof_signer = SnarkProofSigner::<D>::new(
                    params,
                    schnorr_sk_1,
                    schnorr_vk_1,
                    lottery_target_value,
                    key_registration_commitment,
                );
                Some(
                    snark_proof_signer
                        .create_single_signature(&message, &mut rng)
                        .unwrap(),
                )
            };

            SingleSignature {
                concatenation_signature,
                signer_index: 1,
                #[cfg(feature = "future_snark")]
                snark_signature,
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
    }

    mod negative_tests_for_concatenation {
        use super::*;
        use crate::{AggregateVerificationKey, BlsSignatureError, Clerk, SignatureError, Signer};

        type D = MithrilMembershipDigest;

        const TEST_MESSAGE: [u8; 16] = [42u8; 16];

        fn test_parameters() -> Parameters {
            Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            }
        }

        struct SingleSignatureTestContext {
            signer_1: Signer<D>,
            vk_1: VerificationKeyProofOfPossessionForConcatenation,
            vk_2: VerificationKeyProofOfPossessionForConcatenation,
            avk: AggregateVerificationKey<D>,
        }

        fn build_single_signature_context(
            number_of_signers: usize,
            rng_seed: [u8; 32],
        ) -> SingleSignatureTestContext {
            assert!(
                number_of_signers >= 2,
                "at least 2 signers are required for these tests"
            );

            let mut rng = ChaCha20Rng::from_seed(rng_seed);
            let params = test_parameters();

            let mut signing_keys = Vec::with_capacity(number_of_signers);
            let mut verification_keys = Vec::with_capacity(number_of_signers);
            for _ in 0..number_of_signers {
                let signing_key = BlsSigningKey::generate(&mut rng);
                let verification_key =
                    VerificationKeyProofOfPossessionForConcatenation::from(&signing_key);
                signing_keys.push(signing_key);
                verification_keys.push(verification_key);
            }

            let mut registration = KeyRegistration::initialize();
            for verification_key in &verification_keys {
                let entry = RegistrationEntry::new(
                    *verification_key,
                    1,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .unwrap();
                registration.register_by_entry(&entry).unwrap();
            }

            let closed_key_registration = registration.close_registration(&params).unwrap();
            let mut signing_keys = signing_keys.into_iter();
            let sk_1 = signing_keys.next().expect("at least one signer exists");
            let mut verification_keys = verification_keys.into_iter();
            let vk_1 = verification_keys.next().expect(
                "internal test setup invariant violated: missing first verification key (vk_1)",
            );
            let vk_2 = verification_keys.next().expect(
                "internal test setup invariant violated: missing second verification key (vk_2)",
            );
            let signer_1: Signer<D> = Signer::new(
                1,
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    vk_1.vk,
                    closed_key_registration
                        .to_merkle_tree()
                        .to_merkle_tree_batch_commitment(),
                ),
                closed_key_registration,
                params,
                1,
                #[cfg(feature = "future_snark")]
                None,
            );

            let clerk = Clerk::new_clerk_from_signer(&signer_1);
            let avk = clerk.compute_aggregate_verification_key();

            SingleSignatureTestContext {
                signer_1,
                vk_1,
                vk_2,
                avk,
            }
        }

        #[test]
        fn verify_fails_with_wrong_verification_key() {
            let ctx = build_single_signature_context(2, [0u8; 32]);
            let signature = ctx
                .signer_1
                .create_single_signature(&TEST_MESSAGE)
                .expect("signature should be created");

            let params = test_parameters();
            let error = signature
                .verify(
                    &params,
                    &ctx.vk_2.vk,
                    &1,
                    &ctx.avk,
                    &TEST_MESSAGE,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .expect_err("Verification should fail with wrong verification key");
            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::SignatureInvalid(_))
                ),
                "Unexpected error variant: {error:?}"
            );
        }

        #[test]
        fn verify_fails_with_out_of_bounds_index() {
            let ctx = build_single_signature_context(2, [0u8; 32]);
            let mut signature = ctx
                .signer_1
                .create_single_signature(&TEST_MESSAGE)
                .expect("signature should be created");

            let params = test_parameters();
            signature.set_concatenation_signature_indices(&[params.m + 1]);

            let error = signature
                .verify(
                    &params,
                    &ctx.vk_1.vk,
                    &1,
                    &ctx.avk,
                    &TEST_MESSAGE,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .expect_err("Verification should fail with invalid index");
            assert!(
                matches!(
                    error.downcast_ref::<SignatureError>(),
                    Some(SignatureError::IndexBoundFailed(_, _))
                ),
                "Unexpected error variant: {error:?}"
            );
        }

        #[test]
        fn verify_fails_with_wrong_message() {
            let ctx = build_single_signature_context(2, [0u8; 32]);
            let signature = ctx
                .signer_1
                .create_single_signature(&TEST_MESSAGE)
                .expect("signature should be created");
            let wrong_message = [43u8; 16];

            let params = test_parameters();
            let error = signature
                .verify(
                    &params,
                    &ctx.vk_1.vk,
                    &1,
                    &ctx.avk,
                    &wrong_message,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .expect_err("Verification should fail with wrong message");
            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::SignatureInvalid(_))
                ),
                "Unexpected error variant: {error:?}"
            );
        }

        #[test]
        fn verify_fails_with_different_registration_avk() {
            let signing_ctx = build_single_signature_context(2, [0u8; 32]);
            let different_registration_ctx = build_single_signature_context(3, [0u8; 32]);
            let signature = signing_ctx
                .signer_1
                .create_single_signature(&TEST_MESSAGE)
                .expect("signature should be created");

            let params = test_parameters();
            let error = signature
                .verify(
                    &params,
                    &signing_ctx.vk_1.vk,
                    &1,
                    &different_registration_ctx.avk,
                    &TEST_MESSAGE,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .expect_err("Verification should fail with a different registration AVK");
            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::SignatureInvalid(_))
                ),
                "Unexpected error variant: {error:?}"
            );
        }
    }
}
