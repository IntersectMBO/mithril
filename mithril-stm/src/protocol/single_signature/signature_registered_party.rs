use serde::{Deserialize, Serialize, Serializer, ser::SerializeTuple};

use crate::{ClosedRegistrationEntry, MembershipDigest, StmResult, codec};

use super::{SignatureError, SingleSignature};

/// CBOR-friendly envelope for `SingleSignatureWithRegisteredParty` serialization.
///
/// Used as an intermediate representation because `SingleSignatureWithRegisteredParty`
/// has a custom tuple-based `Serialize` implementation that is incompatible with
/// ciborium's derived `Deserialize` (which expects map format). Each sub-component
/// is stored as pre-serialized bytes to avoid this mismatch.
#[derive(Serialize, Deserialize)]
struct SingleSignatureWithRegisteredPartyCborEnvelope {
    signature_bytes: Vec<u8>,
    registration_entry_bytes: Vec<u8>,
}

/// Signature with its registered party.
#[derive(Debug, Clone, Hash, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SingleSignatureWithRegisteredParty {
    /// Stm signature
    pub sig: SingleSignature,
    /// Registered party
    pub reg_party: ClosedRegistrationEntry,
}

impl SingleSignatureWithRegisteredParty {
    /// Convert `SingleSignatureWithRegisteredParty` to CBOR bytes with a version prefix.
    ///
    /// Uses an intermediate envelope struct to avoid ciborium incompatibility
    /// with the custom tuple-based `Serialize` implementation.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        let envelope = SingleSignatureWithRegisteredPartyCborEnvelope {
            signature_bytes: self.sig.to_bytes()?,
            registration_entry_bytes: self.reg_party.to_bytes()?,
        };
        codec::to_cbor_bytes(&envelope)
    }

    /// Extract a `SingleSignatureWithRegisteredParty` from a byte slice.
    ///
    /// Supports both the new versioned CBOR format and the legacy byte-packed format.
    pub fn from_bytes<D: MembershipDigest>(
        bytes: &[u8],
    ) -> StmResult<SingleSignatureWithRegisteredParty> {
        if codec::has_cbor_v1_prefix(bytes) {
            let envelope: SingleSignatureWithRegisteredPartyCborEnvelope =
                codec::from_cbor_bytes(&bytes[1..])?;
            let sig = SingleSignature::from_bytes::<D>(&envelope.signature_bytes)?;
            let reg_party =
                ClosedRegistrationEntry::from_bytes(&envelope.registration_entry_bytes)?;
            Ok(SingleSignatureWithRegisteredParty { sig, reg_party })
        } else {
            Self::from_bytes_legacy::<D>(bytes)
        }
    }

    /// Extract a `SingleSignatureWithRegisteredParty` from a byte slice using the legacy format.
    /// # Layout
    /// * RegParty length (u64 big-endian)
    /// * RegParty
    /// * Signature length (u64 big-endian)
    /// * Signature
    fn from_bytes_legacy<D: MembershipDigest>(
        bytes: &[u8],
    ) -> StmResult<SingleSignatureWithRegisteredParty> {
        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(bytes.get(0..8).ok_or(SignatureError::SerializationError)?);
        let size_reg_party = u64::from_be_bytes(u64_bytes) as usize;
        let reg_party = ClosedRegistrationEntry::from_bytes(
            bytes
                .get(8..8 + size_reg_party)
                .ok_or(SignatureError::SerializationError)?,
        )?;

        let sig_offset = 8 + size_reg_party;
        u64_bytes.copy_from_slice(
            bytes
                .get(sig_offset..sig_offset + 8)
                .ok_or(SignatureError::SerializationError)?,
        );
        let size_sig = u64::from_be_bytes(u64_bytes) as usize;
        let sig = SingleSignature::from_bytes::<D>(
            bytes
                .get(sig_offset + 8..sig_offset + 8 + size_sig)
                .ok_or(SignatureError::SerializationError)?,
        )?;

        Ok(SingleSignatureWithRegisteredParty { sig, reg_party })
    }
}

impl Serialize for SingleSignatureWithRegisteredParty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.sig)?;
        tuple.serialize_element(&self.reg_party)?;
        tuple.end()
    }
}

#[cfg(test)]
mod tests {
    mod golden {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::{
            ClosedKeyRegistration, ClosedRegistrationEntry, KeyRegistration,
            MithrilMembershipDigest, Parameters, RegistrationEntry, SingleSignature,
            SingleSignatureWithRegisteredParty, VerificationKeyProofOfPossessionForConcatenation,
            proof_system::ConcatenationProofSigner, signature_scheme::BlsSigningKey,
        };
        #[cfg(feature = "future_snark")]
        use crate::{
            MembershipDigest, VerificationKeyForSnark, proof_system::SnarkProofSigner,
            protocol::RegistrationEntryForSnark, signature_scheme::SchnorrSigningKey,
        };

        type D = MithrilMembershipDigest;

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_JSON: &str = r#"
        [
            {
                "sigma": [
                149, 157, 201, 187, 140, 54, 0, 128, 209, 88, 16, 203, 61, 78, 77, 98,
                161, 133, 58, 152, 29, 74, 217, 113, 64, 100, 10, 161, 186, 167, 133, 114,
                211, 153, 218, 56, 223, 84, 105, 242, 41, 54, 224, 170, 208, 185, 126, 83
                ],
                "indexes": [1, 4, 5, 8],
                "signer_index": 1
            },
            [
                [
                143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126,
                186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89,
                187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6,
                105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133, 90, 142, 192,
                24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208, 192, 31, 124, 95,
                102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16, 224, 194
                ],
                1
            ]
        ]
        "#;

        #[cfg(feature = "future_snark")]
        const GOLDEN_JSON: &str = r#"
        [
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
                            137, 215, 216, 65, 180, 96, 160, 51, 223, 205, 207, 72, 126, 244, 
                            123, 254, 158, 173, 49, 64, 2, 89, 94, 217, 101, 233, 98, 174, 110, 
                            16, 119, 210
                        ],
                        "response": [
                            31, 131, 67, 139, 239, 68, 151, 50, 252, 1, 16, 202, 248, 152, 179, 
                            131, 85, 107, 185, 90, 47, 252, 229, 113, 101, 42, 149, 0, 244, 60, 113, 10
                        ], 
                        "challenge": [
                            8, 157, 99, 181, 204, 141, 102, 113, 104, 162, 218, 158, 147, 6, 158, 
                            179, 52, 210, 159, 147, 1, 83, 70, 199, 198, 0, 238, 93, 62, 180, 10, 43
                        ]
                    },
                    "indices": []
                }
            },
            [
                [
                    143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126,
                    186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89,
                    187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6,
                    105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133, 90, 142, 192,
                    24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208, 192, 31, 124, 95,
                    102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16, 224, 194
                ],
                1,
                [
                    228, 235, 159, 243, 100, 74, 143, 74, 193, 127, 170, 87, 102, 1, 10, 220,
                    173, 141, 223, 53, 86, 104, 169, 168, 82, 136, 67, 233, 108, 18, 229, 93
                ],
                [
                    194, 71, 33, 27, 194, 63, 247, 234, 230, 51, 190, 78, 41, 36, 192, 130, 
                    112, 88, 3, 19, 29, 13, 169, 32, 237, 47, 40, 179, 162, 115, 20, 64
                ]
            ]
        ]
        "#;

        fn golden_value() -> SingleSignatureWithRegisteredParty {
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

            let mut key_reg = KeyRegistration::initialize();
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
            key_reg.register_by_entry(&entry1).unwrap();
            key_reg.register_by_entry(&entry2).unwrap();
            let closed_key_reg: ClosedKeyRegistration =
                key_reg.close_registration(&params).unwrap();
            let total_stake = closed_key_reg.get_total_stake();

            let concatenation_proof_signer: ConcatenationProofSigner<D> =
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    pk_1.vk,
                    closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment(),
                );
            let concatenation_signature =
                concatenation_proof_signer.create_single_signature(&message).unwrap();

            #[cfg(feature = "future_snark")]
            let snark_signature = {
                let key_registration_commitment = closed_key_reg
                    .to_merkle_tree::<<D as MembershipDigest>::SnarkHash, RegistrationEntryForSnark>(
                ).to_merkle_tree_commitment();
                let closed_registration_entry = ClosedRegistrationEntry::try_from((
                    entry1,
                    closed_key_reg.get_total_stake(),
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

            let signature = SingleSignature {
                concatenation_signature,
                signer_index: 1,
                #[cfg(feature = "future_snark")]
                snark_signature,
            };

            SingleSignatureWithRegisteredParty {
                sig: signature,
                reg_party: ClosedRegistrationEntry::try_from((entry1, total_stake, params.phi_f))
                    .unwrap(),
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

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_CBOR_BYTES: &[u8; 730] = &[
            1, 162, 111, 115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 98, 121, 116, 101, 115,
            152, 131, 1, 24, 191, 24, 101, 24, 115, 24, 105, 24, 103, 24, 109, 24, 97, 24, 152, 24,
            48, 24, 24, 24, 149, 24, 24, 24, 157, 24, 24, 24, 201, 24, 24, 24, 187, 24, 24, 24,
            140, 24, 24, 24, 54, 0, 24, 24, 24, 128, 24, 24, 24, 209, 24, 24, 24, 88, 16, 24, 24,
            24, 203, 24, 24, 24, 61, 24, 24, 24, 78, 24, 24, 24, 77, 24, 24, 24, 98, 24, 24, 24,
            161, 24, 24, 24, 133, 24, 24, 24, 58, 24, 24, 24, 152, 24, 24, 24, 29, 24, 24, 24, 74,
            24, 24, 24, 217, 24, 24, 24, 113, 24, 24, 24, 64, 24, 24, 24, 100, 10, 24, 24, 24, 161,
            24, 24, 24, 186, 24, 24, 24, 167, 24, 24, 24, 133, 24, 24, 24, 114, 24, 24, 24, 211,
            24, 24, 24, 153, 24, 24, 24, 218, 24, 24, 24, 56, 24, 24, 24, 223, 24, 24, 24, 84, 24,
            24, 24, 105, 24, 24, 24, 242, 24, 24, 24, 41, 24, 24, 24, 54, 24, 24, 24, 224, 24, 24,
            24, 170, 24, 24, 24, 208, 24, 24, 24, 185, 24, 24, 24, 126, 24, 24, 24, 83, 24, 103,
            24, 105, 24, 110, 24, 100, 24, 101, 24, 120, 24, 101, 24, 115, 24, 132, 1, 4, 5, 8, 24,
            108, 24, 115, 24, 105, 24, 103, 24, 110, 24, 101, 24, 114, 24, 95, 24, 105, 24, 110,
            24, 100, 24, 101, 24, 120, 1, 24, 255, 120, 24, 114, 101, 103, 105, 115, 116, 114, 97,
            116, 105, 111, 110, 95, 101, 110, 116, 114, 121, 95, 98, 121, 116, 101, 115, 152, 219,
            1, 24, 162, 24, 118, 24, 118, 24, 101, 24, 114, 24, 105, 24, 102, 24, 105, 24, 99, 24,
            97, 24, 116, 24, 105, 24, 111, 24, 110, 24, 95, 24, 107, 24, 101, 24, 121, 24, 95, 24,
            98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 96, 24, 24, 24, 143, 24, 24, 24,
            161, 24, 24, 24, 255, 24, 24, 24, 48, 24, 24, 24, 78, 24, 24, 24, 57, 24, 24, 24, 204,
            24, 24, 24, 220, 24, 24, 24, 25, 24, 24, 24, 221, 24, 24, 24, 164, 24, 24, 24, 252, 24,
            24, 24, 248, 14, 24, 24, 24, 56, 24, 24, 24, 126, 24, 24, 24, 186, 24, 24, 24, 135, 24,
            24, 24, 228, 24, 24, 24, 188, 24, 24, 24, 145, 24, 24, 24, 181, 24, 24, 24, 52, 24, 24,
            24, 200, 24, 24, 24, 97, 24, 24, 24, 99, 24, 24, 24, 213, 24, 24, 24, 46, 0, 24, 24,
            24, 199, 24, 24, 24, 193, 24, 24, 24, 89, 24, 24, 24, 187, 24, 24, 24, 88, 24, 24, 24,
            29, 24, 24, 24, 135, 24, 24, 24, 173, 24, 24, 24, 244, 24, 24, 24, 86, 24, 24, 24, 36,
            24, 24, 24, 83, 24, 24, 24, 54, 24, 24, 24, 67, 24, 24, 24, 164, 6, 24, 24, 24, 137,
            24, 24, 24, 94, 24, 24, 24, 72, 6, 24, 24, 24, 105, 24, 24, 24, 128, 24, 24, 24, 128,
            24, 24, 24, 93, 24, 24, 24, 48, 24, 24, 24, 176, 11, 4, 24, 24, 24, 246, 24, 24, 24,
            138, 24, 24, 24, 48, 24, 24, 24, 180, 24, 24, 24, 133, 24, 24, 24, 90, 24, 24, 24, 142,
            24, 24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 193, 24, 24, 24, 111, 24, 24, 24, 142, 24,
            24, 24, 31, 24, 24, 24, 76, 24, 24, 24, 111, 24, 24, 24, 110, 24, 24, 24, 234, 24, 24,
            24, 153, 24, 24, 24, 90, 24, 24, 24, 208, 24, 24, 24, 192, 24, 24, 24, 31, 24, 24, 24,
            124, 24, 24, 24, 95, 24, 24, 24, 102, 24, 24, 24, 49, 24, 24, 24, 158, 24, 24, 24, 99,
            24, 24, 24, 52, 24, 24, 24, 220, 24, 24, 24, 165, 24, 24, 24, 94, 24, 24, 24, 251, 24,
            24, 24, 68, 24, 24, 24, 69, 24, 24, 24, 121, 16, 24, 24, 24, 224, 24, 24, 24, 194, 24,
            101, 24, 115, 24, 116, 24, 97, 24, 107, 24, 101, 1,
        ];

        #[cfg(feature = "future_snark")]
        const GOLDEN_CBOR_BYTES: &[u8; 1721] = &[
            1, 162, 111, 115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 98, 121, 116, 101, 115,
            153, 1, 140, 1, 24, 191, 24, 101, 24, 115, 24, 105, 24, 103, 24, 109, 24, 97, 24, 152,
            24, 48, 24, 24, 24, 140, 18, 24, 24, 24, 156, 24, 24, 24, 86, 24, 24, 24, 86, 16, 24,
            24, 24, 179, 24, 24, 24, 117, 24, 24, 24, 148, 17, 24, 24, 24, 195, 24, 24, 24, 177,
            24, 24, 24, 207, 24, 24, 24, 235, 24, 24, 24, 93, 24, 24, 24, 252, 24, 24, 24, 78, 24,
            24, 24, 244, 24, 24, 24, 112, 24, 24, 24, 94, 24, 24, 24, 47, 18, 24, 24, 24, 158, 15,
            24, 24, 24, 78, 24, 24, 24, 76, 24, 24, 24, 80, 24, 24, 24, 43, 24, 24, 24, 116, 24,
            24, 24, 242, 24, 24, 24, 116, 24, 24, 24, 205, 24, 24, 24, 252, 21, 24, 24, 24, 194,
            24, 24, 24, 58, 24, 24, 24, 162, 24, 24, 24, 117, 24, 24, 24, 201, 24, 24, 24, 62, 24,
            24, 24, 40, 24, 24, 24, 190, 21, 24, 24, 24, 183, 24, 24, 24, 178, 24, 24, 24, 186, 24,
            24, 24, 196, 24, 24, 24, 136, 24, 103, 24, 105, 24, 110, 24, 100, 24, 101, 24, 120, 24,
            101, 24, 115, 24, 133, 3, 4, 5, 6, 7, 24, 108, 24, 115, 24, 105, 24, 103, 24, 110, 24,
            101, 24, 114, 24, 95, 24, 105, 24, 110, 24, 100, 24, 101, 24, 120, 1, 24, 111, 24, 115,
            24, 110, 24, 97, 24, 114, 24, 107, 24, 95, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97,
            24, 116, 24, 117, 24, 114, 24, 101, 24, 162, 24, 113, 24, 115, 24, 99, 24, 104, 24,
            110, 24, 111, 24, 114, 24, 114, 24, 95, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97, 24,
            116, 24, 117, 24, 114, 24, 101, 24, 163, 24, 112, 24, 99, 24, 111, 24, 109, 24, 109,
            24, 105, 24, 116, 24, 109, 24, 101, 24, 110, 24, 116, 24, 95, 24, 112, 24, 111, 24,
            105, 24, 110, 24, 116, 24, 152, 24, 32, 24, 24, 24, 137, 24, 24, 24, 215, 24, 24, 24,
            216, 24, 24, 24, 65, 24, 24, 24, 180, 24, 24, 24, 96, 24, 24, 24, 160, 24, 24, 24, 51,
            24, 24, 24, 223, 24, 24, 24, 205, 24, 24, 24, 207, 24, 24, 24, 72, 24, 24, 24, 126, 24,
            24, 24, 244, 24, 24, 24, 123, 24, 24, 24, 254, 24, 24, 24, 158, 24, 24, 24, 173, 24,
            24, 24, 49, 24, 24, 24, 64, 2, 24, 24, 24, 89, 24, 24, 24, 94, 24, 24, 24, 217, 24, 24,
            24, 101, 24, 24, 24, 233, 24, 24, 24, 98, 24, 24, 24, 174, 24, 24, 24, 110, 16, 24, 24,
            24, 119, 24, 24, 24, 210, 24, 104, 24, 114, 24, 101, 24, 115, 24, 112, 24, 111, 24,
            110, 24, 115, 24, 101, 24, 152, 24, 32, 24, 24, 24, 31, 24, 24, 24, 131, 24, 24, 24,
            67, 24, 24, 24, 139, 24, 24, 24, 239, 24, 24, 24, 68, 24, 24, 24, 151, 24, 24, 24, 50,
            24, 24, 24, 252, 1, 16, 24, 24, 24, 202, 24, 24, 24, 248, 24, 24, 24, 152, 24, 24, 24,
            179, 24, 24, 24, 131, 24, 24, 24, 85, 24, 24, 24, 107, 24, 24, 24, 185, 24, 24, 24, 90,
            24, 24, 24, 47, 24, 24, 24, 252, 24, 24, 24, 229, 24, 24, 24, 113, 24, 24, 24, 101, 24,
            24, 24, 42, 24, 24, 24, 149, 0, 24, 24, 24, 244, 24, 24, 24, 60, 24, 24, 24, 113, 10,
            24, 105, 24, 99, 24, 104, 24, 97, 24, 108, 24, 108, 24, 101, 24, 110, 24, 103, 24, 101,
            24, 152, 24, 32, 8, 24, 24, 24, 157, 24, 24, 24, 99, 24, 24, 24, 181, 24, 24, 24, 204,
            24, 24, 24, 141, 24, 24, 24, 102, 24, 24, 24, 113, 24, 24, 24, 104, 24, 24, 24, 162,
            24, 24, 24, 218, 24, 24, 24, 158, 24, 24, 24, 147, 6, 24, 24, 24, 158, 24, 24, 24, 179,
            24, 24, 24, 52, 24, 24, 24, 210, 24, 24, 24, 159, 24, 24, 24, 147, 1, 24, 24, 24, 83,
            24, 24, 24, 70, 24, 24, 24, 199, 24, 24, 24, 198, 0, 24, 24, 24, 238, 24, 24, 24, 93,
            24, 24, 24, 62, 24, 24, 24, 180, 10, 24, 24, 24, 43, 24, 103, 24, 105, 24, 110, 24,
            100, 24, 105, 24, 99, 24, 101, 24, 115, 24, 128, 24, 255, 120, 24, 114, 101, 103, 105,
            115, 116, 114, 97, 116, 105, 111, 110, 95, 101, 110, 116, 114, 121, 95, 98, 121, 116,
            101, 115, 153, 1, 206, 1, 24, 164, 24, 118, 24, 118, 24, 101, 24, 114, 24, 105, 24,
            102, 24, 105, 24, 99, 24, 97, 24, 116, 24, 105, 24, 111, 24, 110, 24, 95, 24, 107, 24,
            101, 24, 121, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 96, 24,
            24, 24, 143, 24, 24, 24, 161, 24, 24, 24, 255, 24, 24, 24, 48, 24, 24, 24, 78, 24, 24,
            24, 57, 24, 24, 24, 204, 24, 24, 24, 220, 24, 24, 24, 25, 24, 24, 24, 221, 24, 24, 24,
            164, 24, 24, 24, 252, 24, 24, 24, 248, 14, 24, 24, 24, 56, 24, 24, 24, 126, 24, 24, 24,
            186, 24, 24, 24, 135, 24, 24, 24, 228, 24, 24, 24, 188, 24, 24, 24, 145, 24, 24, 24,
            181, 24, 24, 24, 52, 24, 24, 24, 200, 24, 24, 24, 97, 24, 24, 24, 99, 24, 24, 24, 213,
            24, 24, 24, 46, 0, 24, 24, 24, 199, 24, 24, 24, 193, 24, 24, 24, 89, 24, 24, 24, 187,
            24, 24, 24, 88, 24, 24, 24, 29, 24, 24, 24, 135, 24, 24, 24, 173, 24, 24, 24, 244, 24,
            24, 24, 86, 24, 24, 24, 36, 24, 24, 24, 83, 24, 24, 24, 54, 24, 24, 24, 67, 24, 24, 24,
            164, 6, 24, 24, 24, 137, 24, 24, 24, 94, 24, 24, 24, 72, 6, 24, 24, 24, 105, 24, 24,
            24, 128, 24, 24, 24, 128, 24, 24, 24, 93, 24, 24, 24, 48, 24, 24, 24, 176, 11, 4, 24,
            24, 24, 246, 24, 24, 24, 138, 24, 24, 24, 48, 24, 24, 24, 180, 24, 24, 24, 133, 24, 24,
            24, 90, 24, 24, 24, 142, 24, 24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 193, 24, 24, 24,
            111, 24, 24, 24, 142, 24, 24, 24, 31, 24, 24, 24, 76, 24, 24, 24, 111, 24, 24, 24, 110,
            24, 24, 24, 234, 24, 24, 24, 153, 24, 24, 24, 90, 24, 24, 24, 208, 24, 24, 24, 192, 24,
            24, 24, 31, 24, 24, 24, 124, 24, 24, 24, 95, 24, 24, 24, 102, 24, 24, 24, 49, 24, 24,
            24, 158, 24, 24, 24, 99, 24, 24, 24, 52, 24, 24, 24, 220, 24, 24, 24, 165, 24, 24, 24,
            94, 24, 24, 24, 251, 24, 24, 24, 68, 24, 24, 24, 69, 24, 24, 24, 121, 16, 24, 24, 24,
            224, 24, 24, 24, 194, 24, 101, 24, 115, 24, 116, 24, 97, 24, 107, 24, 101, 1, 24, 120,
            24, 28, 24, 115, 24, 110, 24, 97, 24, 114, 24, 107, 24, 95, 24, 118, 24, 101, 24, 114,
            24, 105, 24, 102, 24, 105, 24, 99, 24, 97, 24, 116, 24, 105, 24, 111, 24, 110, 24, 95,
            24, 107, 24, 101, 24, 121, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152,
            24, 64, 24, 24, 24, 108, 24, 24, 24, 194, 24, 24, 24, 37, 24, 24, 24, 88, 24, 24, 24,
            86, 24, 24, 24, 184, 24, 24, 24, 80, 24, 24, 24, 116, 24, 24, 24, 41, 24, 24, 24, 86,
            24, 24, 24, 123, 24, 24, 24, 210, 24, 24, 24, 29, 24, 24, 24, 247, 24, 24, 24, 113, 24,
            24, 24, 158, 24, 24, 24, 170, 24, 24, 24, 115, 24, 24, 24, 94, 24, 24, 24, 130, 24, 24,
            24, 131, 24, 24, 24, 179, 9, 24, 24, 24, 174, 24, 24, 24, 252, 5, 24, 24, 24, 100, 14,
            24, 24, 24, 125, 15, 24, 24, 24, 235, 24, 24, 24, 32, 24, 24, 24, 228, 24, 24, 24, 235,
            24, 24, 24, 159, 24, 24, 24, 243, 24, 24, 24, 100, 24, 24, 24, 74, 24, 24, 24, 143, 24,
            24, 24, 74, 24, 24, 24, 193, 24, 24, 24, 127, 24, 24, 24, 170, 24, 24, 24, 87, 24, 24,
            24, 102, 1, 10, 24, 24, 24, 220, 24, 24, 24, 173, 24, 24, 24, 141, 24, 24, 24, 223, 24,
            24, 24, 53, 24, 24, 24, 86, 24, 24, 24, 104, 24, 24, 24, 169, 24, 24, 24, 168, 24, 24,
            24, 82, 24, 24, 24, 136, 24, 24, 24, 67, 24, 24, 24, 233, 24, 24, 24, 108, 18, 24, 24,
            24, 229, 24, 24, 24, 93, 24, 120, 24, 26, 24, 108, 24, 111, 24, 116, 24, 116, 24, 101,
            24, 114, 24, 121, 24, 95, 24, 116, 24, 97, 24, 114, 24, 103, 24, 101, 24, 116, 24, 95,
            24, 118, 24, 97, 24, 108, 24, 117, 24, 101, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101,
            24, 115, 24, 152, 24, 32, 24, 24, 24, 194, 24, 24, 24, 71, 24, 24, 24, 33, 24, 24, 24,
            27, 24, 24, 24, 194, 24, 24, 24, 63, 24, 24, 24, 247, 24, 24, 24, 234, 24, 24, 24, 230,
            24, 24, 24, 51, 24, 24, 24, 190, 24, 24, 24, 78, 24, 24, 24, 41, 24, 24, 24, 36, 24,
            24, 24, 192, 24, 24, 24, 130, 24, 24, 24, 112, 24, 24, 24, 88, 3, 19, 24, 24, 24, 29,
            13, 24, 24, 24, 169, 24, 24, 24, 32, 24, 24, 24, 237, 24, 24, 24, 47, 24, 24, 24, 40,
            24, 24, 24, 179, 24, 24, 24, 162, 24, 24, 24, 115, 20, 24, 24, 24, 64,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = SingleSignatureWithRegisteredParty::from_bytes::<D>(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = golden_value().to_bytes().expect("CBOR serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }
}
