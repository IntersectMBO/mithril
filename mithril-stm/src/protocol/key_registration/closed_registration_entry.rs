use serde::{Deserialize, Serialize, Serializer, ser::SerializeTuple};
use std::cmp::Ordering;
use std::hash::Hash;

use crate::{
    PhiFValue, RegisterError, RegistrationEntry, Stake, StmResult, VerificationKeyForConcatenation,
    codec,
};

#[cfg(feature = "future_snark")]
use crate::{
    LotteryTargetValue, VerificationKeyForSnark,
    proof_system::compute_target_value_for_snark_lottery,
};

/// CBOR-friendly envelope for `ClosedRegistrationEntry` serialization.
///
/// Used as an intermediate representation because `ClosedRegistrationEntry`
/// has a custom tuple-based `Serialize` implementation that is incompatible
/// with ciborium's derived `Deserialize` (which expects map format).
#[derive(Serialize, Deserialize)]
struct ClosedRegistrationEntryCborEnvelope {
    verification_key_bytes: Vec<u8>,
    stake: Stake,
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    snark_verification_key_bytes: Option<Vec<u8>>,
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    lottery_target_value_bytes: Option<Vec<u8>>,
}

/// Represents a registration entry of a closed key registration.
#[derive(PartialEq, Eq, Clone, Debug, Deserialize)]
pub struct ClosedRegistrationEntry {
    verification_key_for_concatenation: VerificationKeyForConcatenation,
    stake: Stake,
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    verification_key_for_snark: Option<VerificationKeyForSnark>,
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    lottery_target_value: Option<LotteryTargetValue>,
}

impl ClosedRegistrationEntry {
    /// Creates a new closed registration entry.
    ///
    /// This is private rather than `pub`: it performs no verification of any kind (unlike
    /// `RegistrationEntry::new`, which verifies proof of possession), so it must only be used
    /// where the caller has already established the verification key is trustworthy — currently
    /// only via `TryFrom<(RegistrationEntry, Stake, PhiFValue)>`, which derives from an
    /// already-verified `RegistrationEntry`.
    fn new(
        verification_key_for_concatenation: VerificationKeyForConcatenation,
        stake: Stake,
        #[cfg(feature = "future_snark")] verification_key_for_snark: Option<
            VerificationKeyForSnark,
        >,
        #[cfg(feature = "future_snark")] lottery_target_value: Option<LotteryTargetValue>,
    ) -> Self {
        ClosedRegistrationEntry {
            verification_key_for_concatenation,
            stake,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark,
            #[cfg(feature = "future_snark")]
            lottery_target_value,
        }
    }

    /// Gets the verification key for concatenation.
    pub fn get_verification_key_for_concatenation(&self) -> VerificationKeyForConcatenation {
        self.verification_key_for_concatenation
    }

    /// Gets the stake.
    pub fn get_stake(&self) -> Stake {
        self.stake
    }

    /// Returns a copy of this entry with SNARK-specific fields removed.
    ///
    /// This is used when embedding registration entries in concatenation proofs,
    /// which do not need SNARK fields and must remain backward-compatible with
    /// clients that do not support the `future_snark` feature.
    #[cfg(feature = "future_snark")]
    pub fn without_snark_fields(&self) -> Self {
        ClosedRegistrationEntry {
            verification_key_for_concatenation: self.verification_key_for_concatenation,
            stake: self.stake,
            verification_key_for_snark: None,
            lottery_target_value: None,
        }
    }

    #[cfg(feature = "future_snark")]
    /// Gets the verification key for snark.
    pub fn get_verification_key_for_snark(&self) -> Option<VerificationKeyForSnark> {
        self.verification_key_for_snark
    }

    #[cfg(feature = "future_snark")]
    /// Gets the lottery target value.
    pub fn get_lottery_target_value(&self) -> Option<LotteryTargetValue> {
        self.lottery_target_value
    }

    /// Converts the registration entry to CBOR bytes with a version prefix.
    ///
    /// Uses an intermediate envelope struct to avoid ciborium incompatibility
    /// with the custom tuple-based `Serialize` implementation.
    pub(crate) fn to_bytes(&self) -> StmResult<Vec<u8>> {
        let envelope = ClosedRegistrationEntryCborEnvelope {
            verification_key_bytes: self.verification_key_for_concatenation.to_bytes().to_vec(),
            stake: self.stake,
            #[cfg(feature = "future_snark")]
            snark_verification_key_bytes: self
                .verification_key_for_snark
                .map(|vk| vk.to_bytes().to_vec()),
            #[cfg(feature = "future_snark")]
            lottery_target_value_bytes: self
                .lottery_target_value
                .map(|ltv| ltv.to_bytes().to_vec()),
        };
        codec::to_cbor_bytes(&envelope)
    }

    /// Creates a registration entry from versioned bytes.
    ///
    /// If the bytes start with the CBOR v1 version prefix, decodes the remaining bytes as CBOR.
    /// Otherwise, falls back to the legacy byte-packing format.
    pub(crate) fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            let envelope: ClosedRegistrationEntryCborEnvelope =
                codec::from_cbor_bytes(&bytes[1..])?;
            let verification_key_for_concatenation =
                VerificationKeyForConcatenation::from_bytes(&envelope.verification_key_bytes)?;

            #[cfg(feature = "future_snark")]
            let verification_key_for_snark = envelope
                .snark_verification_key_bytes
                .map(|b| VerificationKeyForSnark::from_bytes(&b))
                .transpose()?;

            #[cfg(feature = "future_snark")]
            let lottery_target_value = envelope
                .lottery_target_value_bytes
                .map(|b| LotteryTargetValue::from_bytes(&b))
                .transpose()?;

            Ok(ClosedRegistrationEntry {
                verification_key_for_concatenation,
                stake: envelope.stake,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark,
                #[cfg(feature = "future_snark")]
                lottery_target_value,
            })
        } else {
            Self::from_bytes_legacy(bytes)
        }
    }

    /// Creates a registration entry from legacy byte-packed format.
    /// Expects 96 bytes for the verification key for concatenation and 8 bytes for the stake
    /// (u64 big-endian).
    /// #[cfg(feature = "future_snark")] Expects 64 bytes for the verification key for snark and 32
    /// bytes for the lottery target value.
    /// The order is backward compatible with previous implementations.
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        let verification_key_for_concatenation = VerificationKeyForConcatenation::from_bytes(
            bytes.get(..96).ok_or(RegisterError::SerializationError)?,
        )?;
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(96..104).ok_or(RegisterError::SerializationError)?);
        let stake = Stake::from_be_bytes(u64_bytes);

        #[cfg(feature = "future_snark")]
        let (verification_key_for_snark, lottery_target_value) = {
            let schnorr_verification_key = bytes
                .get(104..168)
                .map(VerificationKeyForSnark::from_bytes)
                .transpose()?;

            let lottery_target_value =
                bytes.get(168..200).map(LotteryTargetValue::from_bytes).transpose()?;

            match (schnorr_verification_key, lottery_target_value) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(RegisterError::SerializationError.into());
                }
                _ => {}
            }
            (schnorr_verification_key, lottery_target_value)
        };

        Ok(ClosedRegistrationEntry {
            verification_key_for_concatenation,
            stake,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark,
            #[cfg(feature = "future_snark")]
            lottery_target_value,
        })
    }
}

impl Serialize for ClosedRegistrationEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[cfg(not(feature = "future_snark"))]
        {
            let mut tuple = serializer.serialize_tuple(2)?;
            tuple.serialize_element(&self.verification_key_for_concatenation)?;
            tuple.serialize_element(&self.stake)?;
            tuple.end()
        }
        #[cfg(feature = "future_snark")]
        {
            let has_snark_fields = self.verification_key_for_snark.is_some()
                && self.lottery_target_value.is_some()
                && cfg!(feature = "future_snark");
            let tuples_number = if has_snark_fields { 4 } else { 2 };
            let mut tuple = serializer.serialize_tuple(tuples_number)?;
            tuple.serialize_element(&self.verification_key_for_concatenation)?;
            tuple.serialize_element(&self.stake)?;
            if has_snark_fields {
                tuple.serialize_element(&self.verification_key_for_snark)?;
                tuple.serialize_element(&self.lottery_target_value)?;
            }
            tuple.end()
        }
    }
}

/// Converts a `RegistrationEntry` into a `ClosedRegistrationEntry`.
///
/// Extracts the concatenation verification key and stake from the entry. When the `future_snark`
/// feature is enabled and a SNARK verification key is present, the lottery target value is also
/// computed from `phi_f`, the entry's stake, and `total_stake` via `compute_target_value_for_snark_lottery`.
impl TryFrom<(RegistrationEntry, Stake, PhiFValue)> for ClosedRegistrationEntry {
    type Error = anyhow::Error;
    fn try_from(entry_total_stake: (RegistrationEntry, Stake, PhiFValue)) -> StmResult<Self> {
        #[cfg(not(feature = "future_snark"))]
        let (entry, _total_stake, _phi_f) = entry_total_stake;
        #[cfg(feature = "future_snark")]
        let (entry, total_stake, phi_f) = entry_total_stake;
        #[cfg(feature = "future_snark")]
        let (schnorr_verification_key, target_value) = {
            let vk = entry.get_verification_key_for_snark();
            let target = vk
                .is_some()
                .then(|| {
                    compute_target_value_for_snark_lottery(phi_f, entry.get_stake(), total_stake)
                })
                .transpose()?;

            (vk, target)
        };

        Ok(ClosedRegistrationEntry::new(
            entry.get_verification_key_for_concatenation(),
            entry.get_stake(),
            #[cfg(feature = "future_snark")]
            schnorr_verification_key,
            #[cfg(feature = "future_snark")]
            target_value,
        ))
    }
}

impl Hash for ClosedRegistrationEntry {
    /// Hashes the registration entry by hashing the stake first, then the verification key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stake.hash(state);
        self.verification_key_for_concatenation.hash(state);
        #[cfg(feature = "future_snark")]
        {
            self.verification_key_for_snark.hash(state);
            self.lottery_target_value.hash(state);
        }
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

impl PartialOrd for ClosedRegistrationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for ClosedRegistrationEntry {
    /// Orders by stake first, then by Verification key for concatenation.
    ///
    /// Note: this ordering intentionally excludes the snark fields
    /// (`VerificationKeyForSnark`, `LotteryTargetValue`), as we do not need them for ordering
    /// the Merkle tree leaves.
    fn cmp(&self, other: &Self) -> Ordering {
        self.stake.cmp(&other.stake).then(
            self.verification_key_for_concatenation
                .cmp(&other.verification_key_for_concatenation),
        )
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

    fn create_closed_registration_entry(
        rng: &mut ChaCha20Rng,
        stake: Stake,
    ) -> ClosedRegistrationEntry {
        let bls_sk = BlsSigningKey::generate(rng);
        let bls_pk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);

        #[cfg(feature = "future_snark")]
        let schnorr_verification_key = {
            let sk = SchnorrSigningKey::generate(rng);
            VerificationKeyForSnark::new_from_signing_key(sk.clone())
        };
        ClosedRegistrationEntry::new(
            bls_pk.vk,
            stake,
            #[cfg(feature = "future_snark")]
            Some(schnorr_verification_key),
            #[cfg(feature = "future_snark")]
            Some(LotteryTargetValue::get_one()),
        )
    }

    #[test]
    fn test_ord_different_stakes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let entry_low_stake = create_closed_registration_entry(&mut rng, 100);
        let entry_high_stake = create_closed_registration_entry(&mut rng, 200);

        assert_eq!(entry_low_stake.cmp(&entry_high_stake), Ordering::Less);
        assert_eq!(entry_high_stake.cmp(&entry_low_stake), Ordering::Greater);
    }

    #[test]
    fn test_ord_same_stake_different_keys() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let entry1 = create_closed_registration_entry(&mut rng, 100);
        let entry2 = create_closed_registration_entry(&mut rng, 100);

        let cmp_result = entry1.cmp(&entry2);
        assert!(cmp_result == Ordering::Less || cmp_result == Ordering::Greater);

        assert_eq!(entry2.cmp(&entry1), cmp_result.reverse());
    }

    mod golden {
        use super::*;

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_BYTES: &[u8; 104] = &[
            143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126, 186, 135,
            228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89, 187, 88, 29, 135, 173,
            244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4,
            246, 138, 48, 180, 133, 90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153,
            90, 208, 192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16,
            224, 194, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        #[cfg(feature = "future_snark")]
        const GOLDEN_BYTES: &[u8; 200] = &[
            143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126, 186, 135,
            228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89, 187, 88, 29, 135, 173,
            244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4,
            246, 138, 48, 180, 133, 90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153,
            90, 208, 192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16,
            224, 194, 0, 0, 0, 0, 0, 0, 0, 1, 200, 194, 6, 212, 77, 254, 23, 111, 33, 34, 139, 71,
            131, 196, 108, 13, 217, 75, 187, 131, 158, 77, 197, 163, 30, 123, 151, 237, 157, 232,
            167, 10, 45, 121, 194, 155, 110, 46, 240, 74, 141, 138, 78, 228, 92, 179, 58, 63, 233,
            239, 84, 114, 149, 77, 188, 93, 8, 22, 11, 12, 45, 186, 211, 56, 1, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        fn golden_value() -> ClosedRegistrationEntry {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let bls_sk = BlsSigningKey::generate(&mut rng);
            let bls_pk = VerificationKeyProofOfPossessionForConcatenation::from(&bls_sk);

            #[cfg(feature = "future_snark")]
            let schnorr_verification_key = {
                let sk = SchnorrSigningKey::generate(&mut rng);
                VerificationKeyForSnark::new_from_signing_key(sk.clone())
            };
            ClosedRegistrationEntry::new(
                bls_pk.vk,
                1,
                #[cfg(feature = "future_snark")]
                Some(schnorr_verification_key),
                #[cfg(feature = "future_snark")]
                Some(LotteryTargetValue::get_one()),
            )
        }

        #[test]
        fn golden_conversions() {
            let value = ClosedRegistrationEntry::from_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = ClosedRegistrationEntry::to_bytes(&value)
                .expect("ClosedRegistrationEntry serialization should not fail");
            let golden_serialized = ClosedRegistrationEntry::to_bytes(&golden_value())
                .expect("ClosedRegistrationEntry serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }

        #[cfg(not(feature = "future_snark"))]
        const GOLDEN_CBOR_BYTES: &[u8; 219] = &[
            1, 162, 118, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 95, 107, 101,
            121, 95, 98, 121, 116, 101, 115, 152, 96, 24, 143, 24, 161, 24, 255, 24, 48, 24, 78,
            24, 57, 24, 204, 24, 220, 24, 25, 24, 221, 24, 164, 24, 252, 24, 248, 14, 24, 56, 24,
            126, 24, 186, 24, 135, 24, 228, 24, 188, 24, 145, 24, 181, 24, 52, 24, 200, 24, 97, 24,
            99, 24, 213, 24, 46, 0, 24, 199, 24, 193, 24, 89, 24, 187, 24, 88, 24, 29, 24, 135, 24,
            173, 24, 244, 24, 86, 24, 36, 24, 83, 24, 54, 24, 67, 24, 164, 6, 24, 137, 24, 94, 24,
            72, 6, 24, 105, 24, 128, 24, 128, 24, 93, 24, 48, 24, 176, 11, 4, 24, 246, 24, 138, 24,
            48, 24, 180, 24, 133, 24, 90, 24, 142, 24, 192, 24, 24, 24, 193, 24, 111, 24, 142, 24,
            31, 24, 76, 24, 111, 24, 110, 24, 234, 24, 153, 24, 90, 24, 208, 24, 192, 24, 31, 24,
            124, 24, 95, 24, 102, 24, 49, 24, 158, 24, 99, 24, 52, 24, 220, 24, 165, 24, 94, 24,
            251, 24, 68, 24, 69, 24, 121, 16, 24, 224, 24, 194, 101, 115, 116, 97, 107, 101, 1,
        ];

        #[cfg(feature = "future_snark")]
        const GOLDEN_CBOR_BYTES: &[u8; 433] = &[
            1, 164, 118, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 95, 107, 101,
            121, 95, 98, 121, 116, 101, 115, 152, 96, 24, 143, 24, 161, 24, 255, 24, 48, 24, 78,
            24, 57, 24, 204, 24, 220, 24, 25, 24, 221, 24, 164, 24, 252, 24, 248, 14, 24, 56, 24,
            126, 24, 186, 24, 135, 24, 228, 24, 188, 24, 145, 24, 181, 24, 52, 24, 200, 24, 97, 24,
            99, 24, 213, 24, 46, 0, 24, 199, 24, 193, 24, 89, 24, 187, 24, 88, 24, 29, 24, 135, 24,
            173, 24, 244, 24, 86, 24, 36, 24, 83, 24, 54, 24, 67, 24, 164, 6, 24, 137, 24, 94, 24,
            72, 6, 24, 105, 24, 128, 24, 128, 24, 93, 24, 48, 24, 176, 11, 4, 24, 246, 24, 138, 24,
            48, 24, 180, 24, 133, 24, 90, 24, 142, 24, 192, 24, 24, 24, 193, 24, 111, 24, 142, 24,
            31, 24, 76, 24, 111, 24, 110, 24, 234, 24, 153, 24, 90, 24, 208, 24, 192, 24, 31, 24,
            124, 24, 95, 24, 102, 24, 49, 24, 158, 24, 99, 24, 52, 24, 220, 24, 165, 24, 94, 24,
            251, 24, 68, 24, 69, 24, 121, 16, 24, 224, 24, 194, 101, 115, 116, 97, 107, 101, 1,
            120, 28, 115, 110, 97, 114, 107, 95, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105,
            111, 110, 95, 107, 101, 121, 95, 98, 121, 116, 101, 115, 152, 64, 24, 200, 24, 194, 6,
            24, 212, 24, 77, 24, 254, 23, 24, 111, 24, 33, 24, 34, 24, 139, 24, 71, 24, 131, 24,
            196, 24, 108, 13, 24, 217, 24, 75, 24, 187, 24, 131, 24, 158, 24, 77, 24, 197, 24, 163,
            24, 30, 24, 123, 24, 151, 24, 237, 24, 157, 24, 232, 24, 167, 10, 24, 45, 24, 121, 24,
            194, 24, 155, 24, 110, 24, 46, 24, 240, 24, 74, 24, 141, 24, 138, 24, 78, 24, 228, 24,
            92, 24, 179, 24, 58, 24, 63, 24, 233, 24, 239, 24, 84, 24, 114, 24, 149, 24, 77, 24,
            188, 24, 93, 8, 22, 11, 12, 24, 45, 24, 186, 24, 211, 24, 56, 120, 26, 108, 111, 116,
            116, 101, 114, 121, 95, 116, 97, 114, 103, 101, 116, 95, 118, 97, 108, 117, 101, 95,
            98, 121, 116, 101, 115, 152, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = ClosedRegistrationEntry::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = ClosedRegistrationEntry::to_bytes(&golden_value())
                .expect("ClosedRegistrationEntry serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }

    mod envelope_compatibility {
        use super::*;
        use crate::codec;

        #[test]
        fn forward_compatible_with_extra_fields() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);

            #[derive(serde::Serialize)]
            struct EvolvedEnvelope {
                verification_key_bytes: Vec<u8>,
                stake: Stake,
                new_field: String,
            }

            let evolved = EvolvedEnvelope {
                verification_key_bytes: entry
                    .get_verification_key_for_concatenation()
                    .to_bytes()
                    .to_vec(),
                stake: 42,
                new_field: "extra".to_string(),
            };
            let evolved_bytes =
                codec::to_cbor_bytes(&evolved).expect("evolved serialization should not fail");

            let decoded = ClosedRegistrationEntry::from_bytes(&evolved_bytes)
                .expect("decoding with extra field should succeed");
            assert_eq!(entry.get_stake(), decoded.get_stake());
            assert_eq!(
                entry.get_verification_key_for_concatenation(),
                decoded.get_verification_key_for_concatenation()
            );
        }

        #[test]
        fn backward_compatible_with_missing_optional_fields() {
            #[derive(serde::Serialize)]
            struct MinimalEnvelope {
                verification_key_bytes: Vec<u8>,
                stake: Stake,
            }

            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);

            let minimal = MinimalEnvelope {
                verification_key_bytes: entry
                    .get_verification_key_for_concatenation()
                    .to_bytes()
                    .to_vec(),
                stake: 42,
            };
            let minimal_bytes =
                codec::to_cbor_bytes(&minimal).expect("minimal serialization should not fail");

            let decoded = ClosedRegistrationEntry::from_bytes(&minimal_bytes)
                .expect("decoding with missing optional fields should succeed");
            assert_eq!(42, decoded.get_stake());
            assert_eq!(
                entry.get_verification_key_for_concatenation(),
                decoded.get_verification_key_for_concatenation()
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod without_snark_fields {
        use super::*;

        #[test]
        fn preserves_concatenation_key_and_stake() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);

            let stripped = entry.without_snark_fields();

            assert_eq!(
                entry.get_verification_key_for_concatenation(),
                stripped.get_verification_key_for_concatenation()
            );
            assert_eq!(entry.get_stake(), stripped.get_stake());
        }

        #[test]
        fn clears_snark_fields() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);
            assert!(entry.get_verification_key_for_snark().is_some());
            assert!(entry.get_lottery_target_value().is_some());

            let stripped = entry.without_snark_fields();

            assert!(stripped.get_verification_key_for_snark().is_none());
            assert!(stripped.get_lottery_target_value().is_none());
        }

        #[test]
        fn serializes_as_two_element_json_tuple() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);

            let stripped = entry.without_snark_fields();
            let json: serde_json::Value =
                serde_json::to_value(stripped).expect("JSON serialization should not fail");

            let array = json.as_array().expect("should serialize as a JSON array");
            assert_eq!(
                2,
                array.len(),
                "stripped entry should serialize as a 2-element tuple"
            );
        }

        #[test]
        fn entry_with_snark_fields_serializes_as_four_element_json_tuple() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let entry = create_closed_registration_entry(&mut rng, 42);

            let json: serde_json::Value =
                serde_json::to_value(entry).expect("JSON serialization should not fail");

            let array = json.as_array().expect("should serialize as a JSON array");
            assert_eq!(
                4,
                array.len(),
                "full entry should serialize as a 4-element tuple"
            );
        }
    }
}
