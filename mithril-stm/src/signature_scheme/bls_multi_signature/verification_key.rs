use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    iter::Sum,
};

use anyhow::anyhow;
use blst::{
    BLST_ERROR,
    min_sig::{AggregatePublicKey, PublicKey as BlstVk},
};
use serde::{Deserialize, Serialize};

use crate::StmResult;

use super::{
    BlsProofOfPossession, BlsSignatureError, BlsSigningKey, POP, blst_error_to_stm_error,
    helper::unsafe_helpers::verify_pairing,
};

/// MultiSig verification key, which is a wrapper over the BlstVk (element in G2)
/// from the blst library.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlsVerificationKey(pub BlstVk);

impl BlsVerificationKey {
    /// Convert a `VerificationKey` to its raw compressed byte representation.
    ///
    /// This exact byte layout is depended on by the KES sign/verify preimage and the
    /// Merkle-tree leaf hash preimage (`MerkleTreeConcatenationLeaf`) — it must not change.
    pub fn to_raw_bytes(self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Convert a compressed byte string into a `VerificationKey`.
    ///
    /// # Error
    /// This function fails if the bytes do not represent a compressed point of the prime
    /// order subgroup of the curve Bls12-381.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        let bytes = bytes.get(..96).ok_or(BlsSignatureError::SerializationError)?;
        match BlstVk::key_validate(bytes) {
            Ok(vk) => Ok(Self(vk)),
            Err(e) => Err(blst_error_to_stm_error(e, None, None)
                .expect_err("If deserialization is not successful, blst returns and error different to SUCCESS."))
        }
    }

    /// Compare two `VerificationKey`. Used for PartialOrd impl, used to order signatures. The comparison
    /// function can be anything, as long as it is consistent.
    fn compare_verification_keys(&self, other: &BlsVerificationKey) -> Ordering {
        let self_bytes = self.to_raw_bytes();
        let other_bytes = other.to_raw_bytes();
        let mut result = Ordering::Equal;

        for (i, j) in self_bytes.iter().zip(other_bytes.iter()) {
            result = i.cmp(j);
            if result != Ordering::Equal {
                return result;
            }
        }

        result
    }

    pub(crate) fn to_blst_verification_key(self) -> BlstVk {
        self.0
    }
}

impl Display for BlsVerificationKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_raw_bytes())
    }
}

impl Hash for BlsVerificationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash_slice(&self.to_raw_bytes(), state)
    }
}

impl PartialEq for BlsVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for BlsVerificationKey {}

impl PartialOrd for BlsVerificationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for BlsVerificationKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_verification_keys(other)
    }
}

impl<'a> Sum<&'a Self> for BlsVerificationKey {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let keys: Vec<&BlstVk> = iter.map(|x| &x.0).collect();

        assert!(!keys.is_empty(), "One cannot add an empty vector");
        let aggregate_key = AggregatePublicKey::aggregate(&keys, false)
            .expect("An MspMvk is always a valid key. This function only fails if keys is empty or if the keys are invalid, none of which can happen.")
            .to_public_key();

        Self(aggregate_key)
    }
}

impl From<&BlsSigningKey> for BlsVerificationKey {
    /// Convert a secret key into an `MspMvk`. This is performed by computing
    /// `MspMvk = g2 * sk`, where `g2` is the generator in G2. We can use the
    /// blst built-in function `sk_to_pk`.
    fn from(sk: &BlsSigningKey) -> Self {
        BlsVerificationKey(sk.to_blst_secret_key().sk_to_pk())
    }
}

/// MultiSig public key, contains the verification key and the proof of possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsVerificationKeyProofOfPossession {
    /// The verification key.
    pub vk: BlsVerificationKey,
    /// Proof of Possession.
    pub pop: BlsProofOfPossession,
}

impl BlsVerificationKeyProofOfPossession {
    /// if `e(k1,g2) = e(H_G1("PoP" || mvk),mvk)` and `e(g1,mvk) = e(k2,g2)`
    /// are both true, return 1. The first part is a signature verification
    /// of message "PoP", while the second we need to compute the pairing
    /// manually.
    // If we are really looking for performance improvements, we can combine the
    // two final exponentiations (for verifying k1 and k2) into a single one.
    pub(crate) fn verify_proof_of_possession(&self) -> StmResult<()> {
        match self.vk.to_blst_verification_key().validate() {
            Ok(_) => {
                let result = verify_pairing(&self.vk, &self.pop);
                if !(self.pop.get_k1().verify(
                    false,
                    POP,
                    &[],
                    &[],
                    &self.vk.to_blst_verification_key(),
                    false,
                ) == BLST_ERROR::BLST_SUCCESS
                    && result)
                {
                    return Err(anyhow!(BlsSignatureError::KeyInvalid(Box::new(*self))));
                }
                Ok(())
            }
            Err(e) => blst_error_to_stm_error(e, None, Some(self.vk)),
        }
    }

    /// Convert to its 192 byte raw representation.
    ///
    /// # Layout
    /// The layout of a `PublicKeyPoP` encoding is
    /// * Public key
    /// * Proof of Possession
    ///
    /// This exact byte layout is depended on by the KES sign/verify preimage and
    /// `Initializer`'s legacy decoder — it must not change.
    pub fn to_raw_bytes(self) -> [u8; 192] {
        let mut vkpop_bytes = [0u8; 192];
        vkpop_bytes[..96].copy_from_slice(&self.vk.to_raw_bytes());
        vkpop_bytes[96..].copy_from_slice(&self.pop.to_raw_bytes());
        vkpop_bytes
    }

    /// Deserialize a byte string to a `BlsVerificationKeyProofOfPossession`.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mvk = BlsVerificationKey::from_raw_bytes(
            bytes.get(..96).ok_or(BlsSignatureError::SerializationError)?,
        )?;

        let pop = BlsProofOfPossession::from_raw_bytes(
            bytes.get(96..).ok_or(BlsSignatureError::SerializationError)?,
        )?;

        Ok(Self { vk: mvk, pop })
    }
}

impl From<&BlsSigningKey> for BlsVerificationKeyProofOfPossession {
    /// Convert a secret key into a `BlsVerificationKeyProofOfPossession` by simply converting to a
    /// `MspMvk` and `MspPoP`.
    fn from(sk: &BlsSigningKey) -> Self {
        Self {
            vk: sk.into(),
            pop: sk.into(),
        }
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
                "vk": [143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126, 186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89, 187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133, 90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208, 192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16, 224, 194],
                "pop": [168, 50, 233, 193, 15, 136, 65, 72, 123, 148, 129, 176, 38, 198, 209, 47, 28, 204, 176, 144, 57, 251, 42, 28, 66, 76, 89, 97, 158, 63, 54, 198, 194, 176, 135, 221, 14, 185, 197, 225, 202, 98, 243, 74, 233, 225, 143, 151, 147, 177, 170, 117, 66, 165, 66, 62, 33, 216, 232, 75, 68, 114, 195, 22, 100, 65, 44, 198, 4, 166, 102, 233, 253, 240, 59, 175, 60, 117, 142, 114, 140, 122, 17, 87, 110, 187, 1, 17, 10, 195, 154, 13, 249, 86, 54, 226]
            }
        "#;

        fn golden_value() -> BlsVerificationKeyProofOfPossession {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = BlsSigningKey::generate(&mut rng);
            BlsVerificationKeyProofOfPossession {
                vk: BlsVerificationKey::from(&sk),
                pop: BlsProofOfPossession::from(&sk),
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
}
