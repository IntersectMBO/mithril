use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

#[cfg(feature = "future_snark")]
use crate::{LotteryTargetValue, VerificationKeyForSnark};

use crate::{Stake, VerificationKeyForConcatenation};

// Needed by MerkleTreeConcatenationLeaf::from_hash_bytes (test-only) and MerkleTreeSnarkLeaf's
// own byte codec (not yet gated to test — see that type's rename commit).
#[cfg(feature = "future_snark")]
use crate::StmResult;

#[cfg(feature = "future_snark")]
use super::MerkleTreeError;

/// Trait implemented to be used as a Merkle tree leaf.
pub trait MerkleTreeLeaf: Clone + Send + Sync + Copy {
    /// Converts the Merkle tree leaf to a bytes representation used internally by the Merkle tree
    fn as_bytes_for_merkle_tree(&self) -> Vec<u8>;
}

/// The values that are committed in the Merkle Tree for `ConcatenationProof`.
/// Namely, a verified `BlsVerificationKey` and its corresponding stake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct MerkleTreeConcatenationLeaf(pub VerificationKeyForConcatenation, pub Stake);

impl MerkleTreeLeaf for MerkleTreeConcatenationLeaf {
    fn as_bytes_for_merkle_tree(&self) -> Vec<u8> {
        self.to_hash_bytes()
    }
}

impl MerkleTreeConcatenationLeaf {
    /// Byte layout hashed into the Merkle tree via `as_bytes_for_merkle_tree`. Consensus-critical:
    /// changing this changes every previously-computed Merkle root.
    fn to_hash_bytes(self) -> Vec<u8> {
        let mut result = [0u8; 104];
        result[..96].copy_from_slice(&self.0.to_bytes());
        result[96..].copy_from_slice(&self.1.to_be_bytes());
        result.to_vec()
    }

    /// Decodes a leaf from its hash-preimage bytes. Only ever used by this type's own
    /// round-trip tests today — nothing decodes a leaf back from bytes in production.
    #[cfg(all(test, feature = "future_snark"))]
    pub(crate) fn from_hash_bytes(bytes: &[u8]) -> StmResult<Self> {
        let pk = VerificationKeyForConcatenation::from_bytes(bytes)
            .map_err(|_| MerkleTreeError::SerializationError)?;
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&bytes[96..]);
        let stake = Stake::from_be_bytes(u64_bytes);
        Ok(MerkleTreeConcatenationLeaf(pk, stake))
    }
}

impl From<MerkleTreeConcatenationLeaf> for (VerificationKeyForConcatenation, Stake) {
    fn from(leaf: MerkleTreeConcatenationLeaf) -> (VerificationKeyForConcatenation, Stake) {
        (leaf.0, leaf.1)
    }
}

impl PartialOrd for MerkleTreeConcatenationLeaf {
    /// Ordering of MT Values.
    ///
    /// First we order by stake, then by key. By having this ordering,
    /// we have the players with higher stake close together,
    /// meaning that the probability of having several signatures in the same side of the tree, is higher.
    /// This allows us to produce a more efficient batch opening of the merkle tree.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for MerkleTreeConcatenationLeaf {
    fn cmp(&self, other: &Self) -> Ordering {
        self.1.cmp(&other.1).then(self.0.cmp(&other.0))
    }
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
/// The values that are committed in the Merkle Tree for `SnarkProof`.
/// Namely, a verified `SchnorrVerificationKey` and its corresponding target value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct MerkleTreeSnarkLeaf(pub VerificationKeyForSnark, pub LotteryTargetValue);

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl MerkleTreeLeaf for MerkleTreeSnarkLeaf {
    fn as_bytes_for_merkle_tree(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl MerkleTreeSnarkLeaf {
    fn to_bytes(self) -> Vec<u8> {
        let mut result = [0u8; 96];
        result[..64].copy_from_slice(&self.0.to_raw_bytes());
        result[64..].copy_from_slice(&self.1.to_bytes());
        result.to_vec()
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if bytes.len() < 96 {
            return Err(MerkleTreeError::SerializationError.into());
        }
        let pk = VerificationKeyForSnark::from_raw_bytes(&bytes[..64])
            .map_err(|_| MerkleTreeError::SerializationError)?;
        let mut target_value_bytes = [0u8; 32];
        target_value_bytes.copy_from_slice(&bytes[64..]);
        let target_value = LotteryTargetValue::from_bytes(&target_value_bytes)
            .map_err(|_| MerkleTreeError::SerializationError)?;
        Ok(MerkleTreeSnarkLeaf(pk, target_value))
    }
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl From<MerkleTreeSnarkLeaf> for (VerificationKeyForSnark, LotteryTargetValue) {
    fn from(leaf: MerkleTreeSnarkLeaf) -> (VerificationKeyForSnark, LotteryTargetValue) {
        (leaf.0, leaf.1)
    }
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl PartialOrd for MerkleTreeSnarkLeaf {
    /// Ordering of MT Values.
    ///
    /// First we order by target value, then by key. By having this ordering,
    /// we have the players with higher target value close together.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl Ord for MerkleTreeSnarkLeaf {
    fn cmp(&self, other: &Self) -> Ordering {
        self.1.cmp(&other.1).then(self.0.cmp(&other.0))
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::signature_scheme::BlsSigningKey;

    use super::*;

    mod concatenation {
        use super::*;

        #[cfg(feature = "future_snark")]
        mod golden {
            use super::*;
            const GOLDEN_BYTES: &[u8; 104] = &[
                143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126, 186, 135,
                228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89, 187, 88, 29, 135,
                173, 244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6, 105, 128, 128, 93, 48, 176,
                11, 4, 246, 138, 48, 180, 133, 90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110,
                234, 153, 90, 208, 192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68,
                69, 121, 16, 224, 194, 0, 0, 0, 0, 0, 0, 0, 1,
            ];

            fn golden_value() -> MerkleTreeConcatenationLeaf {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                let sk = BlsSigningKey::generate(&mut rng);
                let pk = VerificationKeyForConcatenation::from(&sk);
                let stake = 1u64;
                MerkleTreeConcatenationLeaf(pk, stake)
            }

            #[test]
            fn golden_conversions() {
                let value = MerkleTreeConcatenationLeaf::from_hash_bytes(GOLDEN_BYTES)
                    .expect("This from bytes should not fail");
                assert_eq!(golden_value(), value);

                let serialized = MerkleTreeConcatenationLeaf::to_hash_bytes(value);
                let golden_serialized = MerkleTreeConcatenationLeaf::to_hash_bytes(golden_value());
                assert_eq!(golden_serialized, serialized);
            }
        }

        mod golden_json {
            use super::*;
            const GOLDEN_JSON: &str = r#"
        [
            [143,161,255,48,78,57,204,220,25,221,164,252,248,14,56,126,186,135,228,188,145,
            181,52,200,97,99,213,46,0,199,193,89,187,88,29,135,173,244,86,36,83,54,67,164,
            6,137,94,72,6,105,128,128,93,48,176,11,4,246,138,48,180,133,90,142,192,24,193,
            111,142,31,76,111,110,234,153,90,208,192,31,124,95,102,49,158,99,52,220,165,94,
            251,68,69,121,16,224,194],
            1
        ]"#;

            fn golden_value() -> MerkleTreeConcatenationLeaf {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                let sk = BlsSigningKey::generate(&mut rng);
                let pk = VerificationKeyForConcatenation::from(&sk);
                let stake = 1u64;
                MerkleTreeConcatenationLeaf(pk, stake)
            }

            #[test]
            fn golden_conversions() {
                let value: MerkleTreeConcatenationLeaf = serde_json::from_str(GOLDEN_JSON)
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

    #[cfg(feature = "future_snark")]
    mod snark {
        use midnight_curves::Fq as JubjubBase;

        use crate::{SchnorrSigningKey, signature_scheme::BaseFieldElement};

        use super::*;

        mod golden {

            use super::*;

            const GOLDEN_BYTES: &[u8; 96] = &[
                186, 22, 69, 162, 1, 67, 125, 160, 104, 197, 105, 109, 200, 34, 186, 196, 171, 155,
                191, 178, 11, 116, 108, 8, 111, 249, 47, 39, 137, 55, 62, 62, 144, 52, 95, 161,
                127, 253, 49, 32, 140, 217, 231, 207, 32, 238, 244, 196, 97, 241, 47, 95, 101, 9,
                70, 136, 194, 66, 187, 253, 200, 32, 218, 43, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];

            fn golden_value() -> MerkleTreeSnarkLeaf {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                let sk = SchnorrSigningKey::generate(&mut rng);
                let pk = VerificationKeyForSnark::new_from_signing_key(sk);
                let stake = BaseFieldElement(JubjubBase::from(1u64));
                MerkleTreeSnarkLeaf(pk, stake)
            }

            #[test]
            fn golden_conversions() {
                let value = MerkleTreeSnarkLeaf::from_bytes(GOLDEN_BYTES)
                    .expect("This from bytes should not fail");
                assert_eq!(golden_value(), value);

                let serialized = MerkleTreeSnarkLeaf::to_bytes(value);
                let golden_serialized = MerkleTreeSnarkLeaf::to_bytes(golden_value());
                assert_eq!(golden_serialized, serialized);
            }
        }

        mod golden_json {
            use super::*;
            const GOLDEN_JSON: &str = r#"
        [
            [144,52,95,161,127,253,49,32,140,217,231,207,32,238,244,196,97,241,47,95,101,9,
            70,136,194,66,187,253,200,32,218,43],
            [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        ]"#;

            fn golden_value() -> MerkleTreeSnarkLeaf {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                let sk = SchnorrSigningKey::generate(&mut rng);
                let pk = VerificationKeyForSnark::new_from_signing_key(sk);
                let stake = BaseFieldElement(JubjubBase::from(1u64));
                MerkleTreeSnarkLeaf(pk, stake)
            }

            #[test]
            fn golden_conversions() {
                println!("{:?}", serde_json::to_string(&golden_value()));
                let value: MerkleTreeSnarkLeaf = serde_json::from_str(GOLDEN_JSON)
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
}
