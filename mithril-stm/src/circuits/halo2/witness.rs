//! Circuit witness and instance boundary types for the Halo2 STM circuit.
//!
//! This module defines the exact public/private shapes consumed by the relation, while
//! keeping them separate from lower-level circuit primitives in `types.rs`.
//! Integrators should treat these types as the circuit-facing contract.

use crate::LotteryIndex;
use crate::signature_scheme::{
    PrimeOrderProjectivePoint, SchnorrVerificationKey, UniqueSchnorrSignature,
};

use super::types::CircuitBaseField;

pub use crate::circuits::common::merkle::MerklePath;

/// Lottery target value used by the circuit for signer eligibility checks.
pub type LotteryTargetValue = CircuitBaseField;
/// Signed message value used by the circuit transcript, without any domain prefix.
pub type SignedMessageWithoutPrefix = CircuitBaseField;
/// Merkle tree commitment of the STM membership tree, carried as a circuit public input.
pub type MerkleTreeCommitment = CircuitBaseField;
/// Circuit statement/instance type, representing the public inputs to the STM SNARK circuit.
pub(crate) type CircuitInstance = (MerkleTreeCommitment, SignedMessageWithoutPrefix);

/// Merkle-tree leaf material used by Halo2 witness construction.
///
/// The first field stores the signer's verification key, and the second
/// field stores the lottery target value associated with that signer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CircuitMerkleTreeLeaf(pub SchnorrVerificationKey, pub LotteryTargetValue);

impl CircuitMerkleTreeLeaf {
    /// Returns the signer's verification key stored in this witness leaf.
    pub fn verification_key(&self) -> SchnorrVerificationKey {
        self.0
    }

    /// Returns the curve point backing the signer's verification key.
    pub fn verification_key_point(&self) -> PrimeOrderProjectivePoint {
        self.0.0
    }

    /// Returns the lottery target value associated with this witness leaf.
    pub fn lottery_target_value(&self) -> LotteryTargetValue {
        self.1
    }
}

/// Single circuit witness entry consumed by the Halo2 relation.
#[derive(Clone, Debug)]
pub struct CircuitWitnessEntry {
    /// Merkle leaf material committed for the current signer.
    pub(crate) leaf: CircuitMerkleTreeLeaf,
    /// Merkle authentication path opening `leaf` to the public Merkle tree commitment.
    pub(crate) merkle_path: MerklePath,
    /// Unique Schnorr signature carried by this witness entry.
    pub(crate) unique_schnorr_signature: UniqueSchnorrSignature,
    /// Lottery slot index claimed by this witness entry.
    pub(crate) lottery_index: LotteryIndex,
}

/// Full circuit witness consumed by the Halo2 relation.
pub(crate) type CircuitWitness = Vec<CircuitWitnessEntry>;
