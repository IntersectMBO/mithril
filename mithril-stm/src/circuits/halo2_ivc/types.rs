//! Circuit boundary types for the Halo2 IVC circuit.
//!
//! This module gives domain names to values that are represented as raw field
//! elements or bytes at lower circuit/gadget boundaries.

use ff::Field;
use serde::{Deserialize, Serialize};

use super::{
    NativeField, PREIMAGE_CURRENT_EPOCH_BYTES, PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
    PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES, PREIMAGE_SIZE, Value,
};
use crate::BaseFieldElement;

/// Circuit-boundary alias for Midnight proofs' `Value<T>` witness wrapper.
pub(crate) type CircuitValue<T> = Value<T>;

macro_rules! field_wrapper {
    ($name:ident, zero) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub(crate) struct $name(NativeField);

        impl $name {
            pub(crate) const ZERO: Self = Self(NativeField::ZERO);

            pub(crate) fn from_field(value: NativeField) -> Self {
                Self(value)
            }

            pub(crate) fn as_field(self) -> NativeField {
                self.0
            }
        }
    };
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name(NativeField);

        impl $name {
            pub(crate) fn from_field(value: NativeField) -> Self {
                Self(value)
            }

            pub(crate) fn as_field(self) -> NativeField {
                self.0
            }
        }
    };
}

field_wrapper!(MessageHash, zero);
field_wrapper!(MerkleTreeCommitment, zero);
field_wrapper!(ProtocolParametersHash, zero);
field_wrapper!(CertificateCircuitVerificationKeyRepresentation);
field_wrapper!(IvcCircuitVerificationKeyRepresentation);

macro_rules! u64_wrapper {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub(crate) struct $name(u64);

        impl $name {
            pub(crate) const ZERO: Self = Self::new(0);

            pub(crate) const fn new(value: u64) -> Self {
                Self(value)
            }

            pub(crate) fn as_u64(self) -> u64 {
                self.0
            }

            pub(crate) fn as_field(self) -> NativeField {
                NativeField::from(self.0)
            }

            #[cfg(any(test, feature = "benchmark-internals"))]
            pub(crate) fn from_field(value: NativeField) -> Self {
                let bytes = value.to_bytes_le();
                let low_bytes = bytes[0..8]
                    .try_into()
                    .expect("field byte representation should contain at least 8 bytes");
                Self(u64::from_le_bytes(low_bytes))
            }
        }
    };
}

u64_wrapper!(EpochNumber);
u64_wrapper!(StepCounter);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtocolMessagePreimage(pub(crate) [u8; PREIMAGE_SIZE]);

impl ProtocolMessagePreimage {
    #[cfg(test)]
    pub(crate) fn new(bytes: [u8; PREIMAGE_SIZE]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; PREIMAGE_SIZE] {
        &mut self.0
    }

    pub(crate) fn into_inner(self) -> [u8; PREIMAGE_SIZE] {
        self.0
    }

    /// Decodes the certificate's current epoch from `PREIMAGE_CURRENT_EPOCH_BYTES`. The
    /// 8 bytes are interpreted little-endian as a `u64`.
    pub(crate) fn current_epoch(&self) -> EpochNumber {
        let bytes: [u8; 8] = self.0[PREIMAGE_CURRENT_EPOCH_BYTES]
            .try_into()
            .expect("PREIMAGE_CURRENT_EPOCH_BYTES range is exactly 8 bytes");
        EpochNumber::new(u64::from_le_bytes(bytes))
    }

    /// Decodes the announced next-epoch Merkle-tree commitment from
    /// `PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES`. The 32 bytes are reduced modulo the
    /// base field, mirroring the circuit's `combine_bytes` decoding.
    pub(crate) fn next_merkle_tree_commitment(&self) -> MerkleTreeCommitment {
        let bytes: [u8; 32] = self.0[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES]
            .try_into()
            .expect("PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES range is exactly 32 bytes");
        MerkleTreeCommitment::from_field(
            BaseFieldElement::from_raw(&bytes)
                .expect("BaseFieldElement::from_raw applies modulus reduction and cannot fail")
                .0,
        )
    }

    /// Decodes the announced next-epoch protocol parameters from
    /// `PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES`. The 32 bytes are reduced modulo the
    /// base field, mirroring the circuit's `combine_bytes` decoding.
    pub(crate) fn next_protocol_parameters(&self) -> ProtocolParametersHash {
        let bytes: [u8; 32] = self.0[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES]
            .try_into()
            .expect("PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES range is exactly 32 bytes");
        ProtocolParametersHash::from_field(
            BaseFieldElement::from_raw(&bytes)
                .expect("BaseFieldElement::from_raw applies modulus reduction and cannot fail")
                .0,
        )
    }
}

impl From<[u8; PREIMAGE_SIZE]> for ProtocolMessagePreimage {
    fn from(bytes: [u8; PREIMAGE_SIZE]) -> Self {
        Self(bytes)
    }
}

impl EpochNumber {
    pub(crate) fn is_equal(&self, value: &Self) -> bool {
        self == value
    }

    /// Computes the next epoch value using a checked addition
    /// to avoid not catching potential overflows
    pub(crate) fn next_epoch(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl StepCounter {
    /// Returns true if the StepCounter is not in the genesis
    /// step (= 0) or the first step after genesis (= 1)
    pub(crate) fn is_not_first_step(&self) -> bool {
        self.0 > 1
    }
}

#[cfg(test)]
mod protocol_message_preimage_tests {
    use super::*;

    #[test]
    fn current_epoch_decodes_from_correct_range() {
        let mut bytes = [0u8; PREIMAGE_SIZE];
        bytes[PREIMAGE_CURRENT_EPOCH_BYTES].copy_from_slice(&42u64.to_le_bytes());
        let preimage = ProtocolMessagePreimage::new(bytes);
        assert_eq!(preimage.current_epoch(), EpochNumber::new(42));
    }

    #[test]
    fn next_merkle_tree_commitment_decodes_from_correct_range() {
        let mut bytes = [0u8; PREIMAGE_SIZE];
        bytes[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES].copy_from_slice(&[0x11; 32]);
        let preimage = ProtocolMessagePreimage::new(bytes);
        let expected =
            MerkleTreeCommitment::from_field(BaseFieldElement::from_raw(&[0x11; 32]).unwrap().0);
        assert_eq!(preimage.next_merkle_tree_commitment(), expected);
    }

    #[test]
    fn next_protocol_parameters_decodes_from_correct_range() {
        let mut bytes = [0u8; PREIMAGE_SIZE];
        bytes[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES].copy_from_slice(&[0x22; 32]);
        let preimage = ProtocolMessagePreimage::new(bytes);
        let expected =
            ProtocolParametersHash::from_field(BaseFieldElement::from_raw(&[0x22; 32]).unwrap().0);
        assert_eq!(preimage.next_protocol_parameters(), expected);
    }

    #[test]
    fn genesis_zero_preimage_decodes_to_zero_fields() {
        let preimage = ProtocolMessagePreimage::new([0u8; PREIMAGE_SIZE]);
        assert_eq!(preimage.current_epoch(), EpochNumber::ZERO);
        assert_eq!(
            preimage.next_merkle_tree_commitment(),
            MerkleTreeCommitment::ZERO
        );
        assert_eq!(
            preimage.next_protocol_parameters(),
            ProtocolParametersHash::ZERO
        );
    }

    #[test]
    fn next_merkle_tree_commitment_reduces_max_value_modulo_field() {
        let mut bytes = [0u8; PREIMAGE_SIZE];
        bytes[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES].copy_from_slice(&[0xFF; 32]);
        let preimage = ProtocolMessagePreimage::new(bytes);
        let expected =
            MerkleTreeCommitment::from_field(BaseFieldElement::from_raw(&[0xFF; 32]).unwrap().0);
        assert_eq!(preimage.next_merkle_tree_commitment(), expected);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateProofBytes(Vec<u8>);

impl CertificateProofBytes {
    pub(crate) fn from_certificate_circuit_proof_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    #[cfg(test)]
    pub(crate) fn garbage(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Provisional recursive proof-byte wrapper until `IvcProof` is wired end-to-end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IvcProofBytes(Vec<u8>);

impl IvcProofBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}
