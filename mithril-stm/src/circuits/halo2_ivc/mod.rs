//! Recursive (IVC) SNARK circuit for STM certificate-chain aggregation (feature-gated by `future_snark`).
//!
//! At each step the circuit verifies, in-circuit, the previous IVC proof and the current certificate proof
//! (the certificate being aggregated at that step), folding their KZG openings into a running accumulator so
//! one recursive proof attests to the whole certificate chain. The Midnight proving-backend aliases
//! (field/curve/engine) are isolated in the `midnight_backend` submodule; the circuit-boundary types
//! (`CircuitValue`, `SerdeFormat`, and the field-element wrappers) live in `types`.
//!
//! Internally, `Accumulator`, raw `VerifyingKey`, and `ConstraintSystem` are used directly where the verifier
//! gadget and PLONK APIs require them.

pub(crate) use crate::circuits::CircuitCurve;

pub(crate) use midnight_circuits::{
    ecc::{
        curves::CircuitCurve as CircuitCurveTrait,
        foreign::weierstrass_chip::ForeignWeierstrassEccChip, native::EccChip,
    },
    field::{NativeChip, NativeGadget, decomposition::chip::P2RDecompositionChip},
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
        ControlFlowInstructions, ConversionInstructions, EccInstructions, EqualityInstructions,
        PublicInputInstructions, ZeroInstructions,
    },
    types::{
        AssignedBit, AssignedByte, AssignedForeignPoint, AssignedNative, AssignedNativePoint,
        AssignedScalarOfNativeCurve, Instantiable,
    },
    verifier::{self, Accumulator, AssignedAccumulator, AssignedVk, Msm, VerifierGadget},
};

pub(crate) use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, ProvingKey, VerifyingKey},
    poly::{EvaluationDomain, kzg::KZGCommitmentScheme},
};

pub(crate) mod accumulator;
#[cfg(any(test, feature = "benchmark-internals"))]
pub mod bench;
pub(crate) mod certificate_proof;
pub(crate) mod circuit;
pub(crate) mod constraint_builder;
#[cfg(any(test, feature = "benchmark-internals"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod embedded_assets;
pub(crate) mod errors;
pub(crate) mod gadgets;
pub(crate) mod io;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod key_serialization;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod keys;
#[cfg(test)]
pub(crate) mod protocol_message;
pub(crate) mod state;
pub(crate) mod types;
pub(crate) mod witness_assignments;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) use types::{CircuitValue, ProtocolMessagePreimage};

mod midnight_backend;

use midnight_backend::{EmulatedCurve, RecursiveEmulation};
pub(crate) use midnight_backend::{NativeField, PairingEngine};
pub(crate) use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type IvcNativeGadget =
    NativeGadget<NativeField, P2RDecompositionChip<NativeField>, NativeChip<NativeField>>;

// Degree of the recursive circuit
pub(crate) const RECURSIVE_CIRCUIT_DEGREE: u32 = 19;

pub const PREIMAGE_SIZE: usize = 190;
/// Byte range of the next Merkle-tree commitment within the protocol message preimage.
pub const PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES: std::ops::Range<usize> = 69..101;
/// Byte range of the next protocol parameters within the protocol message preimage.
pub const PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES: std::ops::Range<usize> = 137..169;
/// Byte range of the current epoch within the protocol message preimage.
pub const PREIMAGE_CURRENT_EPOCH_BYTES: std::ops::Range<usize> = 182..190;

pub(crate) const CERTIFICATE_FIXED_BASES_PREFIX: &str = "cert_vk";
pub(crate) const IVC_FIXED_BASES_PREFIX: &str = "ivc_one_vk";

/// Circuit verification key of the recursive circuit used for production.
/// It is created using the circuit verification key of the non-recursive
/// circuit and the SRS from Midnight's power of tau ceremony
pub const RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION: &[u8] =
    include_bytes!("recursive_circuit_verification_key_for_production.bin");
