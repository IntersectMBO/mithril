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
        foreign::weierstrass_chip::{
            ForeignWeierstrassEccChip, ForeignWeierstrassEccConfig, nb_foreign_ecc_chip_columns,
        },
        native::{EccChip, EccConfig, NB_EDWARDS_COLS},
    },
    field::{
        NativeChip, NativeConfig, NativeGadget,
        decomposition::{
            chip::{P2RDecompositionChip, P2RDecompositionConfig},
            pow2range::Pow2RangeChip,
        },
        foreign::FieldChip,
        native::{NB_ARITH_COLS, NB_ARITH_FIXED_COLS},
    },
    hash::poseidon::{
        NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, PoseidonChip, PoseidonConfig,
    },
    hash::sha256::{NB_SHA256_ADVICE_COLS, NB_SHA256_FIXED_COLS},
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
        ControlFlowInstructions, ConversionInstructions, EccInstructions, EqualityInstructions,
        HashInstructions, PublicInputInstructions, ZeroInstructions,
    },
    types::{
        AssignedBit, AssignedByte, AssignedForeignPoint, AssignedNative, AssignedNativePoint,
        AssignedScalarOfNativeCurve, ComposableChip, Instantiable,
    },
    verifier::{self, Accumulator, AssignedAccumulator, AssignedVk, Msm, VerifierGadget},
};

pub(crate) use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey, VerifyingKey},
    poly::{EvaluationDomain, kzg::KZGCommitmentScheme},
};

pub(crate) mod accumulator;
#[cfg(any(test, feature = "benchmark-internals"))]
pub mod bench_helpers;
pub(crate) mod certificate_proof;
pub(crate) mod circuit;
pub(crate) mod config;
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

use midnight_backend::{EmulatedCurve, EmulatedCurveBaseField, RecursiveEmulation};
pub(crate) use midnight_backend::{NativeField, PairingEngine};

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
