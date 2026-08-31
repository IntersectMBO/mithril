#![doc = include_str!("../README.md")]
//! Implementation of Stake-based Threshold Multisignatures
//! Top-level API for Mithril Stake-based Threshold Multisignature scheme.
//! See figure 6 of [the paper](https://eprint.iacr.org/2021/916) for most of the
//! protocol.

/// Return the name of the enclosing function, for test labeling and diagnostics.
///
/// Relies on `std::any::type_name` string formatting and performs suffix stripping (`::f`,
/// `::{{closure}}`) and path slicing to extract the function name. This depends on
/// compiler-generated type names and is therefore not guaranteed to be stable across compiler
/// versions. Intended for test use only.
#[cfg(all(test, feature = "future_snark"))]
macro_rules! current_function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        let name = name.strip_suffix("::f").unwrap_or(name);
        let name = name.strip_suffix("::{{closure}}").unwrap_or(name);
        let function_name_index = name.rfind("::").map(|index| index + 2).unwrap_or(0);
        &name[function_name_index..]
    }};
}

#[cfg(feature = "future_snark")]
pub mod circuits;
pub(crate) mod codec;
#[cfg(feature = "future_snark")]
mod hash;
mod membership_commitment;
mod proof_system;
mod protocol;
mod signature_scheme;

pub use proof_system::AggregateVerificationKeyForConcatenation;
pub(crate) use protocol::RegistrationEntry;
pub use protocol::{
    AggregateSignature, AggregateSignatureError, AggregateSignatureType, AggregateVerificationKey,
    AggregationError, AncillaryGenesisData, AncillaryProofInput, AncillaryProofOutput,
    AncillaryProverData, AncillaryVerifierData, Clerk, ClosedKeyRegistration,
    ClosedRegistrationEntry, GenesisVerificationKeyBundle, Initializer, KeyRegistration,
    Parameters, RegisterError, RegistrationEntryForConcatenation, SignatureError, Signer,
    SingleSignature, SingleSignatureWithRegisteredParty, VerificationKeyForConcatenation,
    VerificationKeyProofOfPossessionForConcatenation,
};
pub use signature_scheme::BlsSignatureError;

use blake2::{Blake2b, digest::consts::U32};
use digest::{Digest, FixedOutput};
use std::fmt::Debug;

#[cfg(feature = "benchmark-internals")]
pub use signature_scheme::{
    BlsProofOfPossession, BlsSignature, BlsSigningKey, BlsVerificationKey,
    BlsVerificationKeyProofOfPossession,
};

#[cfg(feature = "future_snark")]
pub use signature_scheme::{
    BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, StandardSchnorrSignature,
    UniqueSchnorrSignature,
};

#[cfg(all(feature = "future_snark", not(feature = "benchmark-internals")))]
use hash::poseidon::MidnightPoseidonDigest;

#[cfg(feature = "benchmark-internals")]
pub use hash::poseidon::MidnightPoseidonDigest;

#[cfg(feature = "future_snark")]
pub use circuits::{CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE, CircuitVerificationKeyDigest};

#[cfg(feature = "future_snark")]
pub use proof_system::{
    AggregateVerificationKeyForSnark, MERKLE_TREE_DEPTH_FOR_SNARK, SnarkProof, SnarkVerifierData,
};

#[cfg(feature = "future_snark")]
pub use protocol::{RegistrationEntryForSnark, VerificationKeyForSnark};

/// The quantity of stake held by a party, represented as a `u64`.
pub type Stake = u64;

/// The value of a `phi_f` parameter represented as a `f64`
pub type PhiFValue = f64;

/// Quorum index for signatures.
/// An aggregate signature (`StmMultiSig`) must have at least `k` unique indices.
pub type LotteryIndex = u64;

/// Index of the signer in the key registration
pub type SignerIndex = u64;

/// Mithril-stm error type
pub type StmError = anyhow::Error;

/// Mithril-stm result type
pub type StmResult<T> = anyhow::Result<T, StmError>;

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
/// Target value type used in the lottery for snark proof system
pub type LotteryTargetValue = crate::signature_scheme::BaseFieldElement;

/// Trait defining the different hash types for different proof systems.
pub trait MembershipDigest: Clone {
    type ConcatenationHash: Digest + FixedOutput + Clone + Debug + Send + Sync;
    #[cfg(feature = "future_snark")]
    type SnarkHash: Digest + FixedOutput + Clone + Debug + Send + Sync;
}

/// Default Mithril Membership Digest
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MithrilMembershipDigest {}

/// Default implementation of MembershipDigest for Mithril.
///
/// The SNARK path uses Poseidon so the CPU-side membership commitment stays aligned with the
/// Halo2 circuit hashing.
impl MembershipDigest for MithrilMembershipDigest {
    type ConcatenationHash = Blake2b<U32>;
    #[cfg(feature = "future_snark")]
    type SnarkHash = MidnightPoseidonDigest;
}
