macro_rules! cfg_num_integer {
    ($($item:item)*) => {
        $(
            #[cfg(any(feature = "num-integer-backend", target_family = "wasm", target_env = "musl", windows))]
            $item
        )*
    };
}

macro_rules! cfg_rug {
    ($($item:item)*) => {
        $(
            #[cfg(not(any(feature = "num-integer-backend", target_family = "wasm", target_env = "musl", windows)))]
            $item
        )*
    };
}

mod concatenation;
#[cfg(feature = "future_snark")]
mod halo2_snark;
#[cfg(feature = "future_snark")]
mod snark_prover_factory;

/// Serialized `ParamsVerifierKZG` (i.e. `s_g2`) from the Midnight production trusted SRS.
///
/// `ParamsVerifierKZG` serializes only `s_g2` — a single G2 point from the power-of-tau
/// ceremony. This value is independent of the circuit degree `k`, so all circuits
/// (non-recursive and IVC) share it.
///
/// Regenerate by extracting `srs.verifier_params()` from `TrustedSetupProvider` and
/// serializing with `SerdeFormat::RawBytesUnchecked`; the `verifier_setup_matches_trusted_srs`
/// test (in `halo2_snark`) asserts the embedded bytes still match the trusted SRS.
#[cfg(feature = "future_snark")]
pub(crate) const KZG_VERIFIER_PARAMS: [u8; 192] = [
    4, 187, 225, 162, 79, 204, 79, 152, 140, 110, 242, 104, 208, 193, 22, 14, 172, 10, 12, 79, 83,
    216, 11, 215, 79, 61, 46, 70, 103, 190, 39, 64, 134, 37, 168, 56, 37, 53, 78, 39, 199, 8, 89,
    136, 49, 2, 235, 67, 7, 172, 181, 105, 179, 24, 124, 15, 209, 153, 57, 128, 170, 82, 166, 233,
    226, 8, 11, 150, 151, 250, 185, 106, 189, 92, 95, 28, 59, 152, 130, 86, 242, 217, 147, 102,
    241, 187, 204, 241, 60, 240, 226, 7, 2, 254, 225, 140, 15, 8, 23, 150, 4, 171, 232, 193, 130,
    11, 190, 209, 17, 39, 64, 141, 203, 80, 114, 173, 202, 184, 87, 116, 163, 45, 81, 139, 104, 35,
    80, 176, 106, 34, 168, 123, 241, 120, 135, 115, 42, 10, 244, 93, 223, 204, 191, 248, 16, 225,
    178, 33, 226, 165, 145, 29, 111, 150, 131, 163, 111, 78, 127, 231, 212, 66, 129, 222, 134, 161,
    134, 204, 16, 108, 51, 54, 245, 143, 236, 224, 30, 118, 109, 196, 20, 125, 56, 227, 25, 54, 16,
    90, 73, 68, 203, 89,
];

#[cfg(feature = "future_snark")]
pub(crate) mod ivc_halo2_snark;

pub use concatenation::{
    AggregateVerificationKeyForConcatenation, ConcatenationClerk, ConcatenationProof,
};
pub(crate) use concatenation::{ConcatenationProofSigner, SingleSignatureForConcatenation};

#[cfg(feature = "future_snark")]
pub use halo2_snark::{
    AggregateVerificationKeyForSnark, MERKLE_TREE_DEPTH_FOR_SNARK, SnarkProof, SnarkVerifierData,
};

#[cfg(all(test, feature = "future_snark"))]
pub(crate) use halo2_snark::{MockSnarkAggregateSignatureProver, SnarkProverSetup};
#[cfg(feature = "future_snark")]
pub(crate) use halo2_snark::{
    SingleSignatureForSnark, SnarkAggregateSignatureProver, SnarkClerk, SnarkProofSigner,
    SnarkProver, SnarkVerifierSetup, compute_target_value_for_snark_lottery,
};

#[cfg(all(test, feature = "future_snark"))]
pub(crate) use halo2_snark::RIGID_SLOT_BYTES as SNARK_AGGREGATE_VERIFICATION_KEY_RIGID_SLOT_BYTES;

#[cfg(feature = "future_snark")]
pub(crate) use ivc_halo2_snark::rolling_state::IvcRollingState;

#[cfg(feature = "future_snark")]
pub(crate) use snark_prover_factory::{NonDeterministicSnarkProverFactory, SnarkProverFactory};

#[cfg(all(test, feature = "future_snark"))]
pub(crate) use snark_prover_factory::MockSnarkProverFactory;
