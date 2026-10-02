mod bls_multi_signature;
#[cfg(feature = "snark")]
mod schnorr_signature;

pub use bls_multi_signature::*;

#[cfg(feature = "snark")]
pub(crate) use schnorr_signature::DOMAIN_SEPARATION_TAG_CIRCUIT_VERIFICATION_KEY_DIGEST;
#[cfg(feature = "snark")]
pub(crate) use schnorr_signature::DOMAIN_SEPARATION_TAG_LOTTERY;
#[cfg(feature = "snark")]
pub(crate) use schnorr_signature::DOMAIN_SEPARATION_TAG_MERKLE_TREE_LEAF;
#[cfg(feature = "snark")]
pub(crate) use schnorr_signature::DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE;
#[cfg(feature = "snark")]
pub(crate) use schnorr_signature::DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE;
#[cfg(feature = "snark")]
pub use schnorr_signature::*;
