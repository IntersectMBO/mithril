//! Genesis-signed registry of the circuit verification keys trusted for SNARK certificates.
//!
//! The registry whitelists circuit verification key digests over inclusive epoch ranges and
//! supports revoking them retroactively, e.g. after a circuit vulnerability. It is published in
//! the repository per network, retrieved at runtime and verified against the Ed25519 half of
//! the genesis verification key before use.

mod registry;
mod retriever;

pub use mithril_stm::{CIRCUIT_VERIFICATION_KEY_DIGEST_SIZE, CircuitVerificationKeyDigest};
pub use registry::*;
pub use retriever::*;
