//! Genesis-signed registry of the circuit verification keys trusted for SNARK certificates.
//!
//! The registry holds one entry per circuit verification key digest, allowed over an inclusive
//! epoch range or revoked, e.g. after a circuit vulnerability. It is published in the repository
//! per network, retrieved at runtime and verified against the Ed25519 half of the genesis
//! verification key before use.

#![warn(missing_docs)]

#[cfg(feature = "future_snark")]
mod certifier;
#[cfg(feature = "future_snark")]
mod http_downloader;
#[cfg(feature = "future_snark")]
mod registry;
#[cfg(feature = "future_snark")]
mod retriever;
#[cfg(feature = "future_snark")]
pub mod test;

#[cfg(feature = "future_snark")]
pub use certifier::*;
#[cfg(feature = "future_snark")]
pub use http_downloader::*;
#[cfg(feature = "future_snark")]
pub use registry::*;
#[cfg(feature = "future_snark")]
pub use retriever::*;
