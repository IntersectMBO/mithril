//! Utilities module
//! This module contains tools needed mostly for the snapshot download and unpack.

cfg_fs! {
    pub const ANCILLARIES_NOT_SIGNED_BY_MITHRIL: &str = "Ancillary verification does not use the Mithril certification: as a mitigation, IOG owned keys are used to sign these files.";

    mod ancillary_verifier;
    mod bootstrap_files;
    mod fs;
    mod stream_reader;
    mod temp_dir_provider;
    mod unexpected_downloaded_file_verifier;
    mod vec_deque_extensions;

    pub use ancillary_verifier::AncillaryVerifier;
    pub use bootstrap_files::*;
    pub use fs::*;
    pub use stream_reader::*;
    pub(crate) use temp_dir_provider::{TempDirectoryProvider, TimestampTempDirectoryProvider};
    pub(crate) use unexpected_downloaded_file_verifier::*;
    pub use vec_deque_extensions::VecDequeExtensions;
}

cfg_fs_unstable! {
    mod weighted_coin;
    pub mod url;

    pub(crate) use weighted_coin::WeightedCoin;
}

/// Create a 32 bytes seed for a random generator from the current timestamp.
///
/// The timestamp, in nanoseconds, is written in the first 8 bytes. The remaining bytes are zero.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn timestamp_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    seed[..8].copy_from_slice(&timestamp.to_le_bytes());
    seed
}
