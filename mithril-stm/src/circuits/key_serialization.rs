//! Byte encoding of a Midnight verifying key, shared by every circuit that stores its key in that
//! format.
//!
//! `MidnightVK` is self-describing and belongs to the standard library, so Rust coherence allows
//! only one implementation of the crate's byte traits for it. It lives here rather than beside one
//! circuit's keys so that both circuits reach the same encoding.
//!
//! Being self-describing is also why this codec cannot say which circuit a key belongs to: it
//! decodes whatever the bytes declare. Each circuit's newtype guards its own decoder, and that is
//! the entry point callers use.

use anyhow::Context;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::MidnightVK;

use crate::StmResult;
use crate::codec::{TryFromBytes, TryToBytes};

/// Serde format used for the on-disk / in-cache production keys.
pub(crate) const KEY_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

// `MidnightVK` is self-describing, so reading needs only the serde format, no circuit type.
impl TryToBytes for MidnightVK {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the Midnight verifying key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for MidnightVK {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut reader = bytes;
        MidnightVK::read(&mut reader, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to deserialize the Midnight verifying key")
    }
}
