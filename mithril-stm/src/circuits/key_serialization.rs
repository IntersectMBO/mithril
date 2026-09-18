//! Byte encoding of a Midnight verifying key, shared by every circuit that stores its key in that
//! format.
//!
//! `MidnightVK` is self-describing and belongs to the standard library, so Rust coherence allows
//! only one implementation of the crate's byte traits for it. It lives here rather than beside one
//! circuit's keys so that both circuits reach the same encoding.
//!
//! Only the encoding direction lives here. Being self-describing means a decoder cannot tell which
//! circuit a key belongs to — it decodes whatever the bytes declare — so decoding belongs to each
//! circuit's newtype, behind that circuit's guard, and there is deliberately no unguarded decoder to
//! reach for.

use anyhow::Context;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::MidnightVK;

use crate::StmResult;
use crate::codec::TryToBytes;

/// Serde format used for the on-disk / in-cache production keys.
pub(crate) const KEY_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

impl TryToBytes for MidnightVK {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the Midnight verifying key")?;
        Ok(bytes)
    }
}
