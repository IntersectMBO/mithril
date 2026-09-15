//! Byte and serde encodings for a Midnight verifying key, shared by every circuit that stores its
//! key in that format.
//!
//! `MidnightVK` is self-describing and belongs to the standard library, so Rust coherence allows
//! only one implementation of the crate's byte traits for it. It lives here rather than beside one
//! circuit's keys so that both circuits reach the same encoding.

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

/// Serde for a wrapped Midnight verifying key: delegates to the key's [`TryToBytes`] /
/// [`TryFromBytes`] impl so the raw-bytes encoding is defined in one place.
pub(crate) mod midnight_verifying_key_serde {
    use midnight_zk_stdlib::MidnightVK;
    use serde::{Deserializer, Serializer};

    use crate::codec::{TryFromBytes, TryToBytes};

    pub(crate) fn serialize<S: Serializer>(
        verifying_key: &MidnightVK,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = verifying_key.to_bytes_vec().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<MidnightVK, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        MidnightVK::try_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
