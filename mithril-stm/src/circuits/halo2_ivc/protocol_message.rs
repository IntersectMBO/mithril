//! Test/generator-side protocol message builder for Halo2 IVC circuit assets.

use std::collections::BTreeMap;

use anyhow::anyhow;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::proof_system::SNARK_AGGREGATE_VERIFICATION_KEY_RIGID_SLOT_BYTES;
use crate::{AggregateVerificationKeyForSnark, MembershipDigest, StmResult};

use super::PREIMAGE_SIZE;

// Rigid labels match `mithril-common::ProtocolMessage::rigid_preimage()` byte-for-byte.
// These are NOT derived from the key Display strings; the Display strings are only
// used in the dynamic-parts SHA256 computation.
const RIGID_DIGEST_LABEL: &[u8] = b"digest";
const RIGID_NEXT_AGGREGATE_VERIFICATION_KEY_LABEL: &[u8] = b"next_aggregate_verification_key";
const RIGID_NEXT_PROTOCOL_PARAMETERS_LABEL: &[u8] = b"next_protocol_parameters";
const RIGID_CURRENT_EPOCH_LABEL: &[u8] = b"current_epoch";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DynamicProtocolMessagePartKey {
    SnapshotDigest,
}

impl std::fmt::Display for DynamicProtocolMessagePartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SnapshotDigest => write!(f, "snapshot_digest"),
        }
    }
}

pub(crate) struct ProtocolMessage {
    dynamic_message_parts: BTreeMap<DynamicProtocolMessagePartKey, String>,
    next_snark_aggregate_verification_key:
        Option<[u8; SNARK_AGGREGATE_VERIFICATION_KEY_RIGID_SLOT_BYTES]>,
    next_protocol_parameters: Option<[u8; 32]>,
    current_epoch: Option<u64>,
}

impl ProtocolMessage {
    pub(crate) fn new() -> Self {
        Self {
            dynamic_message_parts: BTreeMap::new(),
            next_snark_aggregate_verification_key: None,
            next_protocol_parameters: None,
            current_epoch: None,
        }
    }

    pub(crate) fn set_dynamic_message_part(
        &mut self,
        key: DynamicProtocolMessagePartKey,
        value: String,
    ) {
        self.dynamic_message_parts.insert(key, value);
    }

    pub(crate) fn set_next_snark_aggregate_verification_key<D: MembershipDigest>(
        &mut self,
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
    ) -> StmResult<()> {
        self.next_snark_aggregate_verification_key =
            Some(aggregate_verification_key.to_rigid_slot_bytes()?);
        Ok(())
    }

    pub(crate) fn set_next_protocol_parameters(&mut self, protocol_parameters: [u8; 32]) {
        self.next_protocol_parameters = Some(protocol_parameters);
    }

    pub(crate) fn set_current_epoch(&mut self, current_epoch: u64) {
        self.current_epoch = Some(current_epoch);
    }

    /// Assembles the 190-byte rigid preimage that matches `mithril-common::ProtocolMessage::rigid_preimage()`.
    ///
    /// Layout:
    /// ```text
    /// "digest"                           (6 bytes)
    /// || SHA256(dynamic_parts)           (32 bytes)
    /// || "next_aggregate_verification_key" (31 bytes)
    /// || avk_slot                        (44 bytes)
    /// || "next_protocol_parameters"      (24 bytes)
    /// || params_slot                     (32 bytes)
    /// || "current_epoch"                 (13 bytes)
    /// || epoch_slot                      (8 bytes)
    /// = 190 bytes
    /// ```
    pub(crate) fn try_rigid_preimage(&self) -> StmResult<[u8; PREIMAGE_SIZE]> {
        let dynamic_hash = self.compute_dynamic_parts_hash();
        let avk_slot = self
            .next_snark_aggregate_verification_key
            .ok_or_else(|| anyhow!("next SNARK aggregate verification key slot is required"))?;
        let params_slot = self
            .next_protocol_parameters
            .ok_or_else(|| anyhow!("next protocol parameters slot is required"))?;
        let epoch_slot = self
            .current_epoch
            .ok_or_else(|| anyhow!("current epoch slot is required"))?
            .to_le_bytes();

        let mut preimage = [0u8; PREIMAGE_SIZE];
        let mut cursor = 0;

        // offset 0..6
        preimage[cursor..cursor + RIGID_DIGEST_LABEL.len()].copy_from_slice(RIGID_DIGEST_LABEL);
        cursor += RIGID_DIGEST_LABEL.len();

        // offset 6..38
        preimage[cursor..cursor + 32].copy_from_slice(&dynamic_hash);
        cursor += 32;

        // offset 38..69
        preimage[cursor..cursor + RIGID_NEXT_AGGREGATE_VERIFICATION_KEY_LABEL.len()]
            .copy_from_slice(RIGID_NEXT_AGGREGATE_VERIFICATION_KEY_LABEL);
        cursor += RIGID_NEXT_AGGREGATE_VERIFICATION_KEY_LABEL.len();

        // offset 69..113 — AVK slot; circuit reads the next Merkle-tree commitment from PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES (69..101)
        preimage[cursor..cursor + avk_slot.len()].copy_from_slice(&avk_slot);
        cursor += avk_slot.len();

        // offset 113..137
        preimage[cursor..cursor + RIGID_NEXT_PROTOCOL_PARAMETERS_LABEL.len()]
            .copy_from_slice(RIGID_NEXT_PROTOCOL_PARAMETERS_LABEL);
        cursor += RIGID_NEXT_PROTOCOL_PARAMETERS_LABEL.len();

        // offset 137..169 — params slot; circuit reads from PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES (137..169)
        preimage[cursor..cursor + params_slot.len()].copy_from_slice(&params_slot);
        cursor += params_slot.len();

        // offset 169..182
        preimage[cursor..cursor + RIGID_CURRENT_EPOCH_LABEL.len()]
            .copy_from_slice(RIGID_CURRENT_EPOCH_LABEL);
        cursor += RIGID_CURRENT_EPOCH_LABEL.len();

        // offset 182..190 — epoch slot; circuit reads from PREIMAGE_CURRENT_EPOCH_BYTES (182..190)
        preimage[cursor..cursor + epoch_slot.len()].copy_from_slice(&epoch_slot);

        Ok(preimage)
    }

    /// SHA256 of the dynamic parts in BTreeMap order:
    /// `SHA256(key.to_string() || value)` for each entry.
    fn compute_dynamic_parts_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (key, value) in &self.dynamic_message_parts {
            hasher.update(key.to_string().as_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.finalize().into()
    }
}
