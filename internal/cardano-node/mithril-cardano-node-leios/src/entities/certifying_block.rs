use mithril_common::entities::{BlockNumber, ImmutableFileNumber, SlotNumber};

/// A block that carries a Leios certificate, with the endorser block announced by its direct predecessor.
///
/// The announcement is what the chain commits to: the Blake2b-256 hash of the endorser block body and
/// its size. Every hash is a lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifyingBlock {
    /// Number of the immutable file holding the certifying block.
    pub immutable_file_number: ImmutableFileNumber,

    /// Number of the certifying block.
    pub block_number: BlockNumber,

    /// Slot of the certifying block.
    pub slot_number: SlotNumber,

    /// Hash of the certifying block.
    pub block_hash: String,

    /// Slot of the announcing block, the direct predecessor of the certifying block.
    pub announcing_slot_number: SlotNumber,

    /// Announced hash of the endorser block body.
    pub endorser_block_hash: String,

    /// Announced size of the endorser block body in bytes.
    pub endorser_block_size: u32,
}
