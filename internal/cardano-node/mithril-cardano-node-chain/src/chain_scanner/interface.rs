use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::{BlockNumber, SlotNumber};

use crate::entities::{RawCardanoPoint, ScannedBlock};

/// A scanner that can read cardano transactions in a cardano database
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait BlockScanner: Sync + Send {
    /// Scan the blocks from the first candidate point on the chain, the candidates being ordered
    /// by preference, most recent first, or from the origin without candidates
    async fn scan(
        &self,
        candidates: Vec<RawCardanoPoint>,
        until: BlockNumber,
    ) -> StdResult<Box<dyn BlockStreamer>>;
}

/// [ChainScannedBlocks] allows to scan new blocks and handle rollbacks
#[derive(Debug, Clone, PartialEq)]
pub enum ChainScannedBlocks {
    /// Roll forward on the chain to the next list of [ScannedBlock]
    RollForwards(Vec<ScannedBlock>),
    /// Roll backward on the chain to the previous [SlotNumber]
    RollBackward(SlotNumber),
}

/// Trait that define how blocks are streamed from a Cardano database
#[async_trait]
pub trait BlockStreamer: Sync + Send {
    /// Stream the next available blocks
    async fn poll_next(&mut self) -> StdResult<Option<ChainScannedBlocks>>;

    /// Get the last polled point of the chain
    fn last_polled_point(&self) -> Option<RawCardanoPoint>;
}
