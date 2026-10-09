use async_trait::async_trait;

use mithril_common::StdResult;

use crate::entities::{ChainBlockNextAction, RawCardanoPoint};

/// The trait that reads events to either:
/// - read next block on the chain
/// - rollback to another point in case of rollback
/// - do nothing when tip of the chain is reached
#[async_trait]
pub trait ChainBlockReader: Send + Sync {
    /// Sets the chain point: intersects the chain at the given point and consumes the
    /// acknowledgement of the intersection, so that the next chain blocks are genuine events
    async fn set_chain_point(&mut self, point: &RawCardanoPoint) -> StdResult<()>;

    /// Get the next chain block
    async fn get_next_chain_block(&mut self) -> StdResult<Option<ChainBlockNextAction>>;
}
