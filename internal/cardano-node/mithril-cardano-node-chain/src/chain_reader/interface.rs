use async_trait::async_trait;

use mithril_common::StdResult;

use crate::entities::{ChainBlockNextAction, RawCardanoPoint};

/// The trait that reads events to either:
/// - read next block on the chain
/// - rollback to another point in case of rollback
/// - do nothing when tip of the chain is reached
#[async_trait]
pub trait ChainBlockReader: Send + Sync {
    /// Sets the chain point at the first candidate on the chain of the node, the candidates being
    /// ordered by preference, most recent first. The acknowledgement of the intersection is
    /// consumed when the chain point is the first candidate, and left as the next chain block when
    /// it is an older candidate, as the genuine rollback to the chain point
    async fn set_chain_point(&mut self, candidates: &[RawCardanoPoint]) -> StdResult<()>;

    /// Get the next chain block
    async fn get_next_chain_block(&mut self) -> StdResult<Option<ChainBlockNextAction>>;
}
