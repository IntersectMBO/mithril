use std::{collections::VecDeque, sync::Mutex};

use async_trait::async_trait;

use mithril_common::StdResult;

use crate::entities::{ChainBlockNextAction, RawCardanoPoint};

use crate::chain_reader::ChainBlockReader;

/// [FakeChainReader] is a fake implementation of [ChainBlockReader] for testing purposes.
///
/// Setting the chain point consumes a leading rollback to the first candidate, as the
/// acknowledgement of the intersection sent by the node. A leading rollback to an older candidate
/// stays as the next chain block, as the node acknowledges an intersection below the chain point.
pub struct FakeChainReader {
    chain_block_next_actions: Mutex<VecDeque<ChainBlockNextAction>>,
}

impl FakeChainReader {
    /// Creates a new [FakeChainReader] instance.
    pub fn new(chain_block_next_actions: Vec<ChainBlockNextAction>) -> Self {
        Self {
            chain_block_next_actions: Mutex::new(chain_block_next_actions.into()),
        }
    }

    /// Total remaining next actions
    pub fn get_total_remaining_next_actions(&self) -> usize {
        self.chain_block_next_actions.lock().unwrap().len()
    }
}

#[async_trait]
impl ChainBlockReader for FakeChainReader {
    async fn set_chain_point(&mut self, candidates: &[RawCardanoPoint]) -> StdResult<()> {
        let mut chain_block_next_actions = self.chain_block_next_actions.lock().unwrap();
        let acknowledges_intersection = matches!(
            (chain_block_next_actions.front(), candidates.first()),
            (Some(ChainBlockNextAction::RollBackward { rollback_point }), Some(first_candidate))
                if rollback_point == first_candidate
        );
        if acknowledges_intersection {
            chain_block_next_actions.pop_front();
        }

        Ok(())
    }

    async fn get_next_chain_block(&mut self) -> StdResult<Option<ChainBlockNextAction>> {
        Ok(self.chain_block_next_actions.lock().unwrap().pop_front())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::{BlockNumber, SlotNumber};

    use crate::entities::ScannedBlock;

    use super::*;

    #[tokio::test]
    async fn test_get_next_chain_block() {
        let expected_chain_block_next_actions = vec![
            ChainBlockNextAction::RollForward {
                parsed_block: ScannedBlock::new(
                    "hash-1",
                    BlockNumber(1),
                    SlotNumber(10),
                    Vec::<&str>::new(),
                ),
            },
            ChainBlockNextAction::RollForward {
                parsed_block: ScannedBlock::new(
                    "hash-2",
                    BlockNumber(2),
                    SlotNumber(11),
                    Vec::<&str>::new(),
                ),
            },
            ChainBlockNextAction::RollBackward {
                rollback_point: RawCardanoPoint::new(SlotNumber(1), "point-hash-1".as_bytes()),
            },
        ];

        let mut chain_reader = FakeChainReader::new(expected_chain_block_next_actions.clone());

        let mut chain_block_next_actions = vec![];
        while let Some(chain_block_next_action) = chain_reader.get_next_chain_block().await.unwrap()
        {
            chain_block_next_actions.push(chain_block_next_action);
        }

        assert_eq!(expected_chain_block_next_actions, chain_block_next_actions);
    }

    #[tokio::test]
    async fn set_chain_point_consumes_a_leading_rollback_to_the_chain_point() {
        let chain_point = RawCardanoPoint::new(SlotNumber(1), "point-hash-1".as_bytes());
        let block = ScannedBlock::new("hash-1", BlockNumber(1), SlotNumber(10), Vec::<&str>::new());
        let mut chain_reader = FakeChainReader::new(vec![
            ChainBlockNextAction::RollBackward {
                rollback_point: chain_point.clone(),
            },
            ChainBlockNextAction::RollForward {
                parsed_block: block.clone(),
            },
        ]);

        chain_reader.set_chain_point(&[chain_point]).await.unwrap();

        assert_eq!(
            Some(ChainBlockNextAction::RollForward {
                parsed_block: block
            }),
            chain_reader.get_next_chain_block().await.unwrap()
        );
    }

    #[tokio::test]
    async fn set_chain_point_keeps_a_leading_rollback_to_an_older_candidate() {
        let rollback = ChainBlockNextAction::RollBackward {
            rollback_point: RawCardanoPoint::new(SlotNumber(1), "point-hash-1".as_bytes()),
        };
        let mut chain_reader = FakeChainReader::new(vec![rollback.clone()]);

        chain_reader
            .set_chain_point(&[
                RawCardanoPoint::new(SlotNumber(2), "point-hash-2".as_bytes()),
                RawCardanoPoint::new(SlotNumber(1), "point-hash-1".as_bytes()),
            ])
            .await
            .unwrap();

        assert_eq!(
            Some(rollback),
            chain_reader.get_next_chain_block().await.unwrap()
        );
    }

    #[tokio::test]
    async fn set_chain_point_keeps_a_leading_roll_forward() {
        let roll_forward = ChainBlockNextAction::RollForward {
            parsed_block: ScannedBlock::new(
                "hash-1",
                BlockNumber(1),
                SlotNumber(10),
                Vec::<&str>::new(),
            ),
        };
        let mut chain_reader = FakeChainReader::new(vec![roll_forward.clone()]);

        chain_reader
            .set_chain_point(&[RawCardanoPoint::new(SlotNumber(10), "hash-1")])
            .await
            .unwrap();

        assert_eq!(
            Some(roll_forward),
            chain_reader.get_next_chain_block().await.unwrap()
        );
    }
}
