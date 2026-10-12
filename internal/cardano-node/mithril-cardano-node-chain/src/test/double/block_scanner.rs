use std::collections::VecDeque;
use std::sync::RwLock;

use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::{BlockNumber, ChainPoint};

use crate::chain_scanner::{BlockScanner, BlockStreamer, ChainScannedBlocks};
use crate::entities::{RawCardanoPoint, ScannedBlock};

/// Dumb block scanner
pub struct DumbBlockScanner {
    streamer: RwLock<DumbBlockStreamer>,
}

impl DumbBlockScanner {
    /// Factory
    pub fn new() -> Self {
        Self {
            streamer: RwLock::new(DumbBlockStreamer::new()),
        }
    }

    /// Add to the inner streamer several [ChainScannedBlocks::RollForwards] responses at the end of
    /// its queue.
    pub fn forwards(self, blocks: Vec<Vec<ScannedBlock>>) -> Self {
        self.add_forwards(blocks);
        self
    }

    /// Add to the inner streamer a [ChainScannedBlocks::RollBackward] response at the end of its queue.
    pub fn backward(self, chain_point: ChainPoint) -> Self {
        self.add_backward(chain_point);
        self
    }

    /// Set the last polled point to return when [Self::last_polled_point] is called.
    pub fn last_polled_point(self, raw_point: Option<RawCardanoPoint>) -> Self {
        self.set_last_polled_point(raw_point);
        self
    }

    /// Add to the inner streamer several [ChainScannedBlocks::RollForwards] responses at the end of
    /// its queue.
    pub fn add_forwards(&self, blocks: Vec<Vec<ScannedBlock>>) {
        let mut streamer = self.streamer.write().unwrap();
        *streamer = streamer.clone().forwards(blocks);
    }

    /// Add to the inner streamer a [ChainScannedBlocks::RollBackward] response at the end of its queue.
    pub fn add_backward(&self, chain_point: ChainPoint) {
        let mut streamer = self.streamer.write().unwrap();
        *streamer = streamer.clone().rollback(chain_point);
    }

    /// Set the last polled point to return when [Self::last_polled_point] is called.
    pub fn set_last_polled_point(&self, raw_point: Option<RawCardanoPoint>) {
        let mut streamer = self.streamer.write().unwrap();
        *streamer = streamer.clone().set_last_polled_point(raw_point);
    }
}

impl Default for DumbBlockScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockScanner for DumbBlockScanner {
    async fn scan(
        &self,
        _candidates: Vec<RawCardanoPoint>,
        _until: BlockNumber,
    ) -> StdResult<Box<dyn BlockStreamer>> {
        let streamer = self.streamer.read().unwrap();
        Ok(Box::new(streamer.clone()))
    }
}

/// Dumb block streamer
#[derive(Clone)]
pub struct DumbBlockStreamer {
    streamer_responses: VecDeque<ChainScannedBlocks>,
    last_polled_point: Option<RawCardanoPoint>,
}

impl DumbBlockStreamer {
    /// Factory - the resulting streamer can be polled one time for each list of blocks given
    pub fn new() -> Self {
        Self {
            streamer_responses: VecDeque::new(),
            last_polled_point: None,
        }
    }

    /// Set the last polled point to return when [Self::last_polled_point] is called
    pub fn set_last_polled_point(mut self, raw_point: Option<RawCardanoPoint>) -> Self {
        self.last_polled_point = raw_point;
        self
    }

    /// Add to the streamer several [ChainScannedBlocks::RollForwards] responses at the end of
    /// its queue.
    pub fn forwards(mut self, blocks: Vec<Vec<ScannedBlock>>) -> Self {
        let mut source: VecDeque<_> =
            blocks.into_iter().map(ChainScannedBlocks::RollForwards).collect();
        self.streamer_responses.append(&mut source);

        self
    }

    /// Add to the streamer a [ChainScannedBlocks::RollBackward] response at the end of its queue.
    pub fn rollback(mut self, chain_point: ChainPoint) -> Self {
        self.streamer_responses
            .push_back(ChainScannedBlocks::RollBackward(chain_point.slot_number));
        self
    }
}

impl Default for DumbBlockStreamer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockStreamer for DumbBlockStreamer {
    async fn poll_next(&mut self) -> StdResult<Option<ChainScannedBlocks>> {
        Ok(self.streamer_responses.pop_front())
    }

    fn last_polled_point(&self) -> Option<RawCardanoPoint> {
        self.last_polled_point.clone()
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::SlotNumber;

    use super::*;

    #[tokio::test]
    async fn polling_without_set_of_block_return_none() {
        let mut streamer = DumbBlockStreamer::new().forwards(vec![]);
        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(blocks, None);
    }

    #[tokio::test]
    async fn polling_with_one_set_of_block_returns_some_once() {
        let expected_blocks = vec![ScannedBlock::new(
            "hash-1",
            BlockNumber(1),
            SlotNumber(10),
            Vec::<&str>::new(),
        )];
        let mut streamer = DumbBlockStreamer::new().forwards(vec![expected_blocks.clone()]);

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(blocks, None);
    }

    #[tokio::test]
    async fn polling_with_multiple_sets_of_blocks_returns_some_once() {
        let expected_blocks = vec![
            vec![ScannedBlock::new(
                "hash-1",
                BlockNumber(1),
                SlotNumber(10),
                Vec::<&str>::new(),
            )],
            vec![
                ScannedBlock::new("hash-2", BlockNumber(2), SlotNumber(11), Vec::<&str>::new()),
                ScannedBlock::new("hash-3", BlockNumber(3), SlotNumber(12), Vec::<&str>::new()),
            ],
            vec![ScannedBlock::new(
                "hash-4",
                BlockNumber(4),
                SlotNumber(13),
                Vec::<&str>::new(),
            )],
        ];
        let mut streamer = DumbBlockStreamer::new().forwards(expected_blocks.clone());

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks[0].clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks[1].clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks[2].clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(blocks, None);
    }

    #[tokio::test]
    async fn dumb_scanned_construct_a_streamer_based_on_its_stored_blocks() {
        let expected_blocks = vec![ScannedBlock::new(
            "hash-1",
            BlockNumber(1),
            SlotNumber(10),
            Vec::<&str>::new(),
        )];

        let scanner = DumbBlockScanner::new().forwards(vec![expected_blocks.clone()]);
        let mut streamer = scanner.scan(vec![], BlockNumber(5)).await.unwrap();

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(blocks, None);
    }

    #[tokio::test]
    async fn dumb_scanned_construct_a_streamer_based_on_its_stored_chain_scanned_blocks() {
        let expected_blocks = vec![ScannedBlock::new(
            "hash-1",
            BlockNumber(1),
            SlotNumber(10),
            Vec::<&str>::new(),
        )];
        let expected_chain_point = ChainPoint::new(SlotNumber(10), BlockNumber(2), "block-hash");

        let scanner = DumbBlockScanner::new()
            .forwards(vec![expected_blocks.clone()])
            .backward(expected_chain_point.clone());
        let mut streamer = scanner.scan(vec![], BlockNumber(5)).await.unwrap();

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks.clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollBackward(
                expected_chain_point.slot_number
            ))
        );
    }

    #[tokio::test]
    async fn polling_with_can_return_roll_backward() {
        let expected_blocks = vec![
            vec![ScannedBlock::new(
                "hash-1",
                BlockNumber(1),
                SlotNumber(10),
                Vec::<&str>::new(),
            )],
            vec![ScannedBlock::new(
                "hash-4",
                BlockNumber(4),
                SlotNumber(13),
                Vec::<&str>::new(),
            )],
        ];

        let expected_chain_point = ChainPoint::new(SlotNumber(10), BlockNumber(2), "block-hash");

        let mut streamer = DumbBlockStreamer::new()
            .forwards(expected_blocks.clone())
            .rollback(expected_chain_point.clone());

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks[0].clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollForwards(expected_blocks[1].clone()))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(
            blocks,
            Some(ChainScannedBlocks::RollBackward(
                expected_chain_point.slot_number
            ))
        );

        let blocks = streamer.poll_next().await.unwrap();
        assert_eq!(blocks, None);
    }

    #[tokio::test]
    async fn setting_last_polled_block() {
        let mut streamer = DumbBlockStreamer::new().forwards(vec![]);
        assert_eq!(streamer.last_polled_point(), None);

        let raw_point = RawCardanoPoint::new(SlotNumber(10), "block-hash".as_bytes());
        streamer = streamer.set_last_polled_point(Some(raw_point.clone()));
        assert_eq!(streamer.last_polled_point(), Some(raw_point));

        streamer = streamer.set_last_polled_point(None);
        assert_eq!(streamer.last_polled_point(), None);
    }
}
