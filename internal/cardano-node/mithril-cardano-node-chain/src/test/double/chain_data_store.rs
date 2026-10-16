use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

use slog::Logger;
use tokio::sync::Mutex;

use mithril_common::StdResult;
use mithril_common::crypto_helper::{MKTreeNode, MKTreeStorer};
use mithril_common::entities::{
    BlockHash, BlockNumber, BlockRange, CardanoBlock, CardanoBlockTransactionMkTreeNode,
    CardanoBlockWithTransactions, CardanoTransaction, ChainPoint, SlotNumber, TransactionHash,
};
use mithril_common::signable_builder::BlockRangeRootRetriever;

use crate::chain_importer::{BlockRangeImporter, ChainDataStore};

/// In memory Block range root representation, for testing purposes.
#[derive(Debug, PartialEq, Clone)]
pub struct InMemoryBlockRangeRoot {
    /// Range of block numbers covered
    pub range: BlockRange,
    /// Merkle root of the block range
    pub merkle_root: MKTreeNode,
}

impl From<(BlockRange, MKTreeNode)> for InMemoryBlockRangeRoot {
    fn from(value: (BlockRange, MKTreeNode)) -> Self {
        Self {
            range: value.0,
            merkle_root: value.1,
        }
    }
}

impl From<InMemoryBlockRangeRoot> for (BlockRange, MKTreeNode) {
    fn from(value: InMemoryBlockRangeRoot) -> Self {
        (value.range, value.merkle_root)
    }
}

/// In memory implementation of [ChainDataStore], for testing purposes.
pub struct InMemoryChainDataStore {
    blocks_with_txs: Mutex<Vec<CardanoBlockWithTransactions>>,
    block_range_roots: Mutex<Vec<InMemoryBlockRangeRoot>>,
    legacy_block_range_roots: Mutex<Vec<InMemoryBlockRangeRoot>>,
}

impl Default for InMemoryChainDataStore {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Builder for [InMemoryChainDataStore].
pub struct InMemoryChainDataStoreBuilder {
    blocks_with_txs: Vec<CardanoBlockWithTransactions>,
    block_range_roots: Vec<InMemoryBlockRangeRoot>,
    legacy_block_range_roots: Vec<InMemoryBlockRangeRoot>,
}

impl InMemoryChainDataStoreBuilder {
    /// Set the initial blocks and transactions for the store, replacing any existing data.
    pub fn with_blocks_and_transactions<T: Into<CardanoBlockWithTransactions> + Clone>(
        mut self,
        transactions: &[T],
    ) -> Self {
        self.blocks_with_txs = transactions.iter().map(|b| b.clone().into()).collect();
        self
    }

    /// Set the initial block range roots for the store, replacing any existing data.
    pub fn with_block_range_roots<T: Into<InMemoryBlockRangeRoot> + Clone>(
        mut self,
        block_range_roots: &[T],
    ) -> Self {
        self.block_range_roots = block_range_roots.iter().map(|brr| brr.clone().into()).collect();
        self
    }

    /// Set the initial block range roots for the store, replacing any existing data.
    pub fn with_legacy_block_range_roots<T: Into<InMemoryBlockRangeRoot> + Clone>(
        mut self,
        block_range_roots: &[T],
    ) -> Self {
        self.legacy_block_range_roots =
            block_range_roots.iter().map(|brr| brr.clone().into()).collect();
        self
    }

    /// Computes the block ranges roots, new and legacy, for all block ranges ending at or below the
    /// given block number, and based on the blocks given in [Self::with_blocks_and_transactions]
    ///
    /// Replace any existing block ranges roots and legacy block ranges roots.
    pub async fn compute_block_ranges(mut self, up_to_block_range_end: BlockNumber) -> Self {
        // Leverage tested `BlockRangeImporter` to compute the block ranges roots.
        let worker_store = Arc::new(InMemoryChainDataStore {
            blocks_with_txs: Mutex::new(self.blocks_with_txs.clone()),
            block_range_roots: Default::default(),
            legacy_block_range_roots: Default::default(),
        });

        let discard_logger = Logger::root(slog::Discard, slog::o!());
        let importer = BlockRangeImporter::new(worker_store.clone(), discard_logger);
        importer.run(up_to_block_range_end).await.unwrap();
        importer.run_legacy(up_to_block_range_end).await.unwrap();

        self.block_range_roots = worker_store.get_all_block_range_root().await;
        self.legacy_block_range_roots = worker_store.get_all_legacy_block_range_root().await;

        self
    }

    /// Creates a new [InMemoryChainDataStore] with the current builder's data.
    pub fn build(self) -> InMemoryChainDataStore {
        InMemoryChainDataStore {
            blocks_with_txs: Mutex::new(self.blocks_with_txs),
            block_range_roots: Mutex::new(self.block_range_roots),
            legacy_block_range_roots: Mutex::new(self.legacy_block_range_roots),
        }
    }
}

impl InMemoryChainDataStore {
    /// Creates a new in-memory store builder with no initial data.
    pub fn builder() -> InMemoryChainDataStoreBuilder {
        InMemoryChainDataStoreBuilder {
            blocks_with_txs: vec![],
            block_range_roots: vec![],
            legacy_block_range_roots: vec![],
        }
    }

    /// Returns all transactions in the store.
    pub async fn get_all_transactions(&self) -> Vec<CardanoTransaction> {
        let blocks = self.blocks_with_txs.lock().await.clone();
        blocks.into_iter().flat_map(|b| b.into_transactions()).collect()
    }

    /// Returns all [CardanoBlockWithTransactions] in the store.
    pub async fn get_all_block_with_txs(&self) -> Vec<CardanoBlockWithTransactions> {
        self.blocks_with_txs.lock().await.clone()
    }

    /// Returns all block range roots in the store.
    pub async fn get_all_block_range_root(&self) -> Vec<InMemoryBlockRangeRoot> {
        self.block_range_roots.lock().await.clone()
    }

    /// Returns all block ranges in the store.
    pub async fn get_all_block_ranges(&self) -> Vec<BlockRange> {
        self.block_range_roots
            .lock()
            .await
            .iter()
            .map(|r| r.range.clone())
            .collect()
    }

    /// Returns all legacy block range roots in the store.
    pub async fn get_all_legacy_block_range_root(&self) -> Vec<InMemoryBlockRangeRoot> {
        self.legacy_block_range_roots.lock().await.clone()
    }

    /// Returns all legacy block ranges in the store.
    pub async fn get_all_legacy_block_ranges(&self) -> Vec<BlockRange> {
        self.legacy_block_range_roots
            .lock()
            .await
            .iter()
            .map(|r| r.range.clone())
            .collect()
    }

    /// Returns all [CardanoBlock] with the given block hashes.
    pub async fn get_blocks_by_hashes(&self, block_hashes: &[BlockHash]) -> Vec<CardanoBlock> {
        let blocks_with_txs = self.blocks_with_txs.lock().await;
        blocks_with_txs
            .iter()
            .filter(|block| block_hashes.contains(&block.block_hash))
            .cloned()
            .map(Into::into)
            .collect()
    }

    /// Returns all [CardanoTransaction] with the given transaction hashes.
    pub async fn get_transactions_by_hashes(
        &self,
        transaction_hashes: &[TransactionHash],
    ) -> Vec<CardanoTransaction> {
        let blocks_with_txs = self.blocks_with_txs.lock().await.clone();
        blocks_with_txs
            .into_iter()
            .flat_map(|block| block.into_transactions())
            .filter(|tx| transaction_hashes.contains(&tx.transaction_hash))
            .collect()
    }

    /// Returns all [CardanoBlockTransactionMkTreeNode] contained in the given block ranges.
    pub async fn get_blocks_with_transactions_in_block_ranges(
        &self,
        block_ranges: &[BlockRange],
    ) -> BTreeSet<CardanoBlockTransactionMkTreeNode> {
        let ranges: Vec<Range<BlockNumber>> =
            block_ranges.iter().map(|range| range.clone().into()).collect();
        self.get_blocks_with_transactions_in_ranges(&ranges).await
    }

    /// Returns all [CardanoBlockTransactionMkTreeNode] contained in the given ranges.
    pub async fn get_blocks_with_transactions_in_ranges(
        &self,
        block_ranges: &[Range<BlockNumber>],
    ) -> BTreeSet<CardanoBlockTransactionMkTreeNode> {
        let blocks = self.blocks_with_txs.lock().await;
        blocks
            .iter()
            .filter(|block| block_ranges.iter().any(|range| range.contains(&block.block_number)))
            .cloned()
            .flat_map(|block| block.into_mk_tree_node())
            .collect()
    }
}

#[async_trait::async_trait]
impl ChainDataStore for InMemoryChainDataStore {
    async fn get_highest_beacon(&self) -> StdResult<Option<ChainPoint>> {
        let txs = self.blocks_with_txs.lock().await;
        Ok(txs
            .iter()
            .max_by_key(|tx| tx.block_number)
            .map(|tx| ChainPoint::new(tx.slot_number, tx.block_number, tx.block_hash.clone())))
    }

    async fn get_chain_points_by_block_numbers(
        &self,
        block_numbers: Vec<BlockNumber>,
    ) -> StdResult<Vec<ChainPoint>> {
        let txs = self.blocks_with_txs.lock().await;
        Ok(txs
            .iter()
            .filter(|tx| block_numbers.contains(&tx.block_number))
            .map(|tx| ChainPoint::new(tx.slot_number, tx.block_number, tx.block_hash.clone()))
            .collect())
    }

    async fn get_highest_block_range(&self) -> StdResult<Option<BlockRange>> {
        let roots = self.block_range_roots.lock().await;
        Ok(roots.iter().map(|record| record.range.clone()).max_by_key(|r| r.end))
    }

    async fn get_highest_legacy_block_range(&self) -> StdResult<Option<BlockRange>> {
        let roots = self.legacy_block_range_roots.lock().await;
        Ok(roots.iter().map(|record| record.range.clone()).max_by_key(|r| r.end))
    }

    async fn store_blocks_and_transactions(
        &self,
        blocks_and_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()> {
        self.blocks_with_txs.lock().await.extend(blocks_and_transactions);
        Ok(())
    }

    async fn get_blocks_and_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
        Ok(self.get_blocks_with_transactions_in_ranges(&[range]).await)
    }

    async fn get_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<Vec<CardanoTransaction>> {
        let txs = self.blocks_with_txs.lock().await;
        Ok(txs
            .iter()
            .filter(|tx| range.contains(&tx.block_number))
            .cloned()
            .flat_map(|tx| tx.into_transactions())
            .collect())
    }

    async fn store_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()> {
        self.block_range_roots
            .lock()
            .await
            .extend(block_ranges.into_iter().map(Into::into));
        Ok(())
    }

    async fn store_legacy_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()> {
        self.legacy_block_range_roots
            .lock()
            .await
            .extend(block_ranges.into_iter().map(Into::into));
        Ok(())
    }

    async fn remove_rolled_chain_data_and_block_range(
        &self,
        slot_number: SlotNumber,
    ) -> StdResult<()> {
        self.blocks_with_txs
            .lock()
            .await
            .retain(|b| b.slot_number <= slot_number);

        if let Some(highest_remaining_block_number) =
            self.blocks_with_txs.lock().await.last().map(|tx| tx.block_number)
        {
            self.block_range_roots
                .lock()
                .await
                .retain(|record| record.range.start < highest_remaining_block_number);
            self.legacy_block_range_roots
                .lock()
                .await
                .retain(|record| record.range.start < highest_remaining_block_number);
        } else {
            self.block_range_roots.lock().await.clear();
            self.legacy_block_range_roots.lock().await.clear();
        }

        Ok(())
    }

    async fn optimize(&self) -> StdResult<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<S: MKTreeStorer> BlockRangeRootRetriever<S> for InMemoryChainDataStore {
    async fn retrieve_block_range_roots<'a>(
        &'a self,
        up_to_beacon: BlockNumber,
    ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>> {
        let block_ranges = self.block_range_roots.lock().await;
        let result: Vec<_> = block_ranges
            .iter()
            .filter(|r| r.range.start < up_to_beacon)
            .cloned()
            .map(|r| (r.range, r.merkle_root))
            .collect();
        Ok(Box::new(result.into_iter()))
    }

    async fn retrieve_block_ranges_nodes(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
        Ok(self.get_blocks_with_transactions_in_ranges(&[range]).await)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::MKTreeStoreInMemory;

    use super::*;

    #[tokio::test]
    async fn builder_can_compute_block_range_roots() {
        let expected_computed_ranges = vec![
            BlockRange::from_block_number(BlockNumber(10)),
            BlockRange::from_block_number(BlockNumber(25)),
        ];
        let builder = InMemoryChainDataStore::builder().with_blocks_and_transactions(&[
            CardanoBlockWithTransactions::new(
                "block_hash-10",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-25",
                BlockNumber(25),
                SlotNumber(51),
                vec!["tx_hash-2", "tx_hash-3"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-30",
                BlockNumber(30),
                SlotNumber(52),
                vec!["tx_hash-4", "tx_hash-5"],
            ),
        ]);

        assert_eq!(
            Vec::<InMemoryBlockRangeRoot>::new(),
            builder.block_range_roots
        );
        assert_eq!(
            Vec::<InMemoryBlockRangeRoot>::new(),
            builder.legacy_block_range_roots
        );

        let builder = builder.compute_block_ranges(BlockNumber(29)).await;

        assert_eq!(
            expected_computed_ranges,
            builder
                .block_range_roots
                .iter()
                .map(|b| b.range.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            expected_computed_ranges,
            builder
                .legacy_block_range_roots
                .iter()
                .map(|b| b.range.clone())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn default_store_is_empty() {
        let store = InMemoryChainDataStore::default();

        assert!(store.get_all_transactions().await.is_empty());
        assert!(store.get_all_block_with_txs().await.is_empty());
        assert!(store.get_all_block_ranges().await.is_empty());
        assert!(store.get_all_block_range_root().await.is_empty());
        assert!(store.get_all_legacy_block_range_root().await.is_empty());
        assert!(store.get_all_legacy_block_ranges().await.is_empty());
    }

    #[tokio::test]
    async fn store_and_get_blocks_and_transactions() {
        let store = InMemoryChainDataStore::default();

        let block_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-123",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-123"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-456",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx_hash-456", "tx_hash-789"],
            ),
        ];

        store
            .store_blocks_and_transactions(block_with_tx.clone())
            .await
            .unwrap();

        let stored_blocks_with_txs = store.get_all_block_with_txs().await;
        assert_eq!(block_with_tx, stored_blocks_with_txs);

        let stored_transactions = store.get_all_transactions().await;
        assert_eq!(
            vec![
                CardanoTransaction::new(
                    "tx_hash-123",
                    BlockNumber(10),
                    SlotNumber(50),
                    "block_hash-123"
                ),
                CardanoTransaction::new(
                    "tx_hash-456",
                    BlockNumber(11),
                    SlotNumber(51),
                    "block_hash-456"
                ),
                CardanoTransaction::new(
                    "tx_hash-789",
                    BlockNumber(11),
                    SlotNumber(51),
                    "block_hash-456"
                )
            ],
            stored_transactions
        );
    }

    #[tokio::test]
    async fn store_transactions_appends_to_existing() {
        let existing_batch = vec![CardanoBlockWithTransactions::new(
            "block_hash-123",
            BlockNumber(10),
            SlotNumber(50),
            vec!["tx_hash-123"],
        )];

        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&existing_batch)
            .build();

        let second_batch = vec![CardanoBlockWithTransactions::new(
            "block_hash-456",
            BlockNumber(11),
            SlotNumber(51),
            vec!["tx_hash-456"],
        )];

        store
            .store_blocks_and_transactions(second_batch.clone())
            .await
            .unwrap();

        let stored_blocks_with_tx = store.get_all_block_with_txs().await;
        assert_eq!(2, stored_blocks_with_tx.len());
        assert_eq!(existing_batch[0], stored_blocks_with_tx[0]);
        assert_eq!(second_batch[0], stored_blocks_with_tx[1]);
    }

    #[tokio::test]
    async fn get_highest_beacon_returns_none_when_empty() {
        let store = InMemoryChainDataStore::default();

        let highest_beacon = store.get_highest_beacon().await.unwrap();

        assert_eq!(None, highest_beacon);
    }

    #[tokio::test]
    async fn get_highest_beacon_returns_transaction_with_highest_block_number() {
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&[
                CardanoBlockWithTransactions::new(
                    "block_hash-10",
                    BlockNumber(10),
                    SlotNumber(50),
                    vec!["tx_hash-123"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-25",
                    BlockNumber(25),
                    SlotNumber(51),
                    vec!["tx_hash-456"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-15",
                    BlockNumber(15),
                    SlotNumber(52),
                    vec!["tx_hash-789"],
                ),
            ])
            .build();

        let highest_beacon = store.get_highest_beacon().await.unwrap();

        assert_eq!(
            Some(ChainPoint::new(
                SlotNumber(51),
                BlockNumber(25),
                "block_hash-25"
            )),
            highest_beacon
        );
    }

    #[tokio::test]
    async fn get_highest_beacon_with_multiple_blocks_with_same_block_number() {
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&[
                CardanoBlockWithTransactions::new(
                    "block_hash-10",
                    BlockNumber(10),
                    SlotNumber(50),
                    vec!["tx_hash-123"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-25",
                    BlockNumber(25),
                    SlotNumber(51),
                    vec!["tx_hash-456"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-25",
                    BlockNumber(25),
                    SlotNumber(51),
                    vec!["tx_hash-789"],
                ),
            ])
            .build();

        let highest_beacon = store.get_highest_beacon().await.unwrap();

        assert_eq!(
            Some(ChainPoint::new(
                SlotNumber(51),
                BlockNumber(25),
                "block_hash-25"
            )),
            highest_beacon
        );
    }

    #[tokio::test]
    async fn store_and_get_block_range_roots() {
        let store = InMemoryChainDataStore::default();

        let block_ranges = vec![
            (
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            ),
            (
                BlockRange::from_block_number(BlockRange::LENGTH),
                MKTreeNode::from_hex("BBBB").unwrap(),
            ),
        ];

        store.store_block_range_roots(block_ranges.clone()).await.unwrap();

        let stored_roots = store.get_all_block_range_root().await;
        assert_eq!(
            vec![
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
                },
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
                },
            ],
            stored_roots
        );
    }

    #[tokio::test]
    async fn store_block_range_roots_appends_to_existing() {
        let store = InMemoryChainDataStore::builder()
            .with_block_range_roots(&[(
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            )])
            .build();

        store
            .store_block_range_roots(vec![(
                BlockRange::from_block_number(BlockRange::LENGTH),
                MKTreeNode::from_hex("BBBB").unwrap(),
            )])
            .await
            .unwrap();

        let stored_roots = store.get_all_block_range_root().await;
        assert_eq!(
            vec![
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap()
                },
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap()
                },
            ],
            stored_roots
        );

        let ranges = store.get_all_block_ranges().await;
        assert_eq!(
            vec![
                BlockRange::from_block_number(BlockNumber(0)),
                BlockRange::from_block_number(BlockRange::LENGTH),
            ],
            ranges
        );
    }

    #[tokio::test]
    async fn get_highest_block_range_returns_none_when_empty() {
        let store = InMemoryChainDataStore::default();

        let highest_range = store.get_highest_block_range().await.unwrap();

        assert_eq!(None, highest_range);
    }

    #[tokio::test]
    async fn store_and_get_legacy_block_range_roots() {
        let store = InMemoryChainDataStore::default();

        let block_ranges = vec![
            (
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            ),
            (
                BlockRange::from_block_number(BlockRange::LENGTH),
                MKTreeNode::from_hex("BBBB").unwrap(),
            ),
        ];

        store
            .store_legacy_block_range_roots(block_ranges.clone())
            .await
            .unwrap();

        let stored_roots = store.get_all_legacy_block_range_root().await;
        assert_eq!(
            vec![
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
                },
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
                },
            ],
            stored_roots
        );
    }

    #[tokio::test]
    async fn store_legacy_block_range_roots_appends_to_existing() {
        let store = InMemoryChainDataStore::builder()
            .with_legacy_block_range_roots(&[(
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            )])
            .build();

        store
            .store_legacy_block_range_roots(vec![(
                BlockRange::from_block_number(BlockRange::LENGTH),
                MKTreeNode::from_hex("BBBB").unwrap(),
            )])
            .await
            .unwrap();

        let stored_roots = store.get_all_legacy_block_range_root().await;
        assert_eq!(
            vec![
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap()
                },
                InMemoryBlockRangeRoot {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap()
                },
            ],
            stored_roots
        );

        let ranges = store.get_all_legacy_block_ranges().await;
        assert_eq!(
            vec![
                BlockRange::from_block_number(BlockNumber(0)),
                BlockRange::from_block_number(BlockRange::LENGTH),
            ],
            ranges
        );
    }

    #[tokio::test]
    async fn get_highest_legacy_block_range_returns_none_when_empty() {
        let store = InMemoryChainDataStore::default();

        let highest_range = store.get_highest_legacy_block_range().await.unwrap();

        assert_eq!(None, highest_range);
    }

    #[tokio::test]
    async fn get_highest_legacy_block_range_returns_range_with_highest_end() {
        let store = InMemoryChainDataStore::builder()
            .with_legacy_block_range_roots(&[
                (
                    BlockRange::from_block_number(BlockNumber(0)),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH * 2),
                    MKTreeNode::from_hex("CCCC").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH),
                    MKTreeNode::from_hex("BBBB").unwrap(),
                ),
            ])
            .build();

        let highest_range = store.get_highest_legacy_block_range().await.unwrap();

        assert_eq!(
            Some(BlockRange::from_block_number(BlockRange::LENGTH * 2)),
            highest_range
        );
    }

    #[tokio::test]
    async fn get_transactions_in_range_returns_empty_when_store_empty() {
        let store = InMemoryChainDataStore::default();

        let transactions = store
            .get_transactions_in_range(BlockNumber(0)..BlockNumber(100))
            .await
            .unwrap();

        assert!(transactions.is_empty());
    }

    #[tokio::test]
    async fn get_transactions_in_range_filters_correctly() {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();
        let transactions: Vec<CardanoTransaction> = blocks_with_tx
            .into_iter()
            .flat_map(|tx| tx.into_transactions())
            .collect();

        // Range excludes all transactions
        {
            let result = store
                .get_transactions_in_range(BlockNumber(0)..BlockNumber(10))
                .await
                .unwrap();
            assert!(result.is_empty());
        }

        // Range after all transactions
        {
            let result = store
                .get_transactions_in_range(BlockNumber(13)..BlockNumber(21))
                .await
                .unwrap();
            assert!(result.is_empty());
        }

        // Range includes the first two transactions (10, 11)
        {
            let result = store
                .get_transactions_in_range(BlockNumber(9)..BlockNumber(12))
                .await
                .unwrap();
            assert_eq!(transactions[0..=1].to_vec(), result);
        }

        // Range includes all transactions
        {
            let result = store
                .get_transactions_in_range(BlockNumber(10)..BlockNumber(13))
                .await
                .unwrap();
            assert_eq!(transactions, result);
        }

        // Range includes the last two transactions (11, 12)
        {
            let result = store
                .get_transactions_in_range(BlockNumber(11)..BlockNumber(14))
                .await
                .unwrap();
            assert_eq!(transactions[1..=2].to_vec(), result);
        }
    }

    #[tokio::test]
    async fn get_blocks_with_transactions_in_ranges_returns_empty_when_store_empty() {
        let store = InMemoryChainDataStore::default();

        let transactions = store
            .get_blocks_with_transactions_in_ranges(&[BlockNumber(0)..BlockNumber(100)])
            .await;

        assert!(transactions.is_empty());
    }

    #[tokio::test]
    async fn get_blocks_with_transactions_in_ranges_filters_correctly() {
        fn into_expected_nodes(
            cbtx: &[CardanoBlockWithTransactions],
        ) -> BTreeSet<CardanoBlockTransactionMkTreeNode> {
            cbtx.iter().flat_map(|b| b.clone().into_mk_tree_node()).collect()
        }

        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();

        // One range that include no transactions
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[BlockNumber(0)..BlockNumber(10)])
                .await;
            assert!(result.is_empty());
        }

        // One range after all transactions
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[BlockNumber(13)..BlockNumber(21)])
                .await;
            assert!(result.is_empty());
        }

        // One range includes the first two transactions (10, 11)
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[BlockNumber(9)..BlockNumber(12)])
                .await;
            assert_eq!(into_expected_nodes(&blocks_with_tx[0..=1]), result);
        }

        // One range includes all transactions
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[BlockNumber(10)..BlockNumber(13)])
                .await;
            assert_eq!(into_expected_nodes(&blocks_with_tx), result);
        }

        // One range includes the last two transactions (11, 12)
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[BlockNumber(11)..BlockNumber(14)])
                .await;
            assert_eq!(into_expected_nodes(&blocks_with_tx[1..=2]), result);
        }

        // Two ranges, one that include the first transaction (10) and the other that include the last transaction (12)
        {
            let result = store
                .get_blocks_with_transactions_in_ranges(&[
                    BlockNumber(9)..BlockNumber(11),
                    BlockNumber(12)..BlockNumber(13),
                ])
                .await;
            assert_eq!(
                into_expected_nodes(&[blocks_with_tx[0].clone(), blocks_with_tx[2].clone()]),
                result
            );
        }
    }

    #[tokio::test]
    async fn get_blocks_by_hashes_filters_correctly() {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();

        // Get one existing hash
        {
            let result = store.get_blocks_by_hashes(&["block-hash-1".to_string()]).await;
            assert_eq!(
                vec![CardanoBlock::new("block-hash-1", BlockNumber(10), SlotNumber(50))],
                result
            );
        }
        // Get one non-existing hash
        {
            let result = store.get_blocks_by_hashes(&["block-hash-4".to_string()]).await;
            assert_eq!(Vec::<CardanoBlock>::new(), result);
        }
        // Get two existing hashes and one non-existing hash
        {
            let result = store
                .get_blocks_by_hashes(&[
                    "block-hash-1".to_string(),
                    "block-hash-3".to_string(),
                    "block-hash-4".to_string(),
                ])
                .await;
            assert_eq!(
                vec![
                    CardanoBlock::new("block-hash-1", BlockNumber(10), SlotNumber(50)),
                    CardanoBlock::new("block-hash-3", BlockNumber(12), SlotNumber(52))
                ],
                result
            );
        }
    }

    #[tokio::test]
    async fn get_transactions_by_hashes_filters_correctly() {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();

        // Get one existing hash
        {
            let result = store.get_transactions_by_hashes(&["tx-hash-1".to_string()]).await;
            assert_eq!(
                vec![CardanoTransaction::new(
                    "tx-hash-1",
                    BlockNumber(10),
                    SlotNumber(50),
                    "block-hash-1"
                )],
                result
            );
        }
        // Get one non-existing hash
        {
            let result = store.get_transactions_by_hashes(&["tx-hash-4".to_string()]).await;
            assert_eq!(Vec::<CardanoTransaction>::new(), result);
        }
        // Get two existing hashes and one non-existing hash
        {
            let result = store
                .get_transactions_by_hashes(&[
                    "tx-hash-1".to_string(),
                    "tx-hash-3".to_string(),
                    "tx-hash-4".to_string(),
                ])
                .await;
            assert_eq!(
                vec![
                    CardanoTransaction::new(
                        "tx-hash-1",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block-hash-1"
                    ),
                    CardanoTransaction::new(
                        "tx-hash-3",
                        BlockNumber(12),
                        SlotNumber(52),
                        "block-hash-3"
                    )
                ],
                result
            );
        }
    }

    #[tokio::test]
    async fn remove_rolled_back_chain_data_and_block_range_removes_transactions_above_slot_number()
    {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();

        store
            .remove_rolled_chain_data_and_block_range(SlotNumber(51))
            .await
            .unwrap();

        let remaining = store.get_all_block_with_txs().await;
        assert_eq!(blocks_with_tx[0..=1].to_vec(), remaining);
    }

    #[tokio::test]
    async fn remove_rolled_back_chain_data_and_block_range_removes_block_ranges_above_highest_remaining_block()
     {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockRange::LENGTH * 2,
                SlotNumber(100),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockRange::LENGTH * 4,
                SlotNumber(200),
                vec!["tx-hash-3"],
            ),
        ];
        let block_ranges_roots = vec![
            (
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            ),
            (
                BlockRange::from_block_number(BlockRange::LENGTH),
                MKTreeNode::from_hex("BBBB").unwrap(),
            ),
            (
                BlockRange::from_block_number(BlockRange::LENGTH * 2),
                MKTreeNode::from_hex("CCCC").unwrap(),
            ),
            (
                BlockRange::from_block_number(BlockRange::LENGTH * 3),
                MKTreeNode::from_hex("DDDD").unwrap(),
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .with_block_range_roots(&block_ranges_roots)
            .with_legacy_block_range_roots(&block_ranges_roots)
            .build();

        // Rollback to slot 100 (keeps transactions with slot <= 100)
        store
            .remove_rolled_chain_data_and_block_range(SlotNumber(100))
            .await
            .unwrap();

        let remaining_transactions = store.get_all_transactions().await;
        assert_eq!(2, remaining_transactions.len());

        // Block ranges with start < highest remaining block number (BlockRange::LENGTH * 2) should remain
        let remaining_ranges = store.get_all_block_ranges().await;
        assert_eq!(
            vec![
                BlockRange::from_block_number(BlockNumber(0)),
                BlockRange::from_block_number(BlockRange::LENGTH),
            ],
            remaining_ranges
        );

        // Legacy Block ranges with start < highest remaining block number (BlockRange::LENGTH * 2) should remain
        let remaining_legacy_ranges = store.get_all_legacy_block_ranges().await;
        assert_eq!(
            vec![
                BlockRange::from_block_number(BlockNumber(0)),
                BlockRange::from_block_number(BlockRange::LENGTH),
            ],
            remaining_legacy_ranges
        );
    }

    #[tokio::test]
    async fn remove_rolled_back_chain_data_and_block_range_with_no_remaining_transactions() {
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&[CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            )])
            .with_legacy_block_range_roots(&[(
                BlockRange::from_block_number(BlockNumber(0)),
                MKTreeNode::from_hex("AAAA").unwrap(),
            )])
            .build();

        // Rollback to slot before all transactions
        store
            .remove_rolled_chain_data_and_block_range(SlotNumber(40))
            .await
            .unwrap();

        assert!(store.get_all_block_with_txs().await.is_empty());
        assert!(store.get_all_transactions().await.is_empty());
        assert!(store.get_all_block_range_root().await.is_empty());
        assert!(store.get_all_legacy_block_range_root().await.is_empty());
    }

    #[tokio::test]
    async fn remove_rolled_back_chain_data_and_block_range_keeps_transactions_with_equal_slot_number()
     {
        let blocks_with_tx = vec![
            CardanoBlockWithTransactions::new(
                "block-hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx-hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx-hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block-hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx-hash-3"],
            ),
        ];
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&blocks_with_tx)
            .build();

        store
            .remove_rolled_chain_data_and_block_range(SlotNumber(50))
            .await
            .unwrap();

        let remaining = store.get_all_block_with_txs().await;
        assert_eq!(blocks_with_tx[0..1].to_vec(), remaining);
    }

    mod retrieve_blocks_range_root {
        use super::*;

        fn test_data_set() -> Vec<(BlockRange, MKTreeNode)> {
            vec![
                (
                    BlockRange::from_block_number(BlockNumber(15)),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockNumber(30)),
                    MKTreeNode::from_hex("BBBB").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockNumber(45)),
                    MKTreeNode::from_hex("CCCC").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockNumber(60)),
                    MKTreeNode::from_hex("CCCC").unwrap(),
                ),
            ]
        }

        #[tokio::test]
        async fn returns_empty_when_store_empty() {
            let store = Arc::new(InMemoryChainDataStore::builder().build());
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let iter = retriever
                .retrieve_block_range_roots(BlockNumber(u64::MAX))
                .await
                .unwrap();
            assert_eq!(
                Vec::<(BlockRange, MKTreeNode)>::new(),
                iter.collect::<Vec<_>>()
            );
        }

        #[tokio::test]
        async fn up_to_above_all_stored_ranges_returns_all() {
            let store = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_block_range_roots(&test_data_set())
                    .build(),
            );
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let stored_ranges: Vec<(BlockRange, MKTreeNode)> = retriever
                .retrieve_block_range_roots(BlockNumber(u64::MAX))
                .await
                .unwrap()
                .collect();
            assert_eq!(&test_data_set(), &stored_ranges);
        }

        #[tokio::test]
        async fn up_to_below_start_of_the_first_range_returns_nothing() {
            let store = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_block_range_roots(&test_data_set())
                    .build(),
            );
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let stored_ranges: Vec<(BlockRange, MKTreeNode)> = retriever
                .retrieve_block_range_roots(BlockNumber(10))
                .await
                .unwrap()
                .collect();
            assert_eq!(&Vec::<(BlockRange, MKTreeNode)>::new(), &stored_ranges);
        }

        #[tokio::test]
        async fn up_to_right_below_start_of_the_third_range_returns_the_first_two_ranges() {
            let store = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_block_range_roots(&test_data_set())
                    .build(),
            );
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let stored_ranges: Vec<(BlockRange, MKTreeNode)> = retriever
                .retrieve_block_range_roots(BlockNumber(44))
                .await
                .unwrap()
                .collect();
            assert_eq!(&test_data_set()[0..2], &stored_ranges);
        }

        #[tokio::test]
        async fn up_to_right_at_start_of_the_third_range_returns_the_first_two_ranges() {
            let store = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_block_range_roots(&test_data_set())
                    .build(),
            );
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let stored_ranges: Vec<(BlockRange, MKTreeNode)> = retriever
                .retrieve_block_range_roots(BlockNumber(45))
                .await
                .unwrap()
                .collect();
            assert_eq!(&test_data_set()[0..2], &stored_ranges);
        }

        #[tokio::test]
        async fn up_to_right_after_start_of_the_third_range_returns_the_first_three_ranges() {
            let store = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_block_range_roots(&test_data_set())
                    .build(),
            );
            let retriever = store.clone() as Arc<dyn BlockRangeRootRetriever<MKTreeStoreInMemory>>;

            let stored_ranges: Vec<(BlockRange, MKTreeNode)> = retriever
                .retrieve_block_range_roots(BlockNumber(46))
                .await
                .unwrap()
                .collect();
            assert_eq!(&test_data_set()[0..3], &stored_ranges);
        }
    }

    #[tokio::test]
    async fn get_chain_points_by_block_numbers_returns_the_stored_blocks_only() {
        let store = InMemoryChainDataStore::builder()
            .with_blocks_and_transactions(&[
                CardanoBlockWithTransactions::new(
                    "hash-10",
                    BlockNumber(10),
                    SlotNumber(100),
                    Vec::<String>::new(),
                ),
                CardanoBlockWithTransactions::new(
                    "hash-11",
                    BlockNumber(11),
                    SlotNumber(110),
                    Vec::<String>::new(),
                ),
            ])
            .build();

        let chain_points = store
            .get_chain_points_by_block_numbers(vec![BlockNumber(11), BlockNumber(99)])
            .await
            .unwrap();

        assert_eq!(
            vec![ChainPoint::new(SlotNumber(110), BlockNumber(11), "hash-11")],
            chain_points
        );
    }
}
