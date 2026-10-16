use std::collections::BTreeSet;
use std::ops::Range;

use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::crypto_helper::MKTreeNode;
use mithril_common::entities::{
    BlockNumber, BlockRange, CardanoBlockTransactionMkTreeNode, CardanoBlockWithTransactions,
    CardanoTransaction, ChainPoint, SlotNumber,
};

/// Cardano chain data importer
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ChainDataImporter: Send + Sync {
    /// Import data stored on the chain up to the given beacon into the system
    async fn import(&self, up_to_beacon: BlockNumber) -> StdResult<()>;
}

/// Cardano chain data store
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ChainDataStore: Send + Sync {
    /// Get the highest known transaction beacon
    async fn get_highest_beacon(&self) -> StdResult<Option<ChainPoint>>;

    /// Get the chain points of the stored blocks with the given block numbers
    async fn get_chain_points_by_block_numbers(
        &self,
        block_numbers: Vec<BlockNumber>,
    ) -> StdResult<Vec<ChainPoint>>;

    /// Get the highest stored block range root bounds
    async fn get_highest_block_range(&self) -> StdResult<Option<BlockRange>>;

    /// Get the highest stored legacy block range root bounds
    async fn get_highest_legacy_block_range(&self) -> StdResult<Option<BlockRange>>;

    /// Store the given blocks and their transactions
    async fn store_blocks_and_transactions(
        &self,
        block_with_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()>;

    /// Get all blocks and transactions in an interval of blocks
    async fn get_blocks_and_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>>;

    /// Get transactions in an interval of blocks
    async fn get_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<Vec<CardanoTransaction>>;

    /// Store list of block ranges with their corresponding merkle root
    async fn store_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()>;

    /// Store list of legacy block ranges with their corresponding merkle root
    async fn store_legacy_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()>;

    /// Remove blocks, transactions, and block range roots that are in a rolled-back fork
    ///
    /// * Remove blocks and transactions with a slot number strictly greater than the given slot number
    /// * Remove block range roots that have lower bound range strictly above the given slot number
    async fn remove_rolled_chain_data_and_block_range(
        &self,
        slot_number: SlotNumber,
    ) -> StdResult<()>;

    /// Tell the store to perform optimization tasks if it needs them to improve its query performances
    async fn optimize(&self) -> StdResult<()>;
}
