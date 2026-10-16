use std::ops::Range;
use std::sync::Arc;

use anyhow::Context;

use mithril_common::StdResult;
use mithril_common::crypto_helper::MKTreeNode;
use mithril_common::entities::{
    BlockHash, BlockNumber, BlockRange, CardanoBlockWithTransactions, CardanoTransaction,
    ChainPoint, SlotNumber, TransactionHash,
};

use crate::database::query::{
    DeleteBlockRangeRootQuery, DeleteCardanoBlockAndTransactionQuery,
    DeleteLegacyBlockRangeRootQuery, GetBlockRangeRootQuery, GetCardanoBlockQuery,
    GetCardanoBlockTransactionsQuery, GetCardanoTransactionQuery, GetLegacyBlockRangeRootQuery,
    InsertBlockRangeRootQuery, InsertCardanoBlockQuery, InsertCardanoTransactionQuery,
    InsertLegacyBlockRangeRootQuery,
};
use crate::database::record::{
    BlockRangeRootRecord, CardanoBlockRecord, CardanoBlockTransactionsRecord,
    CardanoTransactionRecord, IntoRecords, StorableCardanoTransactionRecord,
};
use crate::sqlite::{
    ConnectionExtensions, OptimizeMode, SqliteCleaner, SqliteConnection, SqliteConnectionPool,
};

/// ## Cardano transaction repository
///
/// This is a business oriented layer to perform actions on the database through
/// queries.
pub struct CardanoTransactionRepository {
    connection_pool: Arc<SqliteConnectionPool>,
}

impl CardanoTransactionRepository {
    /// Instantiate service
    pub fn new(connection_pool: Arc<SqliteConnectionPool>) -> Self {
        Self { connection_pool }
    }

    /// Perform database optimization (see [SqliteCleaner::optimize] for the applied optimizations)
    pub fn optimize(&self) -> StdResult<()> {
        let connection = self.connection_pool.connection()?;
        SqliteCleaner::optimize(&connection, OptimizeMode::Default)
            .with_context(|| "Failed to optimize database")?;
        self.connection_pool
            .renew_connections()
            .with_context(|| "Failed to renew connection pool")?;

        Ok(())
    }

    /// Return all the [CardanoTransactionRecord]s in the database.
    pub async fn get_all_transactions(&self) -> StdResult<Vec<CardanoTransactionRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetCardanoTransactionQuery::all())
    }

    /// Return all the [CardanoBlockRecord]s in the database.
    pub async fn get_all_blocks(&self) -> StdResult<Vec<CardanoBlockRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetCardanoBlockQuery::all())
    }

    /// Return all the [CardanoTransactionRecord]s in the database where block number is in the
    /// given range.
    pub async fn get_transactions_in_range_blocks(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<Vec<CardanoTransactionRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetCardanoTransactionQuery::between_blocks(range))
    }

    /// Return all the [CardanoBlockTransactionsRecord]s in the database where block number is in the
    /// given range.
    pub async fn get_blocks_with_transactions_in_range_blocks(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<Vec<CardanoBlockTransactionsRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetCardanoBlockTransactionsQuery::between_blocks(range))
    }

    /// Return the [CardanoBlockRecord] for the given block hash.
    pub async fn get_block<T: Into<BlockHash>>(
        &self,
        block_hash: T,
    ) -> StdResult<Option<CardanoBlockRecord>> {
        self.connection_pool
            .connection()?
            .fetch_first(GetCardanoBlockQuery::by_block_hash(&block_hash.into()))
    }

    /// Return the [CardanoTransactionRecord] for the given transaction hash.
    pub async fn get_transaction<T: Into<TransactionHash>>(
        &self,
        transaction_hash: T,
    ) -> StdResult<Option<CardanoTransactionRecord>> {
        self.connection_pool.connection()?.fetch_first(
            GetCardanoTransactionQuery::by_transaction_hash(transaction_hash),
        )
    }

    /// Create new [CardanoBlockRecord] and [StorableCardanoTransactionRecord]s in the database.
    pub async fn create_block_and_transactions(
        &self,
        blocks_with_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()> {
        let connection = self.connection_pool.connection()?;

        self.create_block_and_transactions_with_connection(&connection, blocks_with_transactions)
            .await
    }

    /// Create new [CardanoBlock] and [StorableCardanoTransactionRecord]s in the database.
    async fn create_block_and_transactions_with_connection(
        &self,
        connection: &SqliteConnection,
        blocks_with_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()> {
        if blocks_with_transactions.is_empty() {
            return Ok(());
        }
        let (blocks_records, mut transactions_records) = blocks_with_transactions.into_records();
        connection.apply(InsertCardanoBlockQuery::insert_many(blocks_records)?)?;

        while !transactions_records.is_empty() {
            let chunk: Vec<_> = transactions_records
                .drain(
                    ..transactions_records
                        .len()
                        .min(StorableCardanoTransactionRecord::MAX_PER_INSERT),
                )
                .collect();
            connection.apply(InsertCardanoTransactionQuery::insert_many(chunk)?)?;
        }

        Ok(())
    }

    /// Create new [BlockRangeRootRecord]s in the database.
    pub async fn create_block_range_roots<T: Into<BlockRangeRootRecord>>(
        &self,
        block_ranges: Vec<T>,
    ) -> StdResult<Vec<BlockRangeRootRecord>> {
        let records: Vec<BlockRangeRootRecord> =
            block_ranges.into_iter().map(|tx| tx.into()).collect();
        let connection = self.connection_pool.connection()?;

        connection.fetch_collect(InsertBlockRangeRootQuery::insert_many(records)?)
    }

    /// Create new legacy [BlockRangeRootRecord]s in the database.
    pub async fn create_legacy_block_range_roots<T: Into<BlockRangeRootRecord>>(
        &self,
        block_ranges: Vec<T>,
    ) -> StdResult<Vec<BlockRangeRootRecord>> {
        let records: Vec<BlockRangeRootRecord> =
            block_ranges.into_iter().map(|tx| tx.into()).collect();
        let connection = self.connection_pool.connection()?;

        connection.fetch_collect(InsertLegacyBlockRangeRootQuery::insert_many(records)?)
    }

    /// Get the highest [ChainPoint] of the cardano transactions stored in the database.
    pub async fn get_transaction_highest_chain_point(&self) -> StdResult<Option<ChainPoint>> {
        let first_transaction_with_highest_block_number = self
            .connection_pool
            .connection()?
            .fetch_first(GetCardanoBlockQuery::with_highest_block_number())?;

        Ok(first_transaction_with_highest_block_number.map(|record| {
            ChainPoint::new(record.slot_number, record.block_number, record.block_hash)
        }))
    }

    /// Get the [ChainPoint] of the stored blocks with the given block numbers
    pub async fn get_chain_points_by_block_numbers(
        &self,
        block_numbers: Vec<BlockNumber>,
    ) -> StdResult<Vec<ChainPoint>> {
        let records: Vec<CardanoBlockRecord> = self
            .connection_pool
            .connection()?
            .fetch_collect(GetCardanoBlockQuery::by_block_numbers(block_numbers))?;

        Ok(records
            .into_iter()
            .map(|record| {
                ChainPoint::new(record.slot_number, record.block_number, record.block_hash)
            })
            .collect())
    }

    /// Get the threshold [BlockNumber] to prune the blocks and transactions below.
    ///
    /// To ensure that all new and legacy blocks range roots were computed and stored: This threshold
    /// is the minimum of the highest block number of the block range roots and the highest block
    /// number of the legacy block range roots.
    pub async fn get_prune_blocks_threshold(&self) -> StdResult<Option<BlockNumber>> {
        let highest: Option<i64> = self.connection_pool.connection()?.query_single_cell(
            r#"
select coalesce(min(max_new.highest, max_legacy.highest), max_new.highest, max_legacy.highest)
from (select max(start) as highest from block_range_root) max_new,
     (select max(start) as highest from block_range_root_legacy) max_legacy;"#,
            &[],
        )?;
        highest
            .map(u64::try_from)
            .transpose()
            .map(|num| num.map(BlockNumber))
            .with_context(||
                format!("Integer field max(start) (value={highest:?}) is incompatible with u64 representation.")
            )
    }

    /// Retrieve all the Block Range Roots in database for which their start number is below the given
    /// block number.
    pub async fn retrieve_block_range_roots_up_to(
        &self,
        block_number: BlockNumber,
    ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + '_>> {
        let block_range_roots = self
            .connection_pool
            .connection()?
            .fetch(GetBlockRangeRootQuery::contains_or_below_block_number(
                block_number,
            ))?
            .map(|record| -> (BlockRange, MKTreeNode) { record.into() })
            .collect::<Vec<_>>(); // TODO: remove this collect to return the iterator directly

        Ok(Box::new(block_range_roots.into_iter()))
    }

    /// Retrieve all the legacy Block Range Roots in database for which their start number is below the given
    /// block number.
    pub async fn retrieve_legacy_block_range_roots_up_to(
        &self,
        block_number: BlockNumber,
    ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + '_>> {
        let block_range_roots = self
            .connection_pool
            .connection()?
            .fetch(GetLegacyBlockRangeRootQuery::contains_or_below_block_number(block_number))?
            .map(|record| -> (BlockRange, MKTreeNode) { record.into() })
            .collect::<Vec<_>>(); // TODO: remove this collect to return the iterator directly

        Ok(Box::new(block_range_roots.into_iter()))
    }

    /// Retrieve the block range root with the highest bounds in the database.
    pub async fn retrieve_highest_block_range_root(
        &self,
    ) -> StdResult<Option<BlockRangeRootRecord>> {
        self.connection_pool
            .connection()?
            .fetch_first(GetBlockRangeRootQuery::highest())
    }

    /// Retrieve the legacy block range root with the highest bounds in the database.
    pub async fn retrieve_highest_legacy_block_range_root(
        &self,
    ) -> StdResult<Option<BlockRangeRootRecord>> {
        self.connection_pool
            .connection()?
            .fetch_first(GetLegacyBlockRangeRootQuery::highest())
    }

    /// Retrieve all the [CardanoTransaction] in database.
    pub async fn get_all(&self) -> StdResult<Vec<CardanoTransaction>> {
        let records = self
            .connection_pool
            .connection()?
            .fetch(GetCardanoTransactionQuery::all())?
            .map(|record| record.into())
            .collect();

        Ok(records)
    }

    /// Retrieve all the [BlockRangeRootRecord] in database.
    pub fn get_all_block_range_root(&self) -> StdResult<Vec<BlockRangeRootRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetBlockRangeRootQuery::all())
    }

    /// Retrieve all the legacy [BlockRangeRootRecord] in database.
    pub fn get_all_legacy_block_range_root(&self) -> StdResult<Vec<BlockRangeRootRecord>> {
        self.connection_pool
            .connection()?
            .fetch_collect(GetLegacyBlockRangeRootQuery::all())
    }

    /// Store the given transactions in the database.
    ///
    /// The storage is done in chunks to avoid exceeding sqlite binding limitations.
    pub async fn store_blocks_and_transactions(
        &self,
        blocks_with_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()> {
        let mut remaining_blocks = blocks_with_transactions;

        while !remaining_blocks.is_empty() {
            let connection = self.connection_pool.connection()?;
            let transaction = connection.begin_transaction()?;

            let chunk: Vec<_> = remaining_blocks
                .drain(..remaining_blocks.len().min(CardanoBlockRecord::MAX_PER_INSERT))
                .collect();

            self.create_block_and_transactions_with_connection(&connection, chunk)
                .await
                .with_context(
                    || "CardanoTransactionRepository can not store blocks and transactions",
                )?;

            transaction.commit()?;
        }

        Ok(())
    }

    /// Get the closest block number above a given slot number
    pub async fn get_closest_block_number_above_slot_number(
        &self,
        slot_number: SlotNumber,
    ) -> StdResult<Option<BlockNumber>> {
        let query = GetCardanoBlockQuery::with_highest_block_number_below_slot_number(slot_number);
        let record = self.connection_pool.connection()?.fetch_first(query)?;

        Ok(record.map(|r| r.block_number))
    }

    /// Get the [CardanoTransactionRecord] for the given transaction hashes, up to a block number
    pub async fn get_transaction_by_hashes<T: Into<TransactionHash>>(
        &self,
        hashes: Vec<T>,
        up_to: BlockNumber,
    ) -> StdResult<Vec<CardanoTransactionRecord>> {
        let query = GetCardanoTransactionQuery::by_transaction_hashes(
            hashes.into_iter().map(Into::into).collect(),
            up_to,
        );
        self.connection_pool.connection()?.fetch_collect(query)
    }

    /// Get the [CardanoBlockRecord] for the given block hashes, up to a block number
    pub async fn get_block_by_hashes<T: Into<BlockHash>>(
        &self,
        hashes: Vec<T>,
        up_to: BlockNumber,
    ) -> StdResult<Vec<CardanoBlockRecord>> {
        let query = GetCardanoBlockQuery::by_block_hashes(
            hashes.into_iter().map(Into::into).collect(),
            up_to,
        );
        self.connection_pool.connection()?.fetch_collect(query)
    }

    /// Get the [CardanoTransactionRecord] for the given block ranges.
    pub async fn get_transaction_by_block_ranges(
        &self,
        block_ranges: Vec<BlockRange>,
    ) -> StdResult<Vec<CardanoTransactionRecord>> {
        let mut transactions = vec![];
        // Make one query per block range to optimize throughput as asking multiple block ranges at once
        // made SQLite quickly collapse (see PR #1723)
        for block_range in block_ranges {
            let block_range_transactions: Vec<CardanoTransactionRecord> = self
                .connection_pool
                .connection()?
                .fetch_collect(GetCardanoTransactionQuery::between_blocks(block_range))?;
            transactions.extend(block_range_transactions);
        }

        Ok(transactions)
    }

    /// Get the [CardanoBlockTransactionsRecord] for the given ranges of block numbers
    pub async fn get_blocks_with_transactions_by_ranges_of_block_numbers(
        &self,
        ranges_of_block: Vec<Range<BlockNumber>>,
    ) -> StdResult<Vec<CardanoBlockTransactionsRecord>> {
        let mut blocks_with_transactions = vec![];
        // Make one query per block range to optimize throughput as asking multiple block ranges at once
        // made SQLite quickly collapse (see PR #1723)
        for range in ranges_of_block {
            let block_range_transactions: Vec<CardanoBlockTransactionsRecord> = self
                .connection_pool
                .connection()?
                .fetch_collect(GetCardanoBlockTransactionsQuery::between_blocks(range))?;
            blocks_with_transactions.extend(block_range_transactions);
        }

        Ok(blocks_with_transactions)
    }

    /// Prune the transactions older than the given number of blocks (based on the block range root
    /// stored).
    pub async fn prune_transaction(&self, number_of_blocks_to_keep: BlockNumber) -> StdResult<()> {
        if let Some(highest_block_range_start) = self.get_prune_blocks_threshold().await? {
            let threshold = highest_block_range_start - number_of_blocks_to_keep;
            let query =
                DeleteCardanoBlockAndTransactionQuery::below_block_number_threshold(threshold)?;

            let connection = self.connection_pool.connection()?;
            connection.fetch_first(query)?;
        }

        Ok(())
    }

    /// Remove blocks, transactions, and block range roots that are in a rolled-back fork
    ///
    /// * Remove blocks and transactions with a block number strictly greater than the given block number
    /// * Remove block range roots that have lower bound range strictly above the given block number
    pub async fn remove_rolled_back_transactions_and_block_range_by_block_number(
        &self,
        block_number: BlockNumber,
    ) -> StdResult<()> {
        let connection = self.connection_pool.connection()?;
        let transaction = connection.begin_transaction()?;

        connection.fetch_first(
            DeleteCardanoBlockAndTransactionQuery::above_block_number_threshold(block_number)?,
        )?;
        connection.fetch_first(
            DeleteBlockRangeRootQuery::contains_or_above_block_number_threshold(block_number)?,
        )?;
        connection.fetch_first(
            DeleteLegacyBlockRangeRootQuery::contains_or_above_block_number_threshold(
                block_number,
            )?,
        )?;

        transaction.commit()?;
        Ok(())
    }

    /// Remove blocks, transactions, and block range roots that are in a rolled-back fork
    ///
    /// * Remove blocks and transactions with the closest block number strictly greater than the given slot number if it exists
    /// * Remove block range roots that have lower bound range strictly above the aforementioned block number
    pub async fn remove_rolled_back_blocks_transactions_and_block_range_by_slot_number(
        &self,
        slot_number: SlotNumber,
    ) -> StdResult<()> {
        if let Some(block_number) =
            self.get_closest_block_number_above_slot_number(slot_number).await?
        {
            self.remove_rolled_back_transactions_and_block_range_by_block_number(block_number)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use crate::database::query::GetLegacyBlockRangeRootQuery;
    use crate::database::test_helper::cardano_tx_db_connection_builder;

    use super::*;

    #[tokio::test]
    async fn repository_create_and_get_blocks_and_transactions() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-123",
                    BlockNumber(10),
                    SlotNumber(50),
                    vec!["tx_hash-123", "tx_hash-456"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-789",
                    BlockNumber(11),
                    SlotNumber(51),
                    vec!["tx_hash-789"],
                ),
            ])
            .await
            .unwrap();

        {
            let block_result = repository.get_block("block_hash-123").await.unwrap();
            assert_eq!(
                Some(CardanoBlockRecord {
                    block_hash: "block_hash-123".to_string(),
                    block_number: BlockNumber(10),
                    slot_number: SlotNumber(50),
                }),
                block_result
            );

            let transaction_result = repository.get_transaction("tx_hash-123").await.unwrap();
            assert_eq!(
                Some(CardanoTransactionRecord {
                    transaction_hash: "tx_hash-123".to_string(),
                    block_number: BlockNumber(10),
                    slot_number: SlotNumber(50),
                    block_hash: "block_hash-123".to_string(),
                }),
                transaction_result
            );
        }
        {
            let transaction_result = repository.get_transaction("not-exist").await.unwrap();
            assert_eq!(None, transaction_result);
        }
    }

    #[tokio::test]
    async fn repository_create_and_get_blocks_and_transactions_dont_fail_if_empty_or_no_transactions()
     {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository.create_block_and_transactions(vec![]).await.unwrap();
        repository
            .create_block_and_transactions(vec![CardanoBlockWithTransactions::new(
                "block_hash-10",
                BlockNumber(10),
                SlotNumber(50),
                Vec::<String>::new(),
            )])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn repository_get_transaction_by_hashes() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-10",
                    BlockNumber(10),
                    SlotNumber(50),
                    vec!["tx_hash-123", "tx_hash-456", "tx_hash-789"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-101",
                    BlockNumber(101),
                    SlotNumber(100),
                    vec!["tx_hash-000"],
                ),
            ])
            .await
            .unwrap();

        {
            let transactions = repository
                .get_transaction_by_hashes(vec!["tx_hash-123", "tx_hash-789"], BlockNumber(100))
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoTransactionRecord::new(
                        "tx_hash-123",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                    CardanoTransactionRecord::new(
                        "tx_hash-789",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_transaction_by_hashes(
                    vec!["tx_hash-123", "tx_hash-789", "tx_hash-000"],
                    BlockNumber(100),
                )
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoTransactionRecord::new(
                        "tx_hash-123",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                    CardanoTransactionRecord::new(
                        "tx_hash-789",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_transaction_by_hashes(
                    vec!["tx_hash-123", "tx_hash-789", "tx_hash-000"],
                    BlockNumber(101),
                )
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoTransactionRecord::new(
                        "tx_hash-123",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                    CardanoTransactionRecord::new(
                        "tx_hash-789",
                        BlockNumber(10),
                        SlotNumber(50),
                        "block_hash-10"
                    ),
                    CardanoTransactionRecord::new(
                        "tx_hash-000",
                        BlockNumber(101),
                        SlotNumber(100),
                        "block_hash-101"
                    ),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_transaction_by_hashes(vec!["not-exist".to_string()], BlockNumber(100))
                .await
                .unwrap();

            assert_eq!(Vec::<CardanoTransactionRecord>::new(), transactions);
        }
    }

    #[tokio::test]
    async fn repository_get_block_by_hashes() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-10",
                    BlockNumber(10),
                    SlotNumber(50),
                    vec!["tx_hash-1", "tx_hash-2", "tx_hash-3"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-11",
                    BlockNumber(11),
                    SlotNumber(51),
                    vec!["tx_hash-4", "tx_hash-5"],
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-101",
                    BlockNumber(101),
                    SlotNumber(100),
                    vec!["tx_hash-6"],
                ),
            ])
            .await
            .unwrap();

        {
            let transactions = repository
                .get_block_by_hashes(vec!["block_hash-10", "block_hash-11"], BlockNumber(100))
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoBlockRecord::new("block_hash-10", BlockNumber(10), SlotNumber(50)),
                    CardanoBlockRecord::new("block_hash-11", BlockNumber(11), SlotNumber(51)),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_block_by_hashes(
                    vec!["block_hash-10", "block_hash-11", "block_hash-101"],
                    BlockNumber(100),
                )
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoBlockRecord::new("block_hash-10", BlockNumber(10), SlotNumber(50)),
                    CardanoBlockRecord::new("block_hash-11", BlockNumber(11), SlotNumber(51)),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_block_by_hashes(
                    vec!["block_hash-10", "block_hash-11", "block_hash-101"],
                    BlockNumber(101),
                )
                .await
                .unwrap();

            assert_eq!(
                vec![
                    CardanoBlockRecord::new("block_hash-10", BlockNumber(10), SlotNumber(50)),
                    CardanoBlockRecord::new("block_hash-11", BlockNumber(11), SlotNumber(51)),
                    CardanoBlockRecord::new("block_hash-101", BlockNumber(101), SlotNumber(100)),
                ],
                transactions
            );
        }
        {
            let transactions = repository
                .get_block_by_hashes(vec!["not-exist".to_string()], BlockNumber(100))
                .await
                .unwrap();

            assert_eq!(Vec::<CardanoBlockRecord>::new(), transactions);
        }
    }

    #[tokio::test]
    async fn repository_create_ignore_further_blocks_when_exists() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let base_block = CardanoBlockWithTransactions::new(
            "block_hash-1",
            BlockNumber(10),
            SlotNumber(50),
            vec![""],
        );
        let expected_record: CardanoBlockRecord = base_block.clone().into();

        repository
            .create_block_and_transactions(vec![base_block.clone()])
            .await
            .unwrap();

        // Same block number - ignore changes
        {
            repository
                .create_block_and_transactions(vec![CardanoBlockWithTransactions {
                    block_hash: "block_hash-1-new".to_string(),
                    slot_number: base_block.slot_number + 10,
                    ..base_block.clone()
                }])
                .await
                .unwrap();
            let block_result = repository.get_block("block_hash-1").await.unwrap();

            assert_eq!(Some(expected_record.clone()), block_result);
        }
        // Same slot number - ignore changes
        {
            repository
                .create_block_and_transactions(vec![CardanoBlockWithTransactions {
                    block_hash: "block_hash-1-new".to_string(),
                    block_number: base_block.block_number + 10,
                    ..base_block.clone()
                }])
                .await
                .unwrap();
            let block_result = repository.get_block("block_hash-1").await.unwrap();

            assert_eq!(Some(expected_record.clone()), block_result);
        }
        // Same block hash - ignore changes
        {
            repository
                .create_block_and_transactions(vec![CardanoBlockWithTransactions {
                    block_number: base_block.block_number + 10,
                    slot_number: base_block.slot_number,
                    ..base_block.clone()
                }])
                .await
                .unwrap();
            let block_result = repository.get_block("block_hash-1").await.unwrap();

            assert_eq!(Some(expected_record.clone()), block_result);
        }
    }

    #[tokio::test]
    async fn repository_create_ignore_further_transactions_when_exists() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let base_block_with_txs = CardanoBlockWithTransactions::new(
            "block_hash-1",
            BlockNumber(10),
            SlotNumber(50),
            vec!["tx_hash-1"],
        );

        repository
            .create_block_and_transactions(vec![base_block_with_txs.clone()])
            .await
            .unwrap();
        repository
            .create_block_and_transactions(vec![base_block_with_txs.clone()])
            .await
            .unwrap();
        let transactions_result = repository.get_all().await.unwrap();

        assert_eq!(
            vec![CardanoTransaction::new(
                "tx_hash-1".to_string(),
                BlockNumber(10),
                SlotNumber(50),
                "block_hash-1".to_string(),
            )],
            transactions_result
        );
    }

    #[tokio::test]
    async fn repository_create_blocks_and_transactions_and_get_stored_them_individually() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![CardanoBlockWithTransactions::new(
                "block_hash-123",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-123", "tx_hash-456"],
            )])
            .await
            .unwrap();

        let block_result = repository.get_block("block_hash-123").await.unwrap();
        assert_eq!(
            Some(CardanoBlockRecord {
                block_hash: "block_hash-123".to_string(),
                block_number: BlockNumber(10),
                slot_number: SlotNumber(50),
            }),
            block_result
        );

        let transaction_result = repository.get_transaction("tx_hash-123").await.unwrap();
        assert_eq!(
            Some(CardanoTransactionRecord {
                transaction_hash: "tx_hash-123".to_string(),
                block_number: BlockNumber(10),
                slot_number: SlotNumber(50),
                block_hash: "block_hash-123".to_string(),
            }),
            transaction_result
        );

        let transaction_result = repository.get_transaction("tx_hash-456").await.unwrap();
        assert_eq!(
            Some(CardanoTransactionRecord {
                transaction_hash: "tx_hash-456".to_string(),
                block_number: BlockNumber(10),
                slot_number: SlotNumber(50),
                block_hash: "block_hash-123".to_string(),
            }),
            transaction_result
        );
    }

    #[tokio::test]
    async fn repository_store_blocks_and_transactions_bulk_insert_1_000_blocks_with_500_transactions_per_block()
     {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks_to_insert: Vec<_> = (0..1_000)
            .map(|i| {
                CardanoBlockWithTransactions::new(
                    format!("block_hash-{i}"),
                    BlockNumber(i),
                    SlotNumber(i * 5),
                    (0..500).map(|j| format!("tx_hash-{i}-{j}")).collect(),
                )
            })
            .collect();

        repository
            .store_blocks_and_transactions(blocks_to_insert)
            .await
            .unwrap();

        let all_blocks = repository.get_all_blocks().await.unwrap();
        assert_eq!(1_000, all_blocks.len());
        let all_transactions = repository.get_all_transactions().await.unwrap();
        assert_eq!(1_000 * 500, all_transactions.len());
    }

    #[tokio::test]
    async fn repository_get_all_stored_blocks() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-1",
                    BlockNumber(10),
                    SlotNumber(50),
                    Vec::<String>::new(),
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-2",
                    BlockNumber(11),
                    SlotNumber(51),
                    Vec::<String>::new(),
                ),
            ])
            .await
            .unwrap();

        let transactions_result = repository.get_all_blocks().await.unwrap();
        assert_eq!(
            vec![
                CardanoBlockRecord::new(
                    "block_hash-1".to_string(),
                    BlockNumber(10),
                    SlotNumber(50),
                ),
                CardanoBlockRecord::new(
                    "block_hash-2".to_string(),
                    BlockNumber(11),
                    SlotNumber(51),
                )
            ],
            transactions_result
        )
    }

    #[tokio::test]
    async fn repository_get_all_stored_transactions() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![CardanoBlockWithTransactions::new(
                "block_hash-123",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-123", "tx_hash-456"],
            )])
            .await
            .unwrap();

        let transactions_result = repository.get_all_transactions().await.unwrap();
        assert_eq!(
            vec![
                CardanoTransactionRecord::new(
                    "tx_hash-123".to_string(),
                    BlockNumber(10),
                    SlotNumber(50),
                    "block_hash-123".to_string(),
                ),
                CardanoTransactionRecord::new(
                    "tx_hash-456".to_string(),
                    BlockNumber(10),
                    SlotNumber(50),
                    "block_hash-123".to_string(),
                )
            ],
            transactions_result
        )
    }

    #[tokio::test]
    async fn repository_get_highest_chain_point_without_blocks_in_db() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let highest_beacon = repository.get_transaction_highest_chain_point().await.unwrap();
        assert_eq!(None, highest_beacon);
    }

    #[tokio::test]
    async fn repository_get_highest_chain_point_with_blocks_in_db() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-1",
                    BlockNumber(10),
                    SlotNumber(50),
                    Vec::<String>::new(),
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-2",
                    BlockNumber(100),
                    SlotNumber(150),
                    Vec::<String>::new(),
                ),
            ])
            .await
            .unwrap();

        let highest_beacon = repository.get_transaction_highest_chain_point().await.unwrap();
        assert_eq!(
            Some(ChainPoint::new(
                SlotNumber(150),
                BlockNumber(100),
                "block_hash-2"
            )),
            highest_beacon
        );
    }

    #[tokio::test]
    async fn repository_get_chain_points_by_block_numbers() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        repository
            .create_block_and_transactions(vec![
                CardanoBlockWithTransactions::new(
                    "block_hash-1",
                    BlockNumber(10),
                    SlotNumber(50),
                    Vec::<String>::new(),
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-2",
                    BlockNumber(11),
                    SlotNumber(51),
                    Vec::<String>::new(),
                ),
                CardanoBlockWithTransactions::new(
                    "block_hash-3",
                    BlockNumber(12),
                    SlotNumber(52),
                    Vec::<String>::new(),
                ),
            ])
            .await
            .unwrap();

        let chain_points = repository
            .get_chain_points_by_block_numbers(vec![
                BlockNumber(12),
                BlockNumber(10),
                BlockNumber(99),
            ])
            .await
            .unwrap();

        assert_eq!(
            vec![
                ChainPoint::new(SlotNumber(50), BlockNumber(10), "block_hash-1"),
                ChainPoint::new(SlotNumber(52), BlockNumber(12), "block_hash-3"),
            ],
            chain_points
        );
    }

    #[tokio::test]
    async fn repository_get_transactions_in_range_blocks() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx_hash-3"],
            ),
        ];
        repository
            .create_block_and_transactions(blocks.clone())
            .await
            .unwrap();
        let expected_transactions: Vec<CardanoTransactionRecord> = blocks
            .into_iter()
            .flat_map(|b| b.into_transactions())
            .map(Into::into)
            .collect();

        {
            let transaction_result = repository
                .get_transactions_in_range_blocks(BlockNumber(0)..BlockNumber(10))
                .await
                .unwrap();
            assert_eq!(Vec::<CardanoTransactionRecord>::new(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transactions_in_range_blocks(BlockNumber(13)..BlockNumber(21))
                .await
                .unwrap();
            assert_eq!(Vec::<CardanoTransactionRecord>::new(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transactions_in_range_blocks(BlockNumber(9)..BlockNumber(12))
                .await
                .unwrap();
            assert_eq!(expected_transactions[0..=1].to_vec(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transactions_in_range_blocks(BlockNumber(10)..BlockNumber(13))
                .await
                .unwrap();
            assert_eq!(expected_transactions.clone(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transactions_in_range_blocks(BlockNumber(11)..BlockNumber(14))
                .await
                .unwrap();
            assert_eq!(expected_transactions[1..=2].to_vec(), transaction_result);
        }
    }

    #[tokio::test]
    async fn repository_get_blocks_with_transactions_in_range_blocks() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockNumber(12),
                SlotNumber(52),
                vec!["tx_hash-3"],
            ),
        ];
        repository
            .create_block_and_transactions(blocks.clone())
            .await
            .unwrap();
        let expected_blocks: Vec<CardanoBlockTransactionsRecord> =
            blocks.into_iter().map(Into::into).collect();

        {
            let blocks = repository
                .get_blocks_with_transactions_in_range_blocks(BlockNumber(0)..BlockNumber(10))
                .await
                .unwrap();
            assert_eq!(Vec::<CardanoBlockTransactionsRecord>::new(), blocks);
        }
        {
            let blocks = repository
                .get_blocks_with_transactions_in_range_blocks(BlockNumber(13)..BlockNumber(21))
                .await
                .unwrap();
            assert_eq!(Vec::<CardanoBlockTransactionsRecord>::new(), blocks);
        }
        {
            let blocks = repository
                .get_blocks_with_transactions_in_range_blocks(BlockNumber(9)..BlockNumber(12))
                .await
                .unwrap();
            assert_eq!(expected_blocks[0..=1].to_vec(), blocks);
        }
        {
            let blocks = repository
                .get_blocks_with_transactions_in_range_blocks(BlockNumber(10)..BlockNumber(13))
                .await
                .unwrap();
            assert_eq!(expected_blocks.clone(), blocks);
        }
        {
            let blocks = repository
                .get_blocks_with_transactions_in_range_blocks(BlockNumber(11)..BlockNumber(14))
                .await
                .unwrap();
            assert_eq!(expected_blocks[1..=2].to_vec(), blocks);
        }
    }

    #[tokio::test]
    async fn repository_get_transactions_by_block_ranges() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockNumber(20),
                SlotNumber(52),
                vec!["tx_hash-3"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-4",
                BlockNumber(31),
                SlotNumber(53),
                vec!["tx_hash-4"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-5",
                BlockNumber(35),
                SlotNumber(54),
                vec!["tx_hash-5"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-6",
                BlockNumber(46),
                SlotNumber(55),
                vec!["tx_hash-6"],
            ),
        ];
        repository
            .create_block_and_transactions(blocks.clone())
            .await
            .unwrap();
        let expected_transactions: Vec<CardanoTransactionRecord> = blocks
            .into_iter()
            .flat_map(|b| b.into_transactions())
            .map(Into::into)
            .collect();

        {
            let transaction_result = repository
                .get_transaction_by_block_ranges(vec![BlockRange::from_block_number(BlockNumber(
                    100,
                ))])
                .await
                .unwrap();
            assert_eq!(Vec::<CardanoTransactionRecord>::new(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transaction_by_block_ranges(vec![BlockRange::from_block_number(BlockNumber(
                    0,
                ))])
                .await
                .unwrap();
            assert_eq!(expected_transactions[0..=1].to_vec(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transaction_by_block_ranges(vec![
                    BlockRange::from_block_number(BlockNumber(0)),
                    BlockRange::from_block_number(BlockNumber(15)),
                ])
                .await
                .unwrap();
            assert_eq!(expected_transactions[0..=2].to_vec(), transaction_result);
        }
        {
            let transaction_result = repository
                .get_transaction_by_block_ranges(vec![
                    BlockRange::from_block_number(BlockNumber(0)),
                    BlockRange::from_block_number(BlockNumber(30)),
                ])
                .await
                .unwrap();
            assert_eq!(
                [
                    expected_transactions[0..=1].to_vec(),
                    expected_transactions[3..=4].to_vec()
                ]
                .concat(),
                transaction_result
            );
        }
    }

    #[tokio::test]
    async fn repository_get_blocks_with_transactions_by_ranges_of_block_numbers() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(11),
                SlotNumber(51),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockNumber(20),
                SlotNumber(52),
                vec!["tx_hash-3"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-4",
                BlockNumber(30),
                SlotNumber(53),
                vec!["tx_hash-4"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-5",
                BlockNumber(35),
                SlotNumber(54),
                vec!["tx_hash-5"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-6",
                BlockNumber(46),
                SlotNumber(55),
                vec!["tx_hash-6"],
            ),
        ];
        repository
            .create_block_and_transactions(blocks.clone())
            .await
            .unwrap();
        let expected_blocks: Vec<CardanoBlockTransactionsRecord> =
            blocks.into_iter().map(Into::into).collect();

        // Get for a range higher for which no blocks are stored
        {
            let transaction_result = repository
                .get_blocks_with_transactions_by_ranges_of_block_numbers(vec![
                    BlockNumber(100)..BlockNumber(1000),
                ])
                .await
                .unwrap();
            assert_eq!(
                Vec::<CardanoBlockTransactionsRecord>::new(),
                transaction_result
            );
        }
        // Get for the first 15 blocks
        {
            let transaction_result = repository
                .get_blocks_with_transactions_by_ranges_of_block_numbers(vec![
                    BlockNumber(0)..BlockNumber(15),
                ])
                .await
                .unwrap();
            assert_eq!(expected_blocks[0..=1].to_vec(), transaction_result);
        }
        // Get for two consecutive ranges of 15 blocks
        {
            let transaction_result = repository
                .get_blocks_with_transactions_by_ranges_of_block_numbers(vec![
                    BlockNumber(0)..BlockNumber(15),
                    BlockNumber(15)..BlockNumber(30),
                ])
                .await
                .unwrap();
            assert_eq!(expected_blocks[0..=2].to_vec(), transaction_result);
        }
        // Get for two non-consecutive ranges of 15 blocks
        {
            let transaction_result = repository
                .get_blocks_with_transactions_by_ranges_of_block_numbers(vec![
                    BlockNumber(0)..BlockNumber(15),
                    BlockNumber(30)..BlockNumber(45),
                ])
                .await
                .unwrap();
            assert_eq!(
                [expected_blocks[0..=1].to_vec(), expected_blocks[3..=4].to_vec()].concat(),
                transaction_result
            );
        }
    }

    #[tokio::test]
    async fn repository_get_closest_block_number_by_slot_number() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(100),
                SlotNumber(500),
                Vec::<String>::new(),
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(101),
                SlotNumber(501),
                Vec::<String>::new(),
            ),
        ];
        repository
            .create_block_and_transactions(blocks.clone())
            .await
            .unwrap();

        let transaction_block_number_retrieved = repository
            .get_closest_block_number_above_slot_number(SlotNumber(500))
            .await
            .unwrap();

        assert_eq!(transaction_block_number_retrieved, Some(BlockNumber(100)));
    }

    #[tokio::test]
    async fn repository_store_legacy_block_range() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_legacy_block_range_roots(vec![
                (
                    BlockRange::from_block_number(BlockNumber(0)),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH),
                    MKTreeNode::from_hex("BBBB").unwrap(),
                ),
            ])
            .await
            .unwrap();

        let connection = repository.connection_pool.connection().unwrap();
        let records: Vec<BlockRangeRootRecord> =
            connection.fetch_collect(GetLegacyBlockRangeRootQuery::all()).unwrap();
        assert_eq!(
            vec![
                BlockRangeRootRecord {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
                },
                BlockRangeRootRecord {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
                }
            ],
            records
        );
    }

    #[tokio::test]
    async fn repository_store_legacy_block_range_with_existing_hash_doesnt_erase_existing_data() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let range = BlockRange::from_block_number(BlockNumber(0));

        repository
            .create_legacy_block_range_roots(vec![(
                range.clone(),
                MKTreeNode::from_hex("AAAA").unwrap(),
            )])
            .await
            .unwrap();
        repository
            .create_legacy_block_range_roots(vec![(
                range.clone(),
                MKTreeNode::from_hex("BBBB").unwrap(),
            )])
            .await
            .unwrap();

        let record: Vec<BlockRangeRootRecord> = repository
            .connection_pool
            .connection()
            .unwrap()
            .fetch_collect(GetLegacyBlockRangeRootQuery::all())
            .unwrap();
        assert_eq!(
            vec![BlockRangeRootRecord {
                range,
                merkle_root: MKTreeNode::from_hex("AAAA").unwrap()
            }],
            record
        );
    }

    #[tokio::test]
    async fn repository_retrieve_legacy_block_range_roots_up_to() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let block_range_roots = vec![
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
        ];
        repository
            .create_legacy_block_range_roots(block_range_roots.clone())
            .await
            .unwrap();

        let retrieved_block_ranges = repository
            .retrieve_legacy_block_range_roots_up_to(BlockNumber(45))
            .await
            .unwrap();
        assert_eq!(
            block_range_roots[0..2].to_vec(),
            retrieved_block_ranges.collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn repository_retrieve_highest_legacy_block_range_roots() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let block_range_roots = vec![
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(15)),
                merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
            },
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(30)),
                merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
            },
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(45)),
                merkle_root: MKTreeNode::from_hex("CCCC").unwrap(),
            },
        ];
        repository
            .create_legacy_block_range_roots(block_range_roots.clone())
            .await
            .unwrap();

        let retrieved_block_range =
            repository.retrieve_highest_legacy_block_range_root().await.unwrap();
        assert_eq!(block_range_roots.last().cloned(), retrieved_block_range);
    }

    #[tokio::test]
    async fn repository_store_block_range() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        repository
            .create_block_range_roots(vec![
                (
                    BlockRange::from_block_number(BlockNumber(0)),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH),
                    MKTreeNode::from_hex("BBBB").unwrap(),
                ),
            ])
            .await
            .unwrap();

        let connection = repository.connection_pool.connection().unwrap();
        let records: Vec<BlockRangeRootRecord> =
            connection.fetch_collect(GetBlockRangeRootQuery::all()).unwrap();
        assert_eq!(
            vec![
                BlockRangeRootRecord {
                    range: BlockRange::from_block_number(BlockNumber(0)),
                    merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
                },
                BlockRangeRootRecord {
                    range: BlockRange::from_block_number(BlockRange::LENGTH),
                    merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
                }
            ],
            records
        );
    }

    #[tokio::test]
    async fn repository_store_block_range_with_existing_hash_doesnt_erase_existing_data() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let range = BlockRange::from_block_number(BlockNumber(0));

        repository
            .create_block_range_roots(vec![(range.clone(), MKTreeNode::from_hex("AAAA").unwrap())])
            .await
            .unwrap();
        repository
            .create_block_range_roots(vec![(range.clone(), MKTreeNode::from_hex("BBBB").unwrap())])
            .await
            .unwrap();

        let record: Vec<BlockRangeRootRecord> = repository
            .connection_pool
            .connection()
            .unwrap()
            .fetch_collect(GetBlockRangeRootQuery::all())
            .unwrap();
        assert_eq!(
            vec![BlockRangeRootRecord {
                range,
                merkle_root: MKTreeNode::from_hex("AAAA").unwrap()
            }],
            record
        );
    }

    #[tokio::test]
    async fn repository_retrieve_block_range_roots_up_to() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let block_range_roots = vec![
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
        ];
        repository
            .create_block_range_roots(block_range_roots.clone())
            .await
            .unwrap();

        let retrieved_block_ranges = repository
            .retrieve_block_range_roots_up_to(BlockNumber(45))
            .await
            .unwrap();
        assert_eq!(
            block_range_roots[0..2].to_vec(),
            retrieved_block_ranges.collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn repository_retrieve_highest_block_range_roots() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));
        let block_range_roots = vec![
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(15)),
                merkle_root: MKTreeNode::from_hex("AAAA").unwrap(),
            },
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(30)),
                merkle_root: MKTreeNode::from_hex("BBBB").unwrap(),
            },
            BlockRangeRootRecord {
                range: BlockRange::from_block_number(BlockNumber(45)),
                merkle_root: MKTreeNode::from_hex("CCCC").unwrap(),
            },
        ];
        repository
            .create_block_range_roots(block_range_roots.clone())
            .await
            .unwrap();

        let retrieved_block_range = repository.retrieve_highest_block_range_root().await.unwrap();
        assert_eq!(block_range_roots.last().cloned(), retrieved_block_range);
    }

    #[tokio::test]
    async fn repository_prune_blocks_and_transactions() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockNumber(24),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockNumber(25),
                SlotNumber(51),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockNumber(26),
                SlotNumber(52),
                vec!["tx_hash-3", "tx_hash-4"],
            ),
        ];
        repository.create_block_and_transactions(blocks).await.unwrap();
        // Use by 'prune_transaction' to get the block_range of the highest block number
        repository
            .create_legacy_block_range_roots(vec![(
                BlockRange::from_block_number(BlockNumber(45)),
                MKTreeNode::from_hex("BBBB").unwrap(),
            )])
            .await
            .unwrap();

        let stored_transactions = repository.get_all_transactions().await.unwrap();
        assert_eq!(4, stored_transactions.len());
        let stored_blocks = repository.get_all_blocks().await.unwrap();
        assert_eq!(3, stored_blocks.len());

        // Pruning with a number of block to keep greater than the highest block range start should
        // do nothing.
        repository.prune_transaction(BlockNumber(10_000_000)).await.unwrap();
        let stored_transactions = repository.get_all_transactions().await.unwrap();
        assert_eq!(4, stored_transactions.len());
        let stored_blocks = repository.get_all_blocks().await.unwrap();
        assert_eq!(3, stored_blocks.len());

        // Since the highest block range start is 45, pruning with 20 should remove transactions
        // with a block number strictly below 25.
        repository.prune_transaction(BlockNumber(20)).await.unwrap();
        let transaction_result = repository
            .get_transactions_in_range_blocks(BlockNumber(0)..BlockNumber(25))
            .await
            .unwrap();
        assert_eq!(Vec::<CardanoTransactionRecord>::new(), transaction_result);

        let transaction_result = repository
            .get_transactions_in_range_blocks(BlockNumber(25)..BlockNumber(1000))
            .await
            .unwrap();
        assert_eq!(3, transaction_result.len());

        let stored_blocks = repository.get_all_blocks().await.unwrap();
        assert_eq!(2, stored_blocks.len());
    }

    #[tokio::test]
    async fn get_prune_blocks_threshold() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        // Nothing stored
        {
            let highest = repository.get_prune_blocks_threshold().await.unwrap();
            assert_eq!(None, highest);
        }
        // Add two block range roots in the "new" table but none in the "legacy"; select the highest of the two in the "new" table
        {
            repository
                .create_block_range_roots(vec![
                    (
                        BlockRange::from_block_number(BlockNumber(45)),
                        MKTreeNode::from_hex("AAAA").unwrap(),
                    ),
                    (
                        BlockRange::from_block_number(BlockNumber(60)),
                        MKTreeNode::from_hex("BBBB").unwrap(),
                    ),
                ])
                .await
                .unwrap();
            let highest = repository.get_prune_blocks_threshold().await.unwrap();
            assert_eq!(Some(BlockNumber(60)), highest);
        }
        // Add a first block range in the "legacy" table, but below than existing in the "new" table; the highest should be the new block range
        {
            repository
                .create_legacy_block_range_roots(vec![(
                    BlockRange::from_block_number(BlockNumber(30)),
                    MKTreeNode::from_hex("DDDD").unwrap(),
                )])
                .await
                .unwrap();

            let highest = repository.get_prune_blocks_threshold().await.unwrap();
            assert_eq!(Some(BlockNumber(30)), highest);
        }
        // Add a second block range in the "legacy" table, but higher than existing in the "new" table; the highest should be change back to the new block range
        {
            repository
                .create_legacy_block_range_roots(vec![(
                    BlockRange::from_block_number(BlockNumber(75)),
                    MKTreeNode::from_hex("CCCC").unwrap(),
                )])
                .await
                .unwrap();

            let highest = repository.get_prune_blocks_threshold().await.unwrap();
            assert_eq!(Some(BlockNumber(60)), highest);
        }
    }

    #[tokio::test]
    async fn remove_blocks_transactions_and_block_ranges_greater_than_given_block_number() {
        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-1",
                BlockRange::LENGTH,
                SlotNumber(50),
                vec!["tx_hash-1", "tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-2",
                BlockRange::LENGTH * 3,
                SlotNumber(51),
                vec!["tx_hash-3", "tx_hash-4"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-3",
                BlockRange::LENGTH * 3 + 1,
                SlotNumber(52),
                vec!["tx_hash-5", "tx_hash-6"],
            ),
        ];
        repository.create_block_and_transactions(blocks).await.unwrap();
        repository
            .create_legacy_block_range_roots(vec![
                (
                    BlockRange::from_block_number(BlockRange::LENGTH),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH * 2),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH * 3),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
            ])
            .await
            .unwrap();
        repository
            .create_block_range_roots(vec![
                (
                    BlockRange::from_block_number(BlockNumber(0)),
                    MKTreeNode::from_hex("9999").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH * 2),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
                (
                    BlockRange::from_block_number(BlockRange::LENGTH * 3),
                    MKTreeNode::from_hex("AAAA").unwrap(),
                ),
            ])
            .await
            .unwrap();

        repository
            .remove_rolled_back_transactions_and_block_range_by_block_number(BlockRange::LENGTH * 3)
            .await
            .unwrap();
        assert_eq!(4, repository.get_all_transactions().await.unwrap().len());
        assert_eq!(
            2,
            repository.get_all_legacy_block_range_root().unwrap().len()
        );
        assert_eq!(3, repository.get_all_block_range_root().unwrap().len());
        assert_eq!(2, repository.get_all_blocks().await.unwrap().len());
    }

    #[tokio::test]
    async fn remove_rolled_back_blocks_transactions_and_block_range_by_slot_number() {
        fn transaction_record(
            block_number: BlockNumber,
            slot_number: SlotNumber,
            tx_hash: &str,
        ) -> CardanoTransactionRecord {
            CardanoTransactionRecord::new(
                tx_hash,
                block_number,
                slot_number,
                format!("block_hash-{block_number}"),
            )
        }

        let temp_dir = temp_dir_create!();
        let repository = CardanoTransactionRepository::new(Arc::new(
            cardano_tx_db_connection_builder(&temp_dir).build_pool(1).unwrap(),
        ));

        let blocks = vec![
            CardanoBlockWithTransactions::new(
                "block_hash-10",
                BlockNumber(10),
                SlotNumber(50),
                vec!["tx_hash-1"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-13",
                BlockNumber(13),
                SlotNumber(52),
                vec!["tx_hash-2"],
            ),
            CardanoBlockWithTransactions::new(
                "block_hash-101",
                BlockNumber(101),
                SlotNumber(100),
                vec!["tx_hash-3", "tx_hash-4"],
            ),
        ];
        repository.create_block_and_transactions(blocks).await.unwrap();

        {
            repository
                .remove_rolled_back_blocks_transactions_and_block_range_by_slot_number(SlotNumber(
                    110,
                ))
                .await
                .expect("Failed to remove rolled back transactions");

            let transactions = repository.get_all_transactions().await.unwrap();
            assert_eq!(
                vec![
                    transaction_record(BlockNumber(10), SlotNumber(50), "tx_hash-1"),
                    transaction_record(BlockNumber(13), SlotNumber(52), "tx_hash-2"),
                    transaction_record(BlockNumber(101), SlotNumber(100), "tx_hash-3"),
                    transaction_record(BlockNumber(101), SlotNumber(100), "tx_hash-4"),
                ],
                transactions
            );
        }

        {
            repository
                .remove_rolled_back_blocks_transactions_and_block_range_by_slot_number(SlotNumber(
                    53,
                ))
                .await
                .expect("Failed to remove rolled back transactions");

            let transactions = repository.get_all_transactions().await.unwrap();
            assert_eq!(
                vec![
                    transaction_record(BlockNumber(10), SlotNumber(50), "tx_hash-1"),
                    transaction_record(BlockNumber(13), SlotNumber(52), "tx_hash-2"),
                ],
                transactions
            );
        }

        {
            repository
                .remove_rolled_back_blocks_transactions_and_block_range_by_slot_number(SlotNumber(
                    51,
                ))
                .await
                .expect("Failed to remove rolled back transactions");

            let transactions = repository.get_all_transactions().await.unwrap();
            assert_eq!(
                vec![transaction_record(BlockNumber(10), SlotNumber(50), "tx_hash-1")],
                transactions
            );
        }
    }
}
