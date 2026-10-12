use std::collections::BTreeSet;
use std::ops::{Deref, Range};
use std::sync::Arc;

use mithril_cardano_node_chain::chain_importer::{
    ChainDataPruner, ChainDataStore, HighestStoredBlockNumberGetter,
};
use mithril_common::StdResult;
use mithril_common::crypto_helper::{MKTreeNode, MKTreeStorer};
use mithril_common::entities::{
    BlockNumber, BlockRange, CardanoBlockTransactionMkTreeNode, CardanoBlockWithTransactions,
    CardanoTransaction, ChainPoint, SlotNumber,
};
use mithril_common::signable_builder::{BlockRangeRootRetriever, LegacyBlockRangeRootRetriever};
use mithril_persistence::database::repository::CardanoTransactionRepository;
use mithril_persistence::sqlite::SqliteConnectionPool;

/// Wrapper around [CardanoTransactionRepository] to allow traits implementations
pub struct SignerCardanoChainDataRepository {
    inner: CardanoTransactionRepository,
}

impl SignerCardanoChainDataRepository {
    /// Instantiate a new `SignerCardanoChainDataRepository`
    pub fn new(connection_pool: Arc<SqliteConnectionPool>) -> Self {
        Self {
            inner: CardanoTransactionRepository::new(connection_pool),
        }
    }
}

impl Deref for SignerCardanoChainDataRepository {
    type Target = CardanoTransactionRepository;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[async_trait::async_trait]
impl ChainDataStore for SignerCardanoChainDataRepository {
    async fn get_highest_beacon(&self) -> StdResult<Option<ChainPoint>> {
        self.inner.get_transaction_highest_chain_point().await
    }

    async fn get_chain_points_by_block_numbers(
        &self,
        block_numbers: Vec<BlockNumber>,
    ) -> StdResult<Vec<ChainPoint>> {
        self.inner.get_chain_points_by_block_numbers(block_numbers).await
    }

    async fn get_highest_block_range(&self) -> StdResult<Option<BlockRange>> {
        let record = self.inner.retrieve_highest_block_range_root().await?;
        Ok(record.map(|record| record.range))
    }

    async fn get_highest_legacy_block_range(&self) -> StdResult<Option<BlockRange>> {
        let record = self.inner.retrieve_highest_legacy_block_range_root().await?;
        Ok(record.map(|record| record.range))
    }

    async fn store_blocks_and_transactions(
        &self,
        block_with_transactions: Vec<CardanoBlockWithTransactions>,
    ) -> StdResult<()> {
        self.inner
            .store_blocks_and_transactions(block_with_transactions)
            .await
    }

    async fn get_blocks_and_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
        let records = self.inner.get_blocks_with_transactions_in_range_blocks(range).await?;
        Ok(records.into_iter().flat_map(|b| b.into_mk_tree_nodes()).collect())
    }

    async fn get_transactions_in_range(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<Vec<CardanoTransaction>> {
        self.get_transactions_in_range_blocks(range).await.map(|v| {
            v.into_iter()
                .map(|record| record.into())
                .collect::<Vec<CardanoTransaction>>()
        })
    }

    async fn store_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()> {
        if !block_ranges.is_empty() {
            self.inner.create_block_range_roots(block_ranges).await?;
        }
        Ok(())
    }

    async fn store_legacy_block_range_roots(
        &self,
        block_ranges: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()> {
        if !block_ranges.is_empty() {
            self.inner.create_legacy_block_range_roots(block_ranges).await?;
        }
        Ok(())
    }

    async fn remove_rolled_chain_data_and_block_range(
        &self,
        slot_number: SlotNumber,
    ) -> StdResult<()> {
        self.inner
            .remove_rolled_back_blocks_transactions_and_block_range_by_slot_number(slot_number)
            .await
    }

    async fn optimize(&self) -> StdResult<()> {
        self.inner.optimize()
    }
}

#[async_trait::async_trait]
impl ChainDataPruner for SignerCardanoChainDataRepository {
    async fn prune(&self, number_of_blocks_to_keep: BlockNumber) -> StdResult<()> {
        self.inner.prune_transaction(number_of_blocks_to_keep).await
    }
}

#[async_trait::async_trait]
impl HighestStoredBlockNumberGetter for SignerCardanoChainDataRepository {
    async fn get(&self) -> StdResult<Option<BlockNumber>> {
        let highest_chain_point = self.inner.get_transaction_highest_chain_point().await?;
        Ok(highest_chain_point.map(|c| c.block_number))
    }
}

#[async_trait::async_trait]
impl<S: MKTreeStorer> LegacyBlockRangeRootRetriever<S> for SignerCardanoChainDataRepository {
    async fn retrieve_block_range_roots<'a>(
        &'a self,
        up_to_beacon: BlockNumber,
    ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>> {
        self.inner.retrieve_legacy_block_range_roots_up_to(up_to_beacon).await
    }
}

#[async_trait::async_trait]
impl<S: MKTreeStorer> BlockRangeRootRetriever<S> for SignerCardanoChainDataRepository {
    async fn retrieve_block_range_roots<'a>(
        &'a self,
        up_to_beacon: BlockNumber,
    ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>> {
        self.inner.retrieve_block_range_roots_up_to(up_to_beacon).await
    }

    async fn retrieve_block_ranges_nodes(
        &self,
        range: Range<BlockNumber>,
    ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
        self.inner
            .get_blocks_with_transactions_in_range_blocks(range)
            .await
            .map(|v| v.into_iter().flat_map(|b| b.into_mk_tree_nodes()).collect())
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::chain_importer::{CardanoChainDataImporter, ChainDataImporter};
    use mithril_cardano_node_chain::entities::ScannedBlock;
    use mithril_cardano_node_chain::test::double::DumbBlockScanner;
    use mithril_common::temp_dir_create;

    use crate::database::test_helper::cardano_tx_db_connection_builder;
    use crate::test::TestLogger;

    use super::*;

    fn into_transactions(blocks: &[ScannedBlock]) -> Vec<CardanoTransaction> {
        blocks.iter().flat_map(|b| b.clone().into_transactions()).collect()
    }

    #[tokio::test]
    async fn importing_twice_starting_with_nothing_in_a_real_db_should_yield_transactions_in_same_order()
     {
        let temp_db = temp_dir_create!().join("test.db");
        let blocks = vec![
            ScannedBlock::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(15),
                vec!["tx_hash-1", "tx_hash-2"],
            ),
            ScannedBlock::new(
                "block_hash-2",
                BlockNumber(20),
                SlotNumber(25),
                vec!["tx_hash-3", "tx_hash-4"],
            ),
        ];
        let up_to_block_number = BlockNumber(1000);
        let transactions = into_transactions(&blocks);

        let (importer, repository) = {
            let connection_pool =
                Arc::new(cardano_tx_db_connection_builder(&temp_db).build_pool(1).unwrap());
            let repository = Arc::new(SignerCardanoChainDataRepository::new(connection_pool));
            let importer = CardanoChainDataImporter::new(
                Arc::new(DumbBlockScanner::new().forwards(vec![blocks.clone()])),
                repository.clone(),
                TestLogger::stdout(),
            );
            (importer, repository)
        };

        importer
            .import(up_to_block_number)
            .await
            .expect("Transactions Importer should succeed");
        let cold_imported_transactions = repository.get_all().await.unwrap();

        importer
            .import(up_to_block_number)
            .await
            .expect("Transactions Importer should succeed");
        let warm_imported_transactions = repository.get_all().await.unwrap();

        assert_eq!(transactions, cold_imported_transactions);
        assert_eq!(cold_imported_transactions, warm_imported_transactions);
    }
}
