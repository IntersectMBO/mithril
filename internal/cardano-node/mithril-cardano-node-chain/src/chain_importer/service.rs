use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use slog::Logger;
use tokio::{runtime::Handle, task};

use mithril_common::StdResult;
use mithril_common::entities::BlockNumber;
use mithril_common::logging::LoggerExtensions;

use crate::chain_importer::block_ranges_importer::BlockRangeImporter;
use crate::chain_importer::blocks_and_transactions_importer::BlocksTransactionsImporter;
use crate::chain_importer::{ChainDataImporter, ChainDataStore};
use crate::chain_scanner::BlockScanner;

/// Import and store Cardano chain data (transactions, blocks) and aggregate them into Merkle trees
/// for Mithril certificate generation and proof verification.
#[derive(Clone)]
pub struct CardanoChainDataImporter {
    blocks_transactions_importer: BlocksTransactionsImporter,
    block_ranges_importer: BlockRangeImporter,
    transaction_store: Arc<dyn ChainDataStore>,
}

impl CardanoChainDataImporter {
    /// Constructor
    pub fn new(
        block_scanner: Arc<dyn BlockScanner>,
        transaction_store: Arc<dyn ChainDataStore>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new_with_component_name::<Self>();
        Self {
            blocks_transactions_importer: BlocksTransactionsImporter::new(
                block_scanner,
                transaction_store.clone(),
                logger.clone(),
            ),
            block_ranges_importer: BlockRangeImporter::new(
                transaction_store.clone(),
                logger.clone(),
            ),
            transaction_store,
        }
    }
}

#[async_trait]
impl ChainDataImporter for CardanoChainDataImporter {
    async fn import(&self, up_to_beacon: BlockNumber) -> StdResult<()> {
        let importer = self.clone();
        task::spawn_blocking(move || {
            Handle::current().block_on(async move {
                importer.blocks_transactions_importer.run(up_to_beacon).await?;
                importer.transaction_store.optimize().await?;
                importer.block_ranges_importer.run(up_to_beacon).await?;
                importer.block_ranges_importer.run_legacy(up_to_beacon).await?;
                importer.transaction_store.optimize().await?;
                Ok(())
            })
        })
        .await
        .with_context(|| "ChainDataImporter - worker thread crashed")?
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use mithril_common::crypto_helper::MKTreeNode;
    use mithril_common::entities::{
        BlockRange, CardanoBlockTransactionMkTreeNode, CardanoBlockWithTransactions,
        CardanoTransaction, ChainPoint, SlotNumber,
    };

    use crate::test::TestLogger;
    use crate::test::double::DumbBlockScanner;

    use super::*;

    #[tokio::test]
    async fn test_import_is_non_blocking() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        static MAX_COUNTER: usize = 25;
        static WAIT_TIME: u64 = 50;

        // Use a local set to ensure the counter-task is not dispatched on a different thread
        let local = task::LocalSet::new();
        local
            .run_until(async {
                let importer = CardanoChainDataImporter::new(
                    Arc::new(DumbBlockScanner::new()),
                    Arc::new(BlockingRepository {
                        wait_time: Duration::from_millis(WAIT_TIME),
                    }),
                    TestLogger::stdout(),
                );

                let importer_future = importer.import(BlockNumber(100));
                let counter_task = task::spawn_local(async {
                    while COUNTER.load(std::sync::atomic::Ordering::SeqCst) < MAX_COUNTER {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
                importer_future.await.unwrap();

                counter_task.abort();
            })
            .await;

        assert_eq!(
            MAX_COUNTER,
            COUNTER.load(std::sync::atomic::Ordering::SeqCst)
        );

        struct BlockingRepository {
            wait_time: Duration,
        }

        impl BlockingRepository {
            fn block_thread(&self) {
                std::thread::sleep(self.wait_time);
            }
        }

        #[async_trait]
        impl ChainDataStore for BlockingRepository {
            async fn get_highest_beacon(&self) -> StdResult<Option<ChainPoint>> {
                self.block_thread();
                Ok(None)
            }

            async fn get_chain_points_by_block_numbers(
                &self,
                _: Vec<BlockNumber>,
            ) -> StdResult<Vec<ChainPoint>> {
                self.block_thread();
                Ok(vec![])
            }

            async fn get_highest_block_range(&self) -> StdResult<Option<BlockRange>> {
                self.block_thread();
                Ok(None)
            }

            async fn get_highest_legacy_block_range(&self) -> StdResult<Option<BlockRange>> {
                self.block_thread();
                Ok(None)
            }

            async fn store_blocks_and_transactions(
                &self,
                _: Vec<CardanoBlockWithTransactions>,
            ) -> StdResult<()> {
                self.block_thread();
                Ok(())
            }

            async fn get_blocks_and_transactions_in_range(
                &self,
                _range: Range<BlockNumber>,
            ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
                self.block_thread();
                Ok(BTreeSet::new())
            }

            async fn get_transactions_in_range(
                &self,
                _: Range<BlockNumber>,
            ) -> StdResult<Vec<CardanoTransaction>> {
                self.block_thread();
                Ok(vec![])
            }

            async fn store_block_range_roots(
                &self,
                _block_ranges: Vec<(BlockRange, MKTreeNode)>,
            ) -> StdResult<()> {
                self.block_thread();
                Ok(())
            }

            async fn store_legacy_block_range_roots(
                &self,
                _: Vec<(BlockRange, MKTreeNode)>,
            ) -> StdResult<()> {
                self.block_thread();
                Ok(())
            }

            async fn remove_rolled_chain_data_and_block_range(
                &self,
                _: SlotNumber,
            ) -> StdResult<()> {
                self.block_thread();
                Ok(())
            }

            async fn optimize(&self) -> StdResult<()> {
                self.block_thread();
                Ok(())
            }
        }
    }
}
