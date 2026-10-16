use std::cmp::Reverse;
use std::iter;
use std::sync::Arc;

use slog::{Logger, debug};
use tokio::sync::Mutex;

use mithril_common::StdResult;
use mithril_common::entities::{
    BlockNumber, BlockNumberOffset, CardanoBlockWithTransactions, ChainPoint,
};

use crate::chain_importer::ChainDataStore;
use crate::chain_scanner::{BlockScanner, ChainScannedBlocks};
use crate::entities::RawCardanoPoint;

/// Internal component responsible for importing blocks and transactions from the blockchain into a store.
#[derive(Clone)]
pub(crate) struct BlocksTransactionsImporter {
    block_scanner: Arc<dyn BlockScanner>,
    transaction_store: Arc<dyn ChainDataStore>,
    last_polled_point: Arc<Mutex<Option<RawCardanoPoint>>>,
    logger: Logger,
}

impl BlocksTransactionsImporter {
    /// Security parameter of Cardano, the deepest rollback a node can make
    const SECURITY_PARAMETER: u64 = 2160;

    pub fn new(
        block_scanner: Arc<dyn BlockScanner>,
        transaction_store: Arc<dyn ChainDataStore>,
        logger: Logger,
    ) -> Self {
        Self {
            block_scanner,
            transaction_store,
            last_polled_point: Arc::new(Mutex::new(None)),
            logger,
        }
    }

    pub async fn run(&self, up_to_beacon: BlockNumber) -> StdResult<()> {
        let highest_stored_beacon = self.transaction_store.get_highest_beacon().await?;

        if highest_stored_beacon
            .as_ref()
            .is_some_and(|f| f.block_number >= up_to_beacon)
        {
            debug!(
                self.logger,
                "No need to retrieve Cardano blocks and transactions, the database is up to date for block_number '{up_to_beacon}'",
            );

            Ok(())
        } else {
            let candidates = self.intersection_candidates(&highest_stored_beacon).await?;
            debug!(
                self.logger, "Retrieving Cardano blocks and transactions until block numbered '{up_to_beacon}'";
                "starting_slot_number" => ?candidates.first().map(|c| c.slot_number),
                "highest_stored_block_number" => ?highest_stored_beacon.as_ref().map(|c| c.block_number),
            );

            self.parse_and_store_block_and_transactions_not_imported_yet(candidates, up_to_beacon)
                .await
        }
    }

    async fn start_point(
        &self,
        highest_stored_chain_point: &Option<ChainPoint>,
    ) -> StdResult<Option<RawCardanoPoint>> {
        let last_polled_point = self.last_polled_point.lock().await.clone();
        if last_polled_point.is_none() {
            debug!(
                self.logger,
                "No last polled point available, falling back to the highest stored chain point"
            );
        }

        Ok(last_polled_point.or(highest_stored_chain_point.as_ref().map(RawCardanoPoint::from)))
    }

    /// Candidates of the intersection with the chain of the node, most recent first: the start
    /// point and the stored blocks at Fibonacci depths below the highest stored block, so that the
    /// chain is intersected at the most recent of them the node knows and the store rolled back to
    /// it when the blocks above were rolled back
    async fn intersection_candidates(
        &self,
        highest_stored_chain_point: &Option<ChainPoint>,
    ) -> StdResult<Vec<RawCardanoPoint>> {
        let mut candidates: Vec<RawCardanoPoint> = self
            .start_point(highest_stored_chain_point)
            .await?
            .into_iter()
            .collect();
        if let Some(highest_stored_chain_point) = highest_stored_chain_point {
            let block_numbers =
                Self::intersection_candidate_depths(highest_stored_chain_point.block_number)
                    .into_iter()
                    .map(|depth| highest_stored_chain_point.block_number - BlockNumberOffset(depth))
                    .collect();
            let stored_chain_points = self
                .transaction_store
                .get_chain_points_by_block_numbers(block_numbers)
                .await?;
            candidates.extend(stored_chain_points.iter().map(RawCardanoPoint::from));
        }
        candidates.sort_by_key(|candidate| {
            (Reverse(candidate.slot_number), candidate.block_hash.clone())
        });
        candidates.dedup();

        Ok(candidates)
    }

    /// Depths below the highest stored block of the stored candidates, the strategy of the
    /// chain-sync client of the Cardano node: 0, the Fibonacci numbers below the limit, then the
    /// limit, which is the security parameter or the highest stored block number when smaller
    fn intersection_candidate_depths(highest_stored_block_number: BlockNumber) -> Vec<u64> {
        let limit = Self::SECURITY_PARAMETER.min(*highest_stored_block_number);
        let fibonacci = iter::successors(Some((1u64, 2u64)), |(current, next)| {
            Some((*next, current + next))
        })
        .map(|(current, _next)| current);
        iter::once(0)
            .chain(fibonacci.take_while(|depth| *depth < limit))
            .chain((limit > 0).then_some(limit))
            .collect()
    }

    async fn parse_and_store_block_and_transactions_not_imported_yet(
        &self,
        candidates: Vec<RawCardanoPoint>,
        until: BlockNumber,
    ) -> StdResult<()> {
        let mut streamer = self.block_scanner.scan(candidates, until).await?;

        while let Some(blocks) = streamer.poll_next().await? {
            match blocks {
                ChainScannedBlocks::RollForwards(forward_blocks) => {
                    let parsed_blocks_with_transactions: Vec<CardanoBlockWithTransactions> =
                        forward_blocks.into_iter().map(Into::into).collect();

                    self.transaction_store
                        .store_blocks_and_transactions(parsed_blocks_with_transactions)
                        .await?;
                }
                ChainScannedBlocks::RollBackward(slot_number) => {
                    self.transaction_store
                        .remove_rolled_chain_data_and_block_range(slot_number)
                        .await?;
                }
            }

            if let Some(point) = streamer.last_polled_point() {
                *self.last_polled_point.lock().await = Some(point);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::MKTreeNode;
    use mithril_common::entities::{BlockRange, SlotNumber};

    use crate::chain_scanner::MockBlockScanner;
    use crate::entities::ScannedBlock;
    use crate::test::TestLogger;
    use crate::test::double::{DumbBlockScanner, DumbBlockStreamer, InMemoryChainDataStore};

    use super::*;

    impl BlocksTransactionsImporter {
        fn new_for_test(
            scanner: Arc<dyn BlockScanner>,
            transaction_store: Arc<dyn ChainDataStore>,
        ) -> Self {
            Self::new(scanner, transaction_store, TestLogger::stdout())
        }
    }

    fn into_blocks_with_transactions(blocks: &[ScannedBlock]) -> Vec<CardanoBlockWithTransactions> {
        blocks.iter().map(|b| b.clone().into()).collect()
    }

    mod store_blocks_and_transactions {
        use super::*;

        #[tokio::test]
        async fn store_blocks_that_do_not_have_transactions() {
            let repository = Arc::new(InMemoryChainDataStore::default());
            let up_to_block_number = BlockNumber(1000);

            let scanner = DumbBlockScanner::new().forwards(vec![vec![ScannedBlock::new(
                "block_hash-1",
                BlockNumber(10),
                SlotNumber(15),
                Vec::<String>::new(),
            )]]);
            let importer =
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone());

            importer.run(up_to_block_number).await.unwrap();

            let stored_transactions = repository.get_all_block_with_txs().await;
            assert_eq!(
                vec![CardanoBlockWithTransactions::new(
                    hex::encode("block_hash-1"),
                    BlockNumber(10),
                    SlotNumber(15),
                    Vec::<String>::new()
                )],
                stored_transactions
            );
        }

        #[tokio::test]
        async fn if_nothing_stored_parse_and_store_all_blocks_and_transactions() {
            let repository = Arc::new(InMemoryChainDataStore::default());

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
            let expected_blocks_with_transactions = into_blocks_with_transactions(&blocks);
            let up_to_block_number = BlockNumber(1000);

            let importer = {
                let mut scanner_mock = MockBlockScanner::new();
                scanner_mock
                    .expect_scan()
                    .withf(move |candidates, until| {
                        candidates.is_empty() && until == up_to_block_number
                    })
                    .return_once(move |_, _| {
                        Ok(Box::new(DumbBlockStreamer::new().forwards(vec![blocks])))
                    });
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner_mock), repository.clone())
            };

            importer.run(up_to_block_number).await.unwrap();

            let stored_transactions = repository.get_all_block_with_txs().await;
            assert_eq!(expected_blocks_with_transactions, stored_transactions);
        }

        #[tokio::test]
        async fn if_all_blocks_and_transactions_are_stored_nothing_is_parsed_and_stored() {
            let up_to_block_number = BlockNumber(12);
            let last_block = vec![CardanoBlockWithTransactions::new(
                hex::encode("block_hash-3"),
                BlockNumber(30),
                SlotNumber(35),
                vec!["tx-20"],
            )];
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&last_block)
                    .build(),
            );
            let scanner = DumbBlockScanner::new().forwards(vec![vec![
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
            ]]);

            let importer =
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone());

            importer.run(up_to_block_number).await.unwrap();

            let blocks_with_txs = repository.get_all_block_with_txs().await;
            assert_eq!(last_block, blocks_with_txs);
        }

        #[tokio::test]
        async fn if_half_blocks_and_transactions_are_already_stored_the_other_half_is_parsed_and_stored()
         {
            let highest_stored_chain_point = ChainPoint::new(
                SlotNumber(134),
                BlockNumber(10),
                hex::encode("block_hash-1"),
            );
            let stored_block = ScannedBlock::new(
                hex::decode(&highest_stored_chain_point.block_hash).unwrap(),
                highest_stored_chain_point.block_number,
                highest_stored_chain_point.slot_number,
                vec!["tx_hash-1", "tx_hash-2"],
            );
            let to_store_block = ScannedBlock::new(
                "block_hash-2",
                BlockNumber(20),
                SlotNumber(229),
                vec!["tx_hash-3", "tx_hash-4"],
            );
            let existing_blocks = vec![stored_block.clone()];
            let expected_blocks_with_transactions =
                into_blocks_with_transactions(&[stored_block.clone(), to_store_block.clone()]);
            let up_to_block_number = BlockNumber(22);

            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&existing_blocks)
                    .build(),
            );

            let importer = {
                let scanned_blocks = vec![to_store_block.clone()];
                let mut scanner_mock = MockBlockScanner::new();
                scanner_mock
                    .expect_scan()
                    .withf(move |candidates, until| {
                        candidates == &vec![highest_stored_chain_point.clone().into()]
                            && *until == up_to_block_number
                    })
                    .return_once(move |_, _| {
                        Ok(Box::new(
                            DumbBlockStreamer::new().forwards(vec![scanned_blocks]),
                        ))
                    })
                    .once();
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner_mock), repository.clone())
            };

            importer.run(up_to_block_number).await.unwrap();

            let stored_blocks_with_transactions = repository.get_all_block_with_txs().await;
            assert_eq!(
                expected_blocks_with_transactions,
                stored_blocks_with_transactions
            );
        }
    }

    mod transactions_import_start_point {
        use anyhow::anyhow;
        use async_trait::async_trait;

        use crate::chain_scanner::BlockStreamer;

        use super::*;

        /// Streams one batch of blocks, then fails on the next poll as a streamer which lost its
        /// connection to the node does.
        struct BlockStreamerFailingAfterOneBatch {
            batch: Option<Vec<ScannedBlock>>,
            last_polled_point: Option<RawCardanoPoint>,
        }

        impl BlockStreamerFailingAfterOneBatch {
            fn new(batch: Vec<ScannedBlock>) -> Self {
                Self {
                    batch: Some(batch),
                    last_polled_point: None,
                }
            }
        }

        #[async_trait]
        impl BlockStreamer for BlockStreamerFailingAfterOneBatch {
            async fn poll_next(&mut self) -> StdResult<Option<ChainScannedBlocks>> {
                match self.batch.take() {
                    Some(batch) => {
                        self.last_polled_point = batch.last().map(RawCardanoPoint::from);
                        Ok(Some(ChainScannedBlocks::RollForwards(batch)))
                    }
                    None => Err(anyhow!("Connection to the node lost")),
                }
            }

            fn last_polled_point(&self) -> Option<RawCardanoPoint> {
                self.last_polled_point.clone()
            }
        }

        async fn importer_with_last_polled_point(
            last_polled_point: Option<RawCardanoPoint>,
        ) -> BlocksTransactionsImporter {
            let repository = Arc::new(InMemoryChainDataStore::default());

            BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(last_polled_point)),
                ..BlocksTransactionsImporter::new_for_test(
                    Arc::new(DumbBlockScanner::new()),
                    repository,
                )
            }
        }

        #[tokio::test]
        async fn cloning_keep_last_polled_point() {
            let importer = importer_with_last_polled_point(Some(RawCardanoPoint::new(
                SlotNumber(15),
                "block_hash-1",
            )))
            .await;

            let cloned_importer = importer.clone();
            let start_point = cloned_importer.start_point(&None).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(15), "block_hash-1")),
                start_point
            );
        }

        #[tokio::test]
        async fn none_if_nothing_stored_nor_scanned() {
            let importer = importer_with_last_polled_point(None).await;
            let highest_stored_block_number = None;

            let start_point = importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(None, start_point);
        }

        #[tokio::test]
        async fn start_at_last_stored_point_if_nothing_scanned() {
            let importer = importer_with_last_polled_point(None).await;
            let highest_stored_block_number = Some(ChainPoint::new(
                SlotNumber(25),
                BlockNumber(20),
                hex::encode("block_hash-2"),
            ));

            let start_point = importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(25), "block_hash-2")),
                start_point
            );
        }

        #[tokio::test]
        async fn start_at_last_scanned_point_when_nothing_stored() {
            let importer = importer_with_last_polled_point(Some(RawCardanoPoint::new(
                SlotNumber(15),
                "block_hash-1",
            )))
            .await;
            let highest_stored_block_number = None;

            let start_point = importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(15), "block_hash-1")),
                start_point
            );
        }

        #[tokio::test]
        async fn start_at_last_scanned_point_even_if_something_stored() {
            let importer = importer_with_last_polled_point(Some(RawCardanoPoint::new(
                SlotNumber(15),
                "block_hash-1",
            )))
            .await;
            let highest_stored_block_number = Some(ChainPoint::new(
                SlotNumber(25),
                BlockNumber(20),
                hex::encode("block_hash-2"),
            ));

            let start_point = importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(15), "block_hash-1")),
                start_point
            );
        }

        #[tokio::test]
        async fn importing_transactions_update_start_point_even_if_no_transactions_are_found() {
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(None)),
                ..BlocksTransactionsImporter::new_for_test(
                    Arc::new(
                        DumbBlockScanner::new()
                            .forwards(vec![vec![ScannedBlock::new(
                                "block_hash-1",
                                BlockNumber(10),
                                SlotNumber(15),
                                Vec::<&str>::new(),
                            )]])
                            .last_polled_point(Some(RawCardanoPoint::new(
                                SlotNumber(25),
                                "block_hash-2",
                            ))),
                    ),
                    Arc::new(InMemoryChainDataStore::default()),
                )
            };
            let highest_stored_block_number = None;

            let start_point_before_import =
                importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(None, start_point_before_import);

            importer.run(BlockNumber(1000)).await.unwrap();

            let start_point_after_import =
                importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(25), "block_hash-2")),
                start_point_after_import
            );
        }

        #[tokio::test]
        async fn importing_transactions_dont_update_start_point_if_streamer_did_nothing() {
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(Some(RawCardanoPoint::new(
                    SlotNumber(15),
                    "block_hash-1",
                )))),
                ..BlocksTransactionsImporter::new_for_test(
                    Arc::new(DumbBlockScanner::new()),
                    Arc::new(InMemoryChainDataStore::default()),
                )
            };
            let highest_stored_block_number = None;

            importer.run(BlockNumber(1000)).await.unwrap();

            let start_point_after_import =
                importer.start_point(&highest_stored_block_number).await.unwrap();
            assert_eq!(
                Some(RawCardanoPoint::new(SlotNumber(15), "block_hash-1")),
                start_point_after_import
            );
        }

        #[tokio::test]
        async fn a_failed_run_leaves_the_start_point_at_the_highest_committed_block() {
            // The run starts at block 11. The streamer delivers the fork block F12, which is
            // committed to the store, then fails:
            //
            //   poll 1 -> RollForwards([F12])    committed to the store
            //   poll 2 -> error                   the run fails
            //
            // The next run must start at F12, the highest committed block, not at block 11:
            // the node never rolls back a block it did not deliver in the session of that run,
            // so a run intersecting at block 11 would keep F12 beside the canonical blocks.
            let start_point_at_block_11 = RawCardanoPoint::new(SlotNumber(110), "hash-11");
            let fork_block_12 = ScannedBlock::new(
                "hash-fork-12",
                BlockNumber(12),
                SlotNumber(120),
                Vec::<&str>::new(),
            );
            let streamer: Box<dyn BlockStreamer> =
                Box::new(BlockStreamerFailingAfterOneBatch::new(vec![
                    fork_block_12.clone(),
                ]));
            let mut scanner = MockBlockScanner::new();
            scanner.expect_scan().return_once(move |_, _| Ok(streamer));
            let repository = Arc::new(InMemoryChainDataStore::default());
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(Some(start_point_at_block_11))),
                ..BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone())
            };

            importer
                .run(BlockNumber(1000))
                .await
                .expect_err("The run should fail with the streamer");

            assert_eq!(
                vec![CardanoBlockWithTransactions::from(fork_block_12.clone())],
                repository.get_all_block_with_txs().await
            );
            assert_eq!(
                Some(RawCardanoPoint::from(&fork_block_12)),
                importer.start_point(&None).await.unwrap()
            );
        }
    }

    mod transactions_import_from_a_rolled_back_start_point {
        use anyhow::anyhow;
        use async_trait::async_trait;

        use crate::chain_scanner::{BlockStreamer, CardanoBlockScanner};
        use crate::entities::ChainBlockNextAction;
        use crate::test::double::FakeChainReader;

        use super::*;

        /// Scans a known chain as the node, the chain reader and the streamer do: streams a
        /// rollback to the first candidate on the chain when it is not the first candidate, then
        /// the blocks after it, and fails when no candidate is on the chain.
        struct KnownChainBlockScanner {
            chain: Vec<ScannedBlock>,
        }

        #[async_trait]
        impl BlockScanner for KnownChainBlockScanner {
            async fn scan(
                &self,
                candidates: Vec<RawCardanoPoint>,
                until: BlockNumber,
            ) -> StdResult<Box<dyn BlockStreamer>> {
                let intersection = candidates.iter().find_map(|candidate| {
                    self.chain
                        .iter()
                        .position(|block| RawCardanoPoint::from(block) == *candidate)
                });
                let mut streamer = DumbBlockStreamer::new();
                let first_block_after_intersection = match (candidates.first(), intersection) {
                    (None, _) => 0,
                    (Some(_), None) => {
                        return Err(anyhow!(
                            "No intersection found for the candidates {candidates:?}"
                        ));
                    }
                    (Some(start_point), Some(position)) => {
                        let intersection_block = &self.chain[position];
                        if RawCardanoPoint::from(intersection_block) != *start_point {
                            streamer = streamer.rollback(ChainPoint::new(
                                intersection_block.slot_number,
                                intersection_block.block_number,
                                hex::encode(&intersection_block.block_hash),
                            ));
                        }
                        position + 1
                    }
                };
                let blocks: Vec<ScannedBlock> = self.chain[first_block_after_intersection..]
                    .iter()
                    .filter(|block| block.block_number <= until)
                    .cloned()
                    .collect();
                let last_polled_point = blocks.last().map(RawCardanoPoint::from);

                Ok(Box::new(
                    streamer
                        .forwards(vec![blocks])
                        .set_last_polled_point(last_polled_point),
                ))
            }
        }

        fn stored_blocks_from_10_to_20() -> Vec<ScannedBlock> {
            (10..=20)
                .map(|block_number| {
                    ScannedBlock::new(
                        format!("hash-{block_number}"),
                        BlockNumber(block_number),
                        SlotNumber(block_number * 10),
                        Vec::<&str>::new(),
                    )
                })
                .collect()
        }

        fn point_of_block(blocks: &[ScannedBlock], block_number: u64) -> RawCardanoPoint {
            let block = blocks
                .iter()
                .find(|block| block.block_number == BlockNumber(block_number))
                .unwrap();
            RawCardanoPoint::from(block)
        }

        fn points_of_blocks(
            blocks: &[ScannedBlock],
            block_numbers: &[u64],
        ) -> Vec<RawCardanoPoint> {
            block_numbers
                .iter()
                .map(|block_number| point_of_block(blocks, *block_number))
                .collect()
        }

        fn scanner_expecting_candidates(
            expected_candidates: Vec<RawCardanoPoint>,
        ) -> MockBlockScanner {
            let mut scanner = MockBlockScanner::new();
            scanner
                .expect_scan()
                .withf(move |candidates, _| *candidates == expected_candidates)
                .return_once(|_, _| Ok(Box::new(DumbBlockStreamer::new())));
            scanner
        }

        #[test]
        fn the_candidate_depths_are_the_fibonacci_offsets_of_the_cardano_node_up_to_the_security_parameter()
         {
            assert_eq!(
                vec![
                    0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2160
                ],
                BlocksTransactionsImporter::intersection_candidate_depths(BlockNumber(10_000))
            );
        }

        #[test]
        fn the_candidate_depths_end_at_the_highest_stored_block_number_when_the_store_is_shorter() {
            assert_eq!(
                vec![0, 1, 2, 3, 5, 8, 13, 20],
                BlocksTransactionsImporter::intersection_candidate_depths(BlockNumber(20))
            );
        }

        #[test]
        fn the_candidate_depths_hold_no_duplicate_at_the_boundaries() {
            assert_eq!(
                vec![0],
                BlocksTransactionsImporter::intersection_candidate_depths(BlockNumber(0))
            );
            assert_eq!(
                vec![0, 1],
                BlocksTransactionsImporter::intersection_candidate_depths(BlockNumber(1))
            );
            assert_eq!(
                vec![0, 1, 2, 3, 5, 8, 13],
                BlocksTransactionsImporter::intersection_candidate_depths(BlockNumber(13))
            );
        }

        #[tokio::test]
        async fn the_candidates_are_the_start_point_and_the_stored_blocks_at_fibonacci_depths_most_recent_first()
         {
            let stored_blocks = stored_blocks_from_10_to_20();
            let scanner = scanner_expecting_candidates(points_of_blocks(
                &stored_blocks,
                &[20, 19, 18, 17, 15, 12],
            ));
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&stored_blocks)
                    .build(),
            );
            let importer = BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository);

            importer.run(BlockNumber(1000)).await.unwrap();
        }

        #[tokio::test]
        async fn a_start_point_below_the_highest_stored_block_is_ordered_among_the_stored_candidates()
         {
            let stored_blocks = stored_blocks_from_10_to_20();
            let scanner = scanner_expecting_candidates(points_of_blocks(
                &stored_blocks,
                &[20, 19, 18, 17, 16, 15, 12],
            ));
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&stored_blocks)
                    .build(),
            );
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(Some(point_of_block(&stored_blocks, 16)))),
                ..BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository)
            };

            importer.run(BlockNumber(1000)).await.unwrap();
        }

        #[tokio::test]
        async fn a_run_from_a_rolled_back_start_point_resumes_from_the_last_stored_block_on_the_chain()
         {
            // The previous run stored the block 11 and the fork block F12, which is the start point
            // of this run. The node has since switched to the canonical chain:
            //
            //   11 -> F12             fork, abandoned
            //   11 -> C12 -> C13      canonical chain
            //
            // The node finds no intersection at F12. The run must intersect the chain at block 11,
            // the last stored block on the chain, replace F12 with the canonical blocks and leave
            // the start point of the next run at C13:
            //
            //   store before the run -> 11, F12
            //   store after the run  -> 11, C12, C13
            let block_11 = ScannedBlock::new(
                "hash-11",
                BlockNumber(11),
                SlotNumber(110),
                Vec::<&str>::new(),
            );
            let fork_block_12 = ScannedBlock::new(
                "hash-fork-12",
                BlockNumber(12),
                SlotNumber(120),
                Vec::<&str>::new(),
            );
            let canonical_block_12 = ScannedBlock::new(
                "hash-canonical-12",
                BlockNumber(12),
                SlotNumber(121),
                Vec::<&str>::new(),
            );
            let canonical_block_13 = ScannedBlock::new(
                "hash-canonical-13",
                BlockNumber(13),
                SlotNumber(130),
                Vec::<&str>::new(),
            );
            let scanner = KnownChainBlockScanner {
                chain: vec![
                    block_11.clone(),
                    canonical_block_12.clone(),
                    canonical_block_13.clone(),
                ],
            };
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&[block_11.clone(), fork_block_12.clone()])
                    .build(),
            );
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(Some(RawCardanoPoint::from(
                    &fork_block_12,
                )))),
                ..BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone())
            };

            importer
                .run(BlockNumber(1000))
                .await
                .expect("The run should recover from a start point rolled back by the node");

            assert_eq!(
                into_blocks_with_transactions(&[
                    block_11,
                    canonical_block_12,
                    canonical_block_13.clone()
                ]),
                repository.get_all_block_with_txs().await
            );
            assert_eq!(
                Some(RawCardanoPoint::from(&canonical_block_13)),
                importer.start_point(&None).await.unwrap()
            );
        }

        #[tokio::test]
        async fn a_rollback_to_an_older_candidate_streamed_by_the_reader_is_applied_before_the_canonical_blocks()
         {
            let block_11 = ScannedBlock::new(
                "hash-11",
                BlockNumber(11),
                SlotNumber(110),
                Vec::<&str>::new(),
            );
            let fork_block_12 = ScannedBlock::new(
                "hash-fork-12",
                BlockNumber(12),
                SlotNumber(120),
                Vec::<&str>::new(),
            );
            let canonical_block_12 = ScannedBlock::new(
                "hash-canonical-12",
                BlockNumber(12),
                SlotNumber(121),
                Vec::<&str>::new(),
            );
            let canonical_block_13 = ScannedBlock::new(
                "hash-canonical-13",
                BlockNumber(13),
                SlotNumber(130),
                Vec::<&str>::new(),
            );
            let chain_reader = Arc::new(Mutex::new(FakeChainReader::new(vec![
                ChainBlockNextAction::RollBackward {
                    rollback_point: RawCardanoPoint::from(&block_11),
                },
                ChainBlockNextAction::RollForward {
                    parsed_block: canonical_block_12.clone(),
                },
                ChainBlockNextAction::RollForward {
                    parsed_block: canonical_block_13.clone(),
                },
            ])));
            let scanner = CardanoBlockScanner::new(chain_reader, 100, TestLogger::stdout());
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(&[block_11.clone(), fork_block_12.clone()])
                    .build(),
            );
            let importer = BlocksTransactionsImporter {
                last_polled_point: Arc::new(Mutex::new(Some(RawCardanoPoint::from(
                    &fork_block_12,
                )))),
                ..BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone())
            };

            importer.run(BlockNumber(1000)).await.unwrap();

            assert_eq!(
                into_blocks_with_transactions(&[
                    block_11,
                    canonical_block_12,
                    canonical_block_13.clone()
                ]),
                repository.get_all_block_with_txs().await
            );
            assert_eq!(
                Some(RawCardanoPoint::from(&canonical_block_13)),
                importer.start_point(&None).await.unwrap()
            );
        }
    }

    mod chain_data_rollback {
        use super::*;

        #[tokio::test]
        async fn when_rollbackward_should_remove_transactions() {
            let expected_remaining_block_with_transactions =
                vec![CardanoBlockWithTransactions::new(
                    hex::encode("block_hash-130"),
                    BlockNumber(130),
                    SlotNumber(5),
                    vec!["tx_hash-6", "tx_hash-7"],
                )];
            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_blocks_and_transactions(
                        &[
                            expected_remaining_block_with_transactions.clone(),
                            vec![CardanoBlockWithTransactions::new(
                                hex::encode("block_hash-131"),
                                BlockNumber(131),
                                SlotNumber(10),
                                vec!["tx_hash-8", "tx_hash-9", "tx_hash-10"],
                            )],
                        ]
                        .concat(),
                    )
                    .build(),
            );

            let chain_point = ChainPoint::new(
                SlotNumber(5),
                BlockNumber(130),
                hex::encode("block_hash-130"),
            );
            let scanner = DumbBlockScanner::new().backward(chain_point);

            let importer =
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone());

            importer.run(BlockNumber(3000)).await.unwrap();

            let stored_blocks_with_transactions = repository.get_all_block_with_txs().await;
            assert_eq!(
                expected_remaining_block_with_transactions,
                stored_blocks_with_transactions
            );
        }

        #[tokio::test]
        async fn when_rollbackward_should_remove_block_ranges() {
            let expected_remaining_block_ranges = vec![
                BlockRange::from_block_number(BlockNumber(0)),
                BlockRange::from_block_number(BlockRange::LENGTH),
                BlockRange::from_block_number(BlockRange::LENGTH * 2),
            ];

            let repository = Arc::new(
                InMemoryChainDataStore::builder()
                    .with_legacy_block_range_roots(
                        &[
                            expected_remaining_block_ranges.clone(),
                            vec![
                                BlockRange::from_block_number(BlockRange::LENGTH * 3),
                                BlockRange::from_block_number(BlockRange::LENGTH * 4),
                                BlockRange::from_block_number(BlockRange::LENGTH * 5),
                            ],
                        ]
                        .concat()
                        .into_iter()
                        .map(|b| (b, MKTreeNode::from_hex("AAAA").unwrap()))
                        .collect::<Vec<_>>(),
                    )
                    .with_blocks_and_transactions(&[CardanoBlockWithTransactions::new(
                        hex::encode("block_hash-131"),
                        BlockRange::from_block_number(BlockRange::LENGTH * 3).start,
                        SlotNumber(1),
                        vec!["tx_hash-1", "tx_hash-2", "tx_hash-3"],
                    )])
                    .build(),
            );

            let block_range_roots = repository.get_all_legacy_block_range_root().await;
            assert_eq!(6, block_range_roots.len());

            let chain_point =
                ChainPoint::new(SlotNumber(1), BlockRange::LENGTH * 3, "block_hash-131");
            let scanner = DumbBlockScanner::new().backward(chain_point);

            let importer =
                BlocksTransactionsImporter::new_for_test(Arc::new(scanner), repository.clone());

            importer.run(BlockNumber(3000)).await.unwrap();

            assert_eq!(
                expected_remaining_block_ranges,
                repository.get_all_legacy_block_ranges().await
            );
        }
    }
}
