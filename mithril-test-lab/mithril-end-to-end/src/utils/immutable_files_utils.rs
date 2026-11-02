use anyhow::anyhow;
use rand::seq::SliceRandom;
use std::collections::BTreeSet;
use std::path::Path;

use mithril_common::StdResult;
use pallas_hardano::storage::immutable::read_blocks;
use pallas_traverse::MultiEraBlock;

use crate::devnet::Devnet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardanoBlockTransactions {
    pub block_hash: String,
    pub transaction_hashes: Vec<String>,
    /// Hashes of the sub-transactions nested in the transactions of the block (Dijkstra era)
    pub sub_transaction_hashes: Vec<String>,
}

impl CardanoBlockTransactions {
    /// Lists the top-level transactions and their sub-transactions of a decoded block
    pub fn from_block(block: &MultiEraBlock) -> Self {
        let transactions = block.txs();

        Self {
            block_hash: block.hash().to_string(),
            transaction_hashes: transactions.iter().map(|tx| tx.hash().to_string()).collect(),
            sub_transaction_hashes: transactions
                .iter()
                .flat_map(|tx| tx.sub_transactions())
                .map(|sub_transaction| sub_transaction.hash().to_string())
                .collect(),
        }
    }
}

pub fn retrieve_blocks_transactions_from_immutable_files(
    immutables_dir_path: &Path,
) -> StdResult<Vec<CardanoBlockTransactions>> {
    let chunk = read_blocks(immutables_dir_path)?;
    let mut block_transaction_list: Vec<CardanoBlockTransactions> = Vec::new();
    for block in chunk {
        let block = block?;
        let decoded_block = MultiEraBlock::decode(&block)?;

        block_transaction_list.push(CardanoBlockTransactions::from_block(&decoded_block));
    }
    Ok(block_transaction_list)
}

fn randomly_take<T: Clone>(items: &[T], count: usize) -> Vec<T> {
    let mut items = items.to_vec();
    items.shuffle(&mut rand::rng());
    items.into_iter().take(count).collect()
}

pub fn randomly_take_transactions_hashes(
    blocks_transactions: &[CardanoBlockTransactions],
    count: usize,
) -> Vec<String> {
    randomly_take(
        &blocks_transactions
            .iter()
            .flat_map(|bt| bt.transaction_hashes.clone())
            .collect::<Vec<_>>(),
        count,
    )
}

/// Takes at most `count` sub-transaction hashes at random from the blocks, which a devnet started in the Dijkstra era must provide
pub fn randomly_take_sub_transactions_hashes(
    blocks_transactions: &[CardanoBlockTransactions],
    cardano_node_version: &semver::Version,
    cardano_hard_fork_latest_era_at_epoch: u16,
    count: usize,
) -> StdResult<Vec<String>> {
    let devnet_starts_in_dijkstra =
        Devnet::runs_dijkstra(cardano_node_version) && cardano_hard_fork_latest_era_at_epoch == 0;
    let no_sub_transaction = blocks_transactions
        .iter()
        .all(|bt| bt.sub_transaction_hashes.is_empty());
    if devnet_starts_in_dijkstra && no_sub_transaction {
        return Err(anyhow!(
            "No sub-transaction found in the immutable files of a Dijkstra devnet (cardano-node {cardano_node_version})"
        ));
    }

    Ok(randomly_take(
        &blocks_transactions
            .iter()
            .flat_map(|bt| bt.sub_transaction_hashes.clone())
            .collect::<Vec<_>>(),
        count,
    ))
}

/// Checks that every transaction and sub-transaction id computed by cardano-cli on the devnet is listed by the immutable files, so that the certified ids are the ids the ledger uses
pub fn check_payments_hashes_are_in_blocks(
    blocks_transactions: &[CardanoBlockTransactions],
    transaction_hashes: &[String],
    sub_transaction_hashes: &[String],
) -> StdResult<()> {
    let missing_transaction = transaction_hashes.iter().find(|hash| {
        !blocks_transactions
            .iter()
            .any(|bt| bt.transaction_hashes.contains(hash))
    });
    if let Some(hash) = missing_transaction {
        return Err(anyhow!(
            "Transaction {hash} submitted by the devnet payment script is not listed by the immutable files"
        ));
    }
    let missing_sub_transaction = sub_transaction_hashes.iter().find(|hash| {
        !blocks_transactions
            .iter()
            .any(|bt| bt.sub_transaction_hashes.contains(hash))
    });
    if let Some(hash) = missing_sub_transaction {
        return Err(anyhow!(
            "Sub-transaction {hash} nested by the devnet payment script is not listed by the immutable files"
        ));
    }

    Ok(())
}

/// Removes the duplicated hashes, keeping them sorted
pub fn unique_hashes(hashes: Vec<String>) -> Vec<String> {
    hashes.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

pub fn randomly_take_blocks_hashes(
    blocks_transactions: &[CardanoBlockTransactions],
    count: usize,
) -> Vec<String> {
    randomly_take(
        &blocks_transactions
            .iter()
            .map(|bt| bt.block_hash.clone())
            .collect::<Vec<_>>(),
        count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_retrieve_blocks_transactions_from_immutable_files() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let immutables_path = PathBuf::from(manifest_dir).join("tests/assets/immutable");

        let blocks_and_transactions =
            retrieve_blocks_transactions_from_immutable_files(&immutables_path)
                .expect("Failed to retrieve blocks and transactions from immutable files");

        assert!(!blocks_and_transactions.is_empty());
        assert!(blocks_and_transactions.contains(&CardanoBlockTransactions {
            block_hash:
                "c75a3d5dbfcebd36bcbcdb2701ede41862764e856f81e8f1aafc5a960fd2283a".to_string(),
            transaction_hashes: vec![
                "ce2872d64240a25d7d43fb57efacfd1d9bd20073e91e1539bd31ef3ebc16555e".to_string()
            ],
            sub_transaction_hashes: vec![],
        }));
    }

    #[test]
    fn from_block_separates_top_level_and_sub_transactions_of_a_dijkstra_block() {
        let raw_block = hex::decode(include_str!("../../tests/assets/dijkstra1.block")).unwrap();
        let block = MultiEraBlock::decode(&raw_block).unwrap();

        let block_transactions = CardanoBlockTransactions::from_block(&block);

        assert_eq!(
            block_transactions.block_hash,
            "27a8e2d79a1ea9bfb7906f1d049b6c81b7a77c08504ab45c8c49d50a5f109d64"
        );
        assert_eq!(
            block_transactions.transaction_hashes,
            vec!["7ff742461176a381748e6c0e79f0c483a738e646da8422cdf8fa19deecac52cc".to_string()]
        );
        assert_eq!(
            block_transactions.sub_transaction_hashes,
            vec!["d0fecaa8853c23d59b233149d11d4918cbfd5f8fb7892280d04ed84646e3f586".to_string()]
        );
    }

    #[test]
    fn test_randomly_take_transactions_hashes() {
        let blocks_transactions = vec![
            CardanoBlockTransactions {
                block_hash: "block1".to_string(),
                transaction_hashes: vec!["tx1".to_string(), "tx2".to_string()],
                sub_transaction_hashes: vec![],
            },
            CardanoBlockTransactions {
                block_hash: "block2".to_string(),
                transaction_hashes: vec!["tx3".to_string(), "tx4".to_string()],
                sub_transaction_hashes: vec![],
            },
        ];
        let transaction_hashes = randomly_take_transactions_hashes(&blocks_transactions, 3);
        assert_eq!(transaction_hashes.len(), 3);

        let all_contained = transaction_hashes.iter().all(|item| {
            blocks_transactions
                .iter()
                .any(|bt| bt.transaction_hashes.contains(item))
        });
        assert!(all_contained);
    }

    #[test]
    fn test_randomly_take_blocks_hashes() {
        let blocks_transactions = vec![
            CardanoBlockTransactions {
                block_hash: "block1".to_string(),
                transaction_hashes: vec![],
                sub_transaction_hashes: vec![],
            },
            CardanoBlockTransactions {
                block_hash: "block2".to_string(),
                transaction_hashes: vec![],
                sub_transaction_hashes: vec![],
            },
            CardanoBlockTransactions {
                block_hash: "block3".to_string(),
                transaction_hashes: vec![],
                sub_transaction_hashes: vec![],
            },
            CardanoBlockTransactions {
                block_hash: "block4".to_string(),
                transaction_hashes: vec![],
                sub_transaction_hashes: vec![],
            },
        ];
        let block_hashes = randomly_take_blocks_hashes(&blocks_transactions, 2);
        assert_eq!(block_hashes.len(), 2);

        let all_contained = block_hashes
            .iter()
            .all(|item| blocks_transactions.iter().any(|bt| bt.block_hash == *item));
        assert!(all_contained);
    }

    fn blocks_without_sub_transactions() -> Vec<CardanoBlockTransactions> {
        vec![
            CardanoBlockTransactions {
                block_hash: "block1".to_string(),
                transaction_hashes: vec!["tx1".to_string()],
                sub_transaction_hashes: vec![],
            },
            CardanoBlockTransactions {
                block_hash: "block2".to_string(),
                transaction_hashes: vec!["tx2".to_string()],
                sub_transaction_hashes: vec![],
            },
        ]
    }

    fn blocks_with_sub_transactions() -> Vec<CardanoBlockTransactions> {
        vec![
            CardanoBlockTransactions {
                block_hash: "block1".to_string(),
                transaction_hashes: vec!["tx1".to_string()],
                sub_transaction_hashes: vec!["sub1".to_string(), "sub2".to_string()],
            },
            CardanoBlockTransactions {
                block_hash: "block2".to_string(),
                transaction_hashes: vec!["tx2".to_string()],
                sub_transaction_hashes: vec!["sub3".to_string()],
            },
        ]
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_takes_hashes_of_the_blocks() {
        let blocks_transactions = blocks_with_sub_transactions();

        let sub_transaction_hashes = randomly_take_sub_transactions_hashes(
            &blocks_transactions,
            &semver::Version::new(11, 2, 0),
            0,
            2,
        )
        .unwrap();
        assert_eq!(sub_transaction_hashes.len(), 2);

        let all_contained = sub_transaction_hashes.iter().all(|item| {
            blocks_transactions
                .iter()
                .any(|bt| bt.sub_transaction_hashes.contains(item))
        });
        assert!(all_contained);
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_is_empty_before_cardano_node_11_2_0_without_sub_transactions()
     {
        let hashes = randomly_take_sub_transactions_hashes(
            &blocks_without_sub_transactions(),
            &semver::Version::new(11, 1, 3),
            0,
            5,
        )
        .unwrap();

        assert!(hashes.is_empty());
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_fails_from_cardano_node_11_2_0_without_sub_transactions()
     {
        let error = randomly_take_sub_transactions_hashes(
            &blocks_without_sub_transactions(),
            &semver::Version::new(11, 2, 0),
            0,
            5,
        )
        .unwrap_err();

        assert!(error.to_string().contains(
            "No sub-transaction found in the immutable files of a Dijkstra devnet (cardano-node 11.2.0)"
        ));
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_returns_all_hashes_when_count_exceeds_them() {
        let hashes = randomly_take_sub_transactions_hashes(
            &blocks_with_sub_transactions(),
            &semver::Version::new(11, 2, 0),
            0,
            10,
        )
        .unwrap();

        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_is_empty_from_cardano_node_11_2_0_without_sub_transactions_when_the_hard_fork_is_after_epoch_0()
     {
        let hashes = randomly_take_sub_transactions_hashes(
            &blocks_without_sub_transactions(),
            &semver::Version::new(11, 2, 0),
            2,
            5,
        )
        .unwrap();

        assert!(hashes.is_empty());
    }

    #[test]
    fn unique_hashes_removes_the_duplicates() {
        let hashes = unique_hashes(vec!["b".to_string(), "a".to_string(), "b".to_string()]);

        assert_eq!(hashes, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn check_payments_hashes_are_in_blocks_accepts_listed_hashes() {
        check_payments_hashes_are_in_blocks(
            &blocks_with_sub_transactions(),
            &["tx2".to_string()],
            &["sub1".to_string(), "sub3".to_string()],
        )
        .unwrap();
    }

    #[test]
    fn check_payments_hashes_are_in_blocks_accepts_empty_lists() {
        check_payments_hashes_are_in_blocks(&blocks_without_sub_transactions(), &[], &[]).unwrap();
    }

    #[test]
    fn check_payments_hashes_are_in_blocks_fails_on_an_unlisted_transaction() {
        let error = check_payments_hashes_are_in_blocks(
            &blocks_with_sub_transactions(),
            &["tx9".to_string()],
            &[],
        )
        .unwrap_err();

        assert!(error.to_string().contains("Transaction tx9"));
    }

    #[test]
    fn check_payments_hashes_are_in_blocks_fails_on_an_unlisted_sub_transaction() {
        let error = check_payments_hashes_are_in_blocks(
            &blocks_with_sub_transactions(),
            &[],
            &["sub9".to_string()],
        )
        .unwrap_err();

        assert!(error.to_string().contains("Sub-transaction sub9"));
    }

    #[test]
    fn randomly_take_sub_transactions_hashes_with_count_zero_is_empty_when_sub_transactions_exist()
    {
        let hashes = randomly_take_sub_transactions_hashes(
            &blocks_with_sub_transactions(),
            &semver::Version::new(11, 2, 0),
            0,
            0,
        )
        .unwrap();

        assert!(hashes.is_empty());
    }
}
