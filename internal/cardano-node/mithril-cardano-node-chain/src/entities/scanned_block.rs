use pallas_traverse::MultiEraBlock;
use std::fmt::{Debug, Formatter};

use mithril_common::entities::{
    BlockHash, BlockNumber, CardanoBlockWithTransactions, CardanoTransaction, ChainPoint,
    SlotNumber, TransactionHash,
};

/// A block scanned from a Cardano database
#[derive(Clone, PartialEq)]
pub struct ScannedBlock {
    /// Block hash
    pub block_hash: Vec<u8>,
    /// Block number
    pub block_number: BlockNumber,
    /// Slot number of the block
    pub slot_number: SlotNumber,
    /// Hashes of the transactions in the block, each Dijkstra sub-transaction listed after its parent transaction
    pub transactions_hashes: Vec<TransactionHash>,
}

impl ScannedBlock {
    /// Scanned block factory
    pub fn new<B: Into<Vec<u8>>, T: Into<TransactionHash>>(
        block_hash: B,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        transaction_hashes: Vec<T>,
    ) -> Self {
        Self {
            block_hash: block_hash.into(),
            block_number,
            slot_number,
            transactions_hashes: transaction_hashes.into_iter().map(|h| h.into()).collect(),
        }
    }

    pub(crate) fn convert(multi_era_block: MultiEraBlock) -> Self {
        let mut transactions = Vec::new();
        for tx in &multi_era_block.txs() {
            transactions.push(tx.hash().to_string());
            for sub_transaction in &tx.sub_transactions() {
                transactions.push(sub_transaction.hash().to_string());
            }
        }

        Self::new(
            *multi_era_block.hash(),
            BlockNumber(multi_era_block.number()),
            SlotNumber(multi_era_block.slot()),
            transactions,
        )
    }

    /// Number of transactions in the block
    pub fn transactions_len(&self) -> usize {
        self.transactions_hashes.len()
    }

    /// Returns the block hash as a hex string.
    pub fn block_hash_hex(&self) -> BlockHash {
        hex::encode(&self.block_hash)
    }

    /// Convert the scanned block into a list of Cardano transactions.
    ///
    /// Consume the block.
    pub fn into_transactions(self) -> Vec<CardanoTransaction> {
        let block_hash = self.block_hash_hex();
        self.transactions_hashes
            .into_iter()
            .map(|transaction_hash| {
                CardanoTransaction::new(
                    transaction_hash,
                    self.block_number,
                    self.slot_number,
                    block_hash.clone(),
                )
            })
            .collect::<Vec<_>>()
    }
}

impl Debug for ScannedBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ScannedBlock");
        debug
            .field("block_hash", &self.block_hash_hex())
            .field("block_number", &self.block_number)
            .field("slot_number", &self.slot_number)
            .field("transactions_hashes", &self.transactions_hashes)
            .finish()
    }
}

impl From<&ScannedBlock> for ChainPoint {
    fn from(scanned_block: &ScannedBlock) -> Self {
        ChainPoint::new(
            scanned_block.slot_number,
            scanned_block.block_number,
            scanned_block.block_hash_hex(),
        )
    }
}

impl From<ScannedBlock> for CardanoBlockWithTransactions {
    fn from(value: ScannedBlock) -> Self {
        CardanoBlockWithTransactions::new(
            value.block_hash_hex(),
            value.block_number,
            value.slot_number,
            value.transactions_hashes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanned_block_from_hex_fixture(fixture: &str) -> ScannedBlock {
        let raw_block = hex::decode(fixture).unwrap();
        let multi_era_block = MultiEraBlock::decode(&raw_block).unwrap();

        ScannedBlock::convert(multi_era_block)
    }

    #[test]
    fn block_hash_hex() {
        let block = ScannedBlock::new(
            vec![1, 2, 3],
            BlockNumber(10),
            SlotNumber(50),
            vec!["tx_hash"],
        );
        assert_eq!("010203", block.block_hash_hex());
    }

    #[test]
    fn convert_lists_the_sub_transactions_of_a_dijkstra_block_after_their_parent() {
        let block =
            scanned_block_from_hex_fixture(include_str!("../../tests/assets/dijkstra1.block"));

        assert_eq!(
            block.block_hash_hex(),
            "27a8e2d79a1ea9bfb7906f1d049b6c81b7a77c08504ab45c8c49d50a5f109d64"
        );
        assert_eq!(block.block_number, BlockNumber(154));
        assert_eq!(block.slot_number, SlotNumber(180));
        assert_eq!(
            block.transactions_hashes,
            vec![
                "7ff742461176a381748e6c0e79f0c483a738e646da8422cdf8fa19deecac52cc".to_string(),
                "d0fecaa8853c23d59b233149d11d4918cbfd5f8fb7892280d04ed84646e3f586".to_string(),
            ]
        );
    }

    #[test]
    fn convert_lists_only_the_top_level_transactions_of_a_dijkstra_block_without_sub_transactions()
    {
        let block =
            scanned_block_from_hex_fixture(include_str!("../../tests/assets/dijkstra2.block"));

        assert_eq!(
            block.block_hash_hex(),
            "6794ca80ece53475298f4c47748a5d0e08c3e836e9debaf42dd1b94a9769c409"
        );
        assert_eq!(block.block_number, BlockNumber(145));
        assert_eq!(
            block.transactions_hashes,
            vec![
                "d90e0a53304740b4fe3238b27f77a9cd9e629c9b1bc95d0b12e9ed69180130ab".to_string(),
                "d2a20ad06495d2225f35ee7090ae12db5a15e79d83cb211d24d3d1f4d5985e41".to_string(),
            ]
        );
    }

    #[test]
    fn convert_keeps_the_transactions_of_a_pre_dijkstra_block() {
        let raw_block = hex::decode(include_str!("../../tests/assets/shelley1.block")).unwrap();
        let multi_era_block = MultiEraBlock::decode(&raw_block).unwrap();
        let expected: Vec<String> =
            multi_era_block.txs().iter().map(|tx| tx.hash().to_string()).collect();

        let block = ScannedBlock::convert(multi_era_block);

        assert!(!expected.is_empty());
        assert_eq!(block.transactions_hashes, expected);
    }
}
