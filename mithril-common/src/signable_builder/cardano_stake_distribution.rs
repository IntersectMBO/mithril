use anyhow::{Context, anyhow};
use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    StdResult,
    crypto_helper::{MKTree, MKTreeNode, MKTreeStoreInMemory, decode_bech32, encode_bech32},
    entities::{Epoch, ProtocolMessage, ProtocolMessagePartKey, StakeDistribution},
    signable_builder::SignableBuilder,
};

#[cfg(test)]
use mockall::automock;

/// Stake Distribution Retriever
#[cfg_attr(test, automock)]
#[async_trait]
pub trait StakeDistributionRetriever: Send + Sync {
    /// Retrieve the [StakeDistribution] for a given epoch
    async fn retrieve(&self, epoch: Epoch) -> StdResult<Option<StakeDistribution>>;
}

struct StakeDistributionEntry(String, u64);

impl StakeDistributionEntry {
    pub fn new(pool_id: &str, stake: u64) -> Self {
        Self(pool_id.to_string(), stake)
    }
}

impl From<StakeDistributionEntry> for MKTreeNode {
    fn from(entry: StakeDistributionEntry) -> Self {
        MKTreeNode::new(format!("{}{}", entry.0, entry.1).into())
    }
}

/// A [CardanoStakeDistributionSignableBuilder] builder
pub struct CardanoStakeDistributionSignableBuilder {
    cardano_stake_distribution_retriever: Arc<dyn StakeDistributionRetriever>,
}

impl CardanoStakeDistributionSignableBuilder {
    /// Constructor
    pub fn new(cardano_stake_distribution_retriever: Arc<dyn StakeDistributionRetriever>) -> Self {
        Self {
            cardano_stake_distribution_retriever,
        }
    }

    /// Compute the Merkle tree of a given [StakeDistribution]
    pub fn compute_merkle_tree_from_stake_distribution(
        pools_with_stake: StakeDistribution,
    ) -> StdResult<MKTree<MKTreeStoreInMemory>> {
        let leaves: Vec<MKTreeNode> = pools_with_stake
            .iter()
            .map(|(k, v)| StakeDistributionEntry::new(k, *v).into())
            .collect();

        MKTree::new(&leaves)
    }

    /// Check that every key of a [StakeDistribution] is a canonical pool id.
    ///
    /// A canonical pool id is the lowercase bech32 encoding, with the `pool` human readable part, of
    /// a 28-byte pool hash, as the chain observers produce it. Enforcing it keeps each Merkle leaf
    /// unambiguous, since the boundary between the pool id and its decimal stake cannot be moved.
    pub fn check_pool_ids(pools_with_stake: &StakeDistribution) -> StdResult<()> {
        const POOL_HASH_SIZE: usize = 28;
        const POOL_HRP: &str = "pool";

        for pool_id in pools_with_stake.keys() {
            let is_canonical = decode_bech32(pool_id).ok().is_some_and(|(hrp, data)| {
                hrp == POOL_HRP
                    && data.len() == POOL_HASH_SIZE
                    && encode_bech32(POOL_HRP, &data)
                        .is_ok_and(|reencoded| reencoded.as_str() == pool_id.as_str())
            });
            if !is_canonical {
                return Err(anyhow!(
                    "Invalid pool id in the Cardano stake distribution: {pool_id:?}"
                ));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SignableBuilder<Epoch> for CardanoStakeDistributionSignableBuilder {
    async fn compute_protocol_message(&self, epoch: Epoch) -> StdResult<ProtocolMessage> {
        let pools_with_stake = self
            .cardano_stake_distribution_retriever
            .retrieve(epoch.offset_to_cardano_stake_distribution_snapshot_epoch())
            .await?.with_context(|| format!(
                "CardanoStakeDistributionSignableBuilder could not find the stake distribution for epoch: '{epoch}'"
            ))?;

        let mk_tree = Self::compute_merkle_tree_from_stake_distribution(pools_with_stake)?;

        let mut protocol_message = ProtocolMessage::new();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionEpoch,
            epoch.to_string(),
        );
        protocol_message.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot,
            mk_tree.compute_root()?.to_hex(),
        );

        Ok(protocol_message)
    }
}

#[cfg(test)]
mod tests {
    use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
    use bech32::{Bech32, Bech32m, Fe32, Hrp};
    use mockall::predicate::eq;

    use crate::entities::ProtocolMessagePartKey;

    use super::*;

    fn is_merkle_tree_equals(
        first_pools_with_stake: StakeDistribution,
        second_pools_with_stake: StakeDistribution,
    ) -> bool {
        let first_merkle_tree =
            CardanoStakeDistributionSignableBuilder::compute_merkle_tree_from_stake_distribution(
                first_pools_with_stake,
            )
            .unwrap();
        let second_merkle_tree =
            CardanoStakeDistributionSignableBuilder::compute_merkle_tree_from_stake_distribution(
                second_pools_with_stake,
            )
            .unwrap();

        first_merkle_tree.compute_root().unwrap() == second_merkle_tree.compute_root().unwrap()
    }

    #[test]
    fn compute_merkle_tree_equals() {
        assert!(is_merkle_tree_equals(
            StakeDistribution::from([("pool-123".to_string(), 100)]),
            StakeDistribution::from([("pool-123".to_string(), 100)]),
        ));

        assert!(is_merkle_tree_equals(
            StakeDistribution::from([("pool-123".to_string(), 100), ("pool-456".to_string(), 150)]),
            StakeDistribution::from([("pool-456".to_string(), 150), ("pool-123".to_string(), 100)])
        ));
    }

    #[test]
    fn compute_merkle_tree_not_equals() {
        assert!(!is_merkle_tree_equals(
            StakeDistribution::from([("pool-123".to_string(), 100)]),
            StakeDistribution::from([("pool-456".to_string(), 100)]),
        ));

        assert!(!is_merkle_tree_equals(
            StakeDistribution::from([("pool-123".to_string(), 100)]),
            StakeDistribution::from([("pool-123".to_string(), 999)]),
        ));
    }

    #[tokio::test]
    async fn compute_protocol_message_returns_error_when_no_cardano_stake_distribution_found() {
        let epoch = Epoch(1);

        let mut cardano_stake_distribution_retriever = MockStakeDistributionRetriever::new();
        cardano_stake_distribution_retriever
            .expect_retrieve()
            .return_once(move |_| Ok(None));
        let cardano_stake_distribution_signable_builder =
            CardanoStakeDistributionSignableBuilder::new(Arc::new(
                cardano_stake_distribution_retriever,
            ));

        cardano_stake_distribution_signable_builder
            .compute_protocol_message(epoch)
            .await
            .expect_err("Should return an error when no cardano stake distribution found");
    }

    #[tokio::test]
    async fn compute_protocol_message_returns_signable_and_retrieve_with_epoch_offset() {
        let epoch = Epoch(1);
        let epoch_to_retrieve = Epoch(3);
        let stake_distribution = StakeDistribution::from([("pool-123".to_string(), 100)]);
        let stake_distribution_clone = stake_distribution.clone();

        let mut pools_with_stake_retriever = MockStakeDistributionRetriever::new();
        pools_with_stake_retriever
            .expect_retrieve()
            .with(eq(epoch_to_retrieve))
            .return_once(move |_| Ok(Some(stake_distribution)));
        let cardano_stake_distribution_signable_builder =
            CardanoStakeDistributionSignableBuilder::new(Arc::new(pools_with_stake_retriever));

        let signable = cardano_stake_distribution_signable_builder
            .compute_protocol_message(epoch)
            .await
            .unwrap();

        let expected_mktree =
            CardanoStakeDistributionSignableBuilder::compute_merkle_tree_from_stake_distribution(
                stake_distribution_clone,
            )
            .unwrap();
        let mut signable_expected = ProtocolMessage::new();
        signable_expected.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionEpoch,
            epoch.to_string(),
        );
        signable_expected.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot,
            expected_mktree.compute_root().unwrap().to_hex(),
        );
        assert_eq!(signable_expected, signable);
    }

    fn canonical_pool_id() -> String {
        encode_bech32("pool", &[0u8; 28]).unwrap()
    }

    fn pool_id_with_padding_bit_set() -> String {
        let mut data_characters: Vec<Fe32> = [0u8; 28].iter().copied().bytes_to_fes().collect();
        let last_character = data_characters.last_mut().unwrap();
        *last_character = Fe32::try_from(last_character.to_u8() | 1).unwrap();
        data_characters
            .into_iter()
            .with_checksum::<Bech32>(&Hrp::parse("pool").unwrap())
            .chars()
            .collect::<String>()
    }

    #[test]
    fn check_pool_ids_accepts_canonical_pool_ids() {
        let genuine = StakeDistribution::from([(canonical_pool_id(), 1000)]);

        CardanoStakeDistributionSignableBuilder::check_pool_ids(&genuine)
            .expect("canonical pool ids must be accepted");
    }

    #[test]
    fn check_pool_ids_rejects_keys_that_are_not_canonical_pool_ids() {
        let pool_id = canonical_pool_id();

        for bad_key in [
            format!("{pool_id}1234"),
            "pool-123".to_string(),
            pool_id.to_uppercase(),
            encode_bech32("stake", &[0u8; 28]).unwrap(),
            encode_bech32("pool", &[0u8; 27]).unwrap(),
            encode_bech32("pool", &[0u8; 32]).unwrap(),
            bech32::encode::<Bech32m>(Hrp::parse("pool").unwrap(), &[0u8; 28]).unwrap(),
            pool_id_with_padding_bit_set(),
        ] {
            let altered = StakeDistribution::from([(bad_key.clone(), 5)]);
            assert!(
                CardanoStakeDistributionSignableBuilder::check_pool_ids(&altered).is_err(),
                "key '{bad_key}' must be rejected"
            );
        }
    }

    #[test]
    fn check_pool_ids_rejects_a_bad_key_following_a_canonical_pool_id() {
        let pool_id = canonical_pool_id();
        let mixed =
            StakeDistribution::from([(pool_id.clone(), 1000), (format!("{pool_id}1234"), 5)]);

        assert!(
            CardanoStakeDistributionSignableBuilder::check_pool_ids(&mixed).is_err(),
            "a bad key following a canonical pool id must be rejected"
        );
    }
}
