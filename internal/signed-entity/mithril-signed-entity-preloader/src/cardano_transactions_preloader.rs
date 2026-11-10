//! # Cardano Transaction Preloader
//!
//! This module provides a preload mechanism for Cardano Transaction signed entity, allowing
//! to compute in advance the Transactions & Block Range Root to be signed.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::{
    StdResult,
    entities::{BlockNumber, SignedEntityTypeDiscriminants},
    signable_builder::TransactionsImporter,
};

use crate::PreloadTask;

const SIGNED_ENTITIES_TO_LOCK: [SignedEntityTypeDiscriminants; 2] = [
    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
    SignedEntityTypeDiscriminants::CardanoTransactions,
];

/// CardanoTransactionsPreloaderChecker gives the ability to determine
/// if the Cardano Transactions Preloader should import the transactions.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CardanoTransactionsPreloaderChecker: Send + Sync {
    /// Determine if the Cardano Transactions Preloader should preload.
    async fn is_activated(&self) -> StdResult<bool>;
}

/// CardanoTransactionsPreloaderActivation
pub struct CardanoTransactionsPreloaderActivation {
    activation: bool,
}

impl CardanoTransactionsPreloaderActivation {
    /// Create a new instance of `CardanoTransactionsPreloaderActivation`
    pub fn new(activation: bool) -> Self {
        Self { activation }
    }
}

#[async_trait]
impl CardanoTransactionsPreloaderChecker for CardanoTransactionsPreloaderActivation {
    async fn is_activated(&self) -> StdResult<bool> {
        Ok(self.activation)
    }
}

/// Preload task for Cardano Transactions and Cardano Blocks Transactions signed entities, allowing
/// to compute in advance the Blocks, Transactions & Block Range Root to be signed.
///
/// Must be run with a [PreloadTaskRunner][crate::PreloadTaskRunner].
pub struct CardanoTransactionsPreloader {
    importer: Arc<dyn TransactionsImporter>,
    security_parameter: BlockNumber,
    chain_observer: Arc<dyn ChainObserver>,
    activation_state: Arc<dyn CardanoTransactionsPreloaderChecker>,
}

impl CardanoTransactionsPreloader {
    /// Create a new instance of `CardanoTransactionsPreloader`.
    pub fn new(
        importer: Arc<dyn TransactionsImporter>,
        security_parameter: BlockNumber,
        chain_observer: Arc<dyn ChainObserver>,
        activation_state: Arc<dyn CardanoTransactionsPreloaderChecker>,
    ) -> Self {
        Self {
            importer,
            security_parameter,
            chain_observer,
            activation_state,
        }
    }
}

#[async_trait]
impl PreloadTask for CardanoTransactionsPreloader {
    fn signed_entities_to_lock(&self) -> Vec<SignedEntityTypeDiscriminants> {
        SIGNED_ENTITIES_TO_LOCK.to_vec()
    }

    async fn is_activated(&self) -> StdResult<bool> {
        self.activation_state.is_activated().await
    }

    /// Preload the Cardano Transactions by running the importer up to the current chain block number.
    async fn preload(&self) -> StdResult<()> {
        let chain_point = self.chain_observer.get_current_chain_point().await?.with_context(
            || "No chain point yielded by the chain observer, is your cardano node ready?",
        )?;
        let up_to_block_number = chain_point.block_number - self.security_parameter;
        self.importer.import(up_to_block_number).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use mockall::mock;
    use mockall::predicate::eq;

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::entities::{ChainPoint, TimePoint};
    use mithril_common::test::double::Dummy;
    use mithril_common::test::mock_extensions::MockBuilder;

    use super::*;

    mock! {
        pub TransactionsImporter { }

        #[async_trait]
        impl TransactionsImporter for TransactionsImporter {
            async fn import(&self, up_to_beacon: BlockNumber) -> StdResult<()>;
        }
    }

    fn build_chain_observer() -> (FakeChainObserver, BlockNumber, BlockNumber) {
        let chain_block_number = BlockNumber(5000);
        let security_parameter = BlockNumber(542);
        let chain_observer = FakeChainObserver::new(Some(TimePoint {
            chain_point: ChainPoint {
                block_number: chain_block_number,
                ..ChainPoint::dummy()
            },
            ..TimePoint::dummy()
        }));
        (chain_observer, chain_block_number, security_parameter)
    }

    #[tokio::test]
    async fn preload_call_its_inner_importer_up_to_the_chain_block_number_minus_security_parameter()
    {
        let (chain_observer, chain_block_number, security_parameter) = build_chain_observer();
        let expected_parsed_block_number = chain_block_number - security_parameter;

        let importer = MockBuilder::<MockTransactionsImporter>::configure(|mock| {
            mock.expect_import()
                .times(1)
                .with(eq(expected_parsed_block_number))
                .returning(|_| Ok(()));
        });

        let preloader = CardanoTransactionsPreloader::new(
            importer,
            security_parameter,
            Arc::new(chain_observer),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn preload_fail_if_chain_point_is_not_available() {
        let chain_observer = FakeChainObserver::new(None);
        let importer = MockBuilder::<MockTransactionsImporter>::configure(|mock| {
            mock.expect_import().never();
        });

        let preloader = CardanoTransactionsPreloader::new(
            importer,
            BlockNumber(0),
            Arc::new(chain_observer),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        preloader
            .preload()
            .await
            .expect_err("should raise an error when chain point is not available");
    }

    #[test]
    fn lock_cardano_transactions_and_cardano_blocks_transactions() {
        let (chain_observer, _, _) = build_chain_observer();
        let preloader = CardanoTransactionsPreloader::new(
            Arc::new(MockTransactionsImporter::new()),
            BlockNumber(0),
            Arc::new(chain_observer),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        assert_eq!(
            vec![
                SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ],
            preloader.signed_entities_to_lock()
        );
    }
}
