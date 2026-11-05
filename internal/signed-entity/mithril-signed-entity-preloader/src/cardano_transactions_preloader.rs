//! # Cardano Transaction Preloader
//!
//! This module provides a preload mechanism for Cardano Transaction signed entity, allowing
//! to compute in advance the Transactions & Block Range Root to be signed.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug, info};

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::{
    StdResult,
    entities::{BlockNumber, SignedEntityTypeDiscriminants},
    logging::LoggerExtensions,
    signable_builder::TransactionsImporter,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

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

/// Preload mechanism for Cardano Transactions and Cardano Blocks Transactions signed entities, allowing
/// to compute in advance the Blocks, Transactions & Block Range Root to be signed.
pub struct CardanoTransactionsPreloader {
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    importer: Arc<dyn TransactionsImporter>,
    security_parameter: BlockNumber,
    chain_observer: Arc<dyn ChainObserver>,
    logger: Logger,
    activation_state: Arc<dyn CardanoTransactionsPreloaderChecker>,
}

impl CardanoTransactionsPreloader {
    /// Create a new instance of `CardanoTransactionsPreloader`.
    pub fn new(
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        importer: Arc<dyn TransactionsImporter>,
        security_parameter: BlockNumber,
        chain_observer: Arc<dyn ChainObserver>,
        logger: Logger,
        activation_state: Arc<dyn CardanoTransactionsPreloaderChecker>,
    ) -> Self {
        Self {
            signed_entity_type_lock,
            importer,
            security_parameter,
            chain_observer,
            logger: logger.new_with_component_name::<Self>(),
            activation_state,
        }
    }

    /// Preload the Cardano Transactions by running the importer up to the current chain block number.
    pub async fn preload(&self) -> StdResult<()> {
        if !self.is_activated().await? {
            debug!(self.logger, "Not running, conditions not met");
            return Ok(());
        }

        info!(self.logger, "Started");
        debug!(self.logger, "Locking signed entity types"; "entity_types" => ?SIGNED_ENTITIES_TO_LOCK);
        let lock_guards = SIGNED_ENTITIES_TO_LOCK
            .map(|signed_entity_type| self.signed_entity_type_lock.lock(signed_entity_type));

        let preload_result = self.do_preload().await;

        debug!(self.logger, "Releasing signed entity types"; "entity_types" => ?SIGNED_ENTITIES_TO_LOCK);
        drop(lock_guards);
        info!(self.logger, "Finished");

        preload_result
    }

    /// Return the activation state of the preloader.
    pub async fn is_activated(&self) -> StdResult<bool> {
        self.activation_state.is_activated().await
    }

    async fn do_preload(&self) -> StdResult<()> {
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
    use anyhow::anyhow;
    use async_trait::async_trait;
    use mockall::mock;
    use mockall::predicate::eq;

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::entities::{BlockNumber, ChainPoint, TimePoint};
    use mithril_common::test::double::Dummy;
    use mithril_common::test::mock_extensions::MockBuilder;

    use crate::test_tools::TestLogger;

    use super::*;

    mock! {
        pub TransactionsImporter { }

        #[async_trait]
        impl TransactionsImporter for TransactionsImporter {
            async fn import(&self, up_to_beacon: BlockNumber) -> StdResult<()>;
        }
    }

    struct ImporterWithSignedEntityTypeLockCheck {
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    }
    #[async_trait]
    impl TransactionsImporter for ImporterWithSignedEntityTypeLockCheck {
        async fn import(&self, _up_to_beacon: BlockNumber) -> StdResult<()> {
            assert!(
                self.signed_entity_type_lock
                    .is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
            );
            assert!(
                self.signed_entity_type_lock
                    .is_locked(SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
            );
            Ok(())
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
    async fn call_its_inner_importer_when_is_activated() {
        let (chain_observer, chain_block_number, security_parameter) = build_chain_observer();
        let expected_parsed_block_number = chain_block_number - security_parameter;

        let importer = MockBuilder::<MockTransactionsImporter>::configure(|mock| {
            mock.expect_import()
                .times(1)
                .with(eq(expected_parsed_block_number))
                .returning(|_| Ok(()));
        });

        let preloader = CardanoTransactionsPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            importer,
            security_parameter,
            Arc::new(chain_observer),
            TestLogger::stdout(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn do_not_call_its_inner_importer_when_is_not_activated() {
        let (chain_observer, _, _) = build_chain_observer();
        let importer = MockBuilder::<MockTransactionsImporter>::configure(|mock| {
            mock.expect_import().never();
        });

        let preloader = CardanoTransactionsPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            importer,
            BlockNumber(542),
            Arc::new(chain_observer),
            TestLogger::stdout(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(false)),
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn return_error_when_is_activated_return_error() {
        let (chain_observer, _, _) = build_chain_observer();
        let mut importer = MockTransactionsImporter::new();
        importer.expect_import().never();

        let preloader_checker =
            MockBuilder::<MockCardanoTransactionsPreloaderChecker>::configure(|mock| {
                mock.expect_is_activated().returning(|| Err(anyhow::anyhow!("error")));
            });

        let preloader = CardanoTransactionsPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            Arc::new(importer),
            BlockNumber(542),
            Arc::new(chain_observer),
            TestLogger::stdout(),
            preloader_checker,
        );

        preloader
            .preload()
            .await
            .expect_err("should raise an error with error from the activation");
    }

    #[tokio::test]
    async fn fail_if_chain_point_is_not_available() {
        let chain_observer = FakeChainObserver::new(None);
        let importer = MockBuilder::<MockTransactionsImporter>::configure(|mock| {
            mock.expect_import().never();
        });

        let preloader = CardanoTransactionsPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            importer,
            BlockNumber(0),
            Arc::new(chain_observer),
            TestLogger::stdout(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        preloader
            .preload()
            .await
            .expect_err("should raise an error when chain point is not available");
    }

    #[tokio::test]
    async fn should_lock_entity_type_while_preloading() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());

        let preloader = CardanoTransactionsPreloader::new(
            signed_entity_type_lock.clone(),
            Arc::new(ImporterWithSignedEntityTypeLockCheck {
                signed_entity_type_lock: signed_entity_type_lock.clone(),
            }),
            BlockNumber(0),
            Arc::new(FakeChainObserver::new(Some(TimePoint::dummy()))),
            TestLogger::stdout(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        assert!(
            !signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
        );
        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
        );

        preloader.preload().await.unwrap();

        assert!(
            !signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
        );
        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
        );
    }

    #[tokio::test]
    async fn should_release_locked_entity_type_when_preloading_fail() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let chain_observer = FakeChainObserver::new(None);

        let preloader = CardanoTransactionsPreloader::new(
            signed_entity_type_lock.clone(),
            MockBuilder::<MockTransactionsImporter>::configure(|mock| {
                mock.expect_import().returning(|_| Err(anyhow!("import failed")));
            }),
            BlockNumber(0),
            Arc::new(chain_observer),
            TestLogger::stdout(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        );

        preloader.preload().await.unwrap_err();

        assert!(
            !signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
        );
        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
        );
    }
}
