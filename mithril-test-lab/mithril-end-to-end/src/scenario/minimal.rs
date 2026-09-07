use std::sync::Arc;

use slog_scope::info;
use tokio::task::JoinSet;

use mithril_common::{
    StdResult,
    entities::{Epoch, SignedEntityTypeDiscriminants},
};

use crate::{
    Aggregator, MithrilInfrastructure,
    toolkit::ScenarioToolkit,
    utils::{
        randomly_take_blocks_hashes, randomly_take_transactions_hashes,
        retrieve_blocks_transactions_from_immutable_files,
    },
};

pub struct MinimalScenario {
    toolkit: ScenarioToolkit,
    infrastructure: Arc<MithrilInfrastructure>,
    signed_entity_type: SignedEntityTypeDiscriminants,
}

impl MinimalScenario {
    pub fn new(
        toolkit: ScenarioToolkit,
        infrastructure: Arc<MithrilInfrastructure>,
        signed_entity_type: SignedEntityTypeDiscriminants,
    ) -> Self {
        Self {
            infrastructure,
            toolkit,
            signed_entity_type,
        }
    }

    pub async fn run(self) -> StdResult<()> {
        let mut join_set = JoinSet::new();
        let spec = Arc::new(self);

        // Delegate some stakes to pools
        let delegation_round = 1;
        spec.toolkit
            .exec
            .delegate_stakes_to_pools(spec.infrastructure.devnet(), delegation_round)
            .await?;

        if matches!(
            &spec.signed_entity_type,
            SignedEntityTypeDiscriminants::CardanoStakeDistribution
                | SignedEntityTypeDiscriminants::CardanoTransactions
        ) {
            // Transfer some funds on the devnet to have some Cardano transactions to sign.
            // This step needs to be executed early in the process so that the transactions are available
            // for signing in the penultimate immutable chunk before the end of the test.
            // As we get closer to the tip of the chain when signing, we'll be able to relax this constraint.
            spec.toolkit.exec.transfer_funds(spec.infrastructure.devnet()).await?;
        }

        info!("Bootstrapping leader aggregator");
        spec.bootstrap_leader_aggregator(&spec.infrastructure).await?;

        info!("Starting followers");
        for follower_aggregator in spec.infrastructure.follower_aggregators() {
            follower_aggregator.serve().await?;
        }

        info!("Running scenarios");
        for index in 0..spec.infrastructure.aggregators().len() {
            let spec_clone = spec.clone();
            join_set.spawn(async move {
                let infrastructure = &spec_clone.infrastructure;

                spec_clone
                    .run_scenario(infrastructure.aggregator(index), infrastructure)
                    .await
            });
        }

        while let Some(res) = join_set.join_next().await {
            res??;
        }

        Ok(())
    }

    pub async fn bootstrap_leader_aggregator(
        &self,
        infrastructure: &MithrilInfrastructure,
    ) -> StdResult<()> {
        let leader_aggregator = infrastructure.leader_aggregator();

        self.toolkit.wait.for_enough_immutable(leader_aggregator).await?;
        let chain_observer = leader_aggregator.chain_observer();
        let start_epoch = chain_observer.get_current_epoch().await?.unwrap_or_default();

        // Wait 2 epochs after start epoch for the aggregator to be able to bootstrap a genesis certificate
        let target_epoch = start_epoch + 2;
        self.toolkit
            .wait
            .for_aggregator_at_target_epoch(
                leader_aggregator,
                target_epoch,
                "minimal epoch for the aggregator to be able to bootstrap genesis certificate"
                    .to_string(),
            )
            .await?;
        self.toolkit
            .exec
            .bootstrap_genesis_certificate(leader_aggregator)
            .await?;
        self.toolkit.wait.for_epoch_settings(leader_aggregator).await?;

        Ok(())
    }

    pub async fn run_scenario(
        &self,
        aggregator: &Aggregator,
        infrastructure: &MithrilInfrastructure,
    ) -> StdResult<()> {
        let chain_observer = aggregator.chain_observer();
        let start_epoch = chain_observer.get_current_epoch().await?.unwrap_or_default();

        // Wait 3 epochs after genesis certificate creation
        let target_epoch = start_epoch + 3;
        self.toolkit
            .wait
            .for_aggregator_at_target_epoch(
                aggregator,
                target_epoch,
                "epoch after which a minimal number of certificates have been produced".to_string(),
            )
            .await?;

        // Verify that artifacts are produced and signed correctly
        self.verify_artifacts_production(target_epoch, aggregator, infrastructure)
            .await?;

        Ok(())
    }

    async fn verify_artifacts_production(
        &self,
        target_epoch: Epoch,
        aggregator: &Aggregator,
        infrastructure: &MithrilInfrastructure,
    ) -> StdResult<Epoch> {
        let mut client = infrastructure.build_client(aggregator).await?;

        let expected_epoch_min = target_epoch - 1;
        let immutable_files_directory = aggregator.db_directory().join("immutable");
        let blocks_transactions =
            retrieve_blocks_transactions_from_immutable_files(&immutable_files_directory)?;

        let transaction_hashes = randomly_take_transactions_hashes(&blocks_transactions, 5);
        let block_hashes = randomly_take_blocks_hashes(&blocks_transactions, 5);

        // Verify that the aggregator is still producing a certificate chain
        self.toolkit
            .check
            .certificate
            .is_creating_certificate_with_min_epoch(aggregator, expected_epoch_min)
            .await?;

        // Verify that mithril stake distribution artifacts are produced and signed correctly
        self.toolkit
            .check
            .mithril_stake_distribution
            .is_certified_and_verified(
                aggregator,
                &mut client,
                expected_epoch_min,
                infrastructure.signers().len(),
            )
            .await?;

        // Verify that Cardano database snapshot artifacts are produced and signed correctly
        if self.signed_entity_type == SignedEntityTypeDiscriminants::CardanoDatabase {
            self.toolkit
                .check
                .cardano_database
                .is_certified_and_verified(
                    aggregator,
                    &mut client,
                    infrastructure.client_ipfs_node().map(|n| n.rpc_url.clone()),
                    expected_epoch_min,
                    infrastructure.signers().len(),
                )
                .await?;
        }

        // Verify that Cardano transactions artifacts are produced and signed correctly
        if self.signed_entity_type == SignedEntityTypeDiscriminants::CardanoTransactions {
            self.toolkit
                .check
                .cardano_transactions
                .is_certified_and_verified(
                    aggregator,
                    &mut client,
                    expected_epoch_min,
                    infrastructure.signers().len(),
                    transaction_hashes.clone(),
                )
                .await?;
        }

        // Verify that Cardano blocks transactions artifacts are produced and signed correctly
        if self.signed_entity_type == SignedEntityTypeDiscriminants::CardanoBlocksTransactions {
            self.toolkit
                .check
                .cardano_blocks_transactions
                .is_certified_and_verified(
                    aggregator,
                    &mut client,
                    expected_epoch_min,
                    infrastructure.signers().len(),
                    block_hashes.clone(),
                    transaction_hashes.clone(),
                )
                .await?;
        }

        // Verify that Cardano stake distribution artifacts are produced and signed correctly
        if self.signed_entity_type == SignedEntityTypeDiscriminants::CardanoStakeDistribution {
            {
                self.toolkit
                    .check
                    .cardano_stake_distribution
                    .is_certified_and_verified(
                        aggregator,
                        &mut client,
                        expected_epoch_min,
                        infrastructure.signers().len(),
                    )
                    .await?;
            }
        }

        Ok(target_epoch)
    }
}
