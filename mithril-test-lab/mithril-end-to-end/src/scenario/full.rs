use std::sync::Arc;

use slog_scope::{info, warn};
use tokio::task::JoinSet;

use mithril_common::{
    StdResult,
    entities::{Epoch, SignedEntityTypeDiscriminants},
};

use crate::{
    Aggregator, MithrilInfrastructure, NodeVersion,
    toolkit::ScenarioToolkit,
    utils::{
        randomly_take_blocks_hashes, randomly_take_transactions_hashes,
        retrieve_blocks_transactions_from_immutable_files,
    },
};

pub struct FullScenario {
    toolkit: ScenarioToolkit,
    infrastructure: Arc<MithrilInfrastructure>,
    is_signing_cardano_transactions: bool,
    is_signing_cardano_blocks_transactions: bool,
    is_signing_cardano_stake_distribution: bool,
    is_signing_cardano_database: bool,
    check_client_cli_snapshot_converter: bool,
    next_era: Option<String>,
    regenesis_on_era_switch: bool,
}

impl FullScenario {
    pub fn new(
        toolkit: ScenarioToolkit,
        infrastructure: Arc<MithrilInfrastructure>,
        signed_entity_types: Vec<String>,
        check_client_cli_snapshot_converter: bool,
        next_era: Option<String>,
        regenesis_on_era_switch: bool,
    ) -> Self {
        let is_signing_cardano_blocks_transactions = {
            let contains_cardano_blocks_transactions = signed_entity_types
                .contains(&SignedEntityTypeDiscriminants::CardanoBlocksTransactions.to_string());

            if contains_cardano_blocks_transactions
                && !infrastructure.can_certify_cardano_blocks_transactions()
            {
                warn!(
                    "Aggregator(s) version below 0.8.25 or Signer(s) version below 0.3.18, skipping CardanoBlocksTransactions checks"
                );
                false
            } else {
                contains_cardano_blocks_transactions
            }
        };

        Self {
            infrastructure,
            toolkit,
            is_signing_cardano_transactions: signed_entity_types
                .contains(&SignedEntityTypeDiscriminants::CardanoTransactions.to_string()),
            is_signing_cardano_blocks_transactions,
            is_signing_cardano_stake_distribution: signed_entity_types
                .contains(&SignedEntityTypeDiscriminants::CardanoStakeDistribution.to_string()),
            is_signing_cardano_database: signed_entity_types
                .contains(&SignedEntityTypeDiscriminants::CardanoDatabase.to_string()),
            check_client_cli_snapshot_converter,
            next_era,
            regenesis_on_era_switch,
        }
    }

    pub async fn run(self) -> StdResult<()> {
        let mut join_set = JoinSet::new();
        let spec = Arc::new(self);

        // Transfer some funds on the devnet to have some Cardano transactions to sign.
        // This step needs to be executed early in the process so that the transactions are available
        // for signing in the penultimate immutable chunk before the end of the test.
        // As we get closer to the tip of the chain when signing, we'll be able to relax this constraint.
        spec.toolkit.exec.transfer_funds(spec.infrastructure.devnet()).await?;

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
        let mut target_epoch = start_epoch + 2;
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

        // Wait 2 epochs before changing stake distribution, so that we use at least one original stake distribution
        target_epoch += 2;
        self.toolkit
            .wait
            .for_aggregator_at_target_epoch(
                leader_aggregator,
                target_epoch,
                "epoch after which the stake distribution will change".to_string(),
            )
            .await?;

        // Delegate some stakes to pools
        let delegation_round = 1;
        self.toolkit
            .exec
            .delegate_stakes_to_pools(infrastructure.devnet(), delegation_round)
            .await?;

        Ok(())
    }

    pub async fn run_scenario(
        &self,
        aggregator: &Aggregator,
        infrastructure: &MithrilInfrastructure,
    ) -> StdResult<()> {
        let chain_observer = aggregator.chain_observer();
        let start_epoch = chain_observer.get_current_epoch().await?.unwrap_or_default();

        // Wait 2 epochs before changing protocol parameters
        let mut target_epoch = start_epoch + 2;
        self.toolkit
            .wait
            .for_aggregator_at_target_epoch(
                aggregator,
                target_epoch,
                "epoch after which the protocol parameters will change".to_string(),
            )
            .await?;

        if aggregator.is_first() || aggregator.version().is_below("0.7.94") {
            // A certificate chain lagging one epoch behind the chain tip is normal, but a restart
            // crossing an epoch boundary before the current epoch is certified would create an
            // unrecoverable epoch gap and block the aggregator
            let current_epoch = chain_observer.get_current_epoch().await?.unwrap_or_default();
            self.toolkit
                .check
                .certificate
                .is_creating_certificate_with_min_epoch(aggregator, current_epoch)
                .await?;

            self.toolkit
                .exec
                .update_protocol_parameters(aggregator, infrastructure.aggregate_signature_type())
                .await?;
        }

        // Wait 6 epochs after protocol parameters update, so that we make sure that we use new protocol parameters as well as new stake distribution a few times
        target_epoch += 6;
        self.toolkit.wait.for_aggregator_at_target_epoch(
            aggregator,
            target_epoch,
            "epoch after which the certificate chain will be long enough to catch most common troubles with stake distribution and protocol parameters".to_string(),
        )
        .await?;

        // Verify that artifacts are produced and signed correctly
        let mut target_epoch = self
            .verify_artifacts_production(target_epoch, aggregator, infrastructure)
            .await?;

        // Verify that artifacts are produced and signed correctly after era switch
        if let Some(next_era) = &self.next_era {
            // Switch to next era
            if aggregator.is_first() {
                infrastructure.register_switch_to_next_era(next_era).await?;
            }
            target_epoch += 5;
            self.toolkit
                .wait
                .for_aggregator_at_target_epoch(
                    aggregator,
                    target_epoch,
                    "epoch after which the era switch will have triggered".to_string(),
                )
                .await?;

            // Proceed to a re-genesis of the certificate chain
            if self.regenesis_on_era_switch {
                self.toolkit.exec.bootstrap_genesis_certificate(aggregator).await?;
                target_epoch += 5;
                self.toolkit
                    .wait
                    .for_aggregator_at_target_epoch(
                        aggregator,
                        target_epoch,
                        "epoch after which the re-genesis on era switch will be completed"
                            .to_string(),
                    )
                    .await?;
            }

            // Verify that artifacts are produced and signed correctly
            self.verify_artifacts_production(target_epoch, aggregator, infrastructure)
                .await?;
        }

        // Check the ledger snapshot conversion step using utxo-hd snapshot-converter
        if self.check_client_cli_snapshot_converter {
            let mut client = infrastructure.build_client(aggregator).await?;
            self.toolkit
                .check
                .client_can_convert_the_ledger_snapshot(
                    &mut client,
                    aggregator.full_node(),
                    infrastructure.devnet().artifacts_dir(),
                    NodeVersion::new(infrastructure.cardano_node_version().clone()),
                )
                .await?;
        }

        Ok(())
    }

    async fn verify_artifacts_production(
        &self,
        target_epoch: Epoch,
        aggregator: &Aggregator,
        infrastructure: &MithrilInfrastructure,
    ) -> StdResult<Epoch> {
        let mut client = infrastructure.build_client(aggregator).await?;

        let expected_epoch_min = target_epoch - 3;
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
        if self.is_signing_cardano_database {
            self.toolkit
                .check
                .cardano_database
                .is_certified_and_verified(
                    aggregator,
                    &mut client,
                    expected_epoch_min,
                    infrastructure.signers().len(),
                )
                .await?;
        }

        // Verify that Cardano transactions artifacts are produced and signed correctly
        if self.is_signing_cardano_transactions {
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
        if self.is_signing_cardano_blocks_transactions {
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
        if self.is_signing_cardano_stake_distribution {
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
