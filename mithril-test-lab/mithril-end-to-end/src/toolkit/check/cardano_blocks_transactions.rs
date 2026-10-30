use anyhow::anyhow;
use slog_scope::{info, warn};

use mithril_common::{
    StdResult,
    entities::{BlockHash, Epoch, TransactionHash},
    messages::CardanoBlocksTransactionsSnapshotListItemMessage,
};

use crate::{
    Aggregator, CardanoBlockCommand, CardanoTransactionV2Command, Client, ClientCommand,
    toolkit::{CheckCertificateToolkit, ScenarioToolkitContext},
};

use super::utils;

#[derive(Debug, Clone)]
pub struct CheckCardanoBlocksTransactionsToolkit {
    context: ScenarioToolkitContext,
}

impl CheckCardanoBlocksTransactionsToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { context }
    }

    pub async fn is_certified_and_verified(
        &self,
        aggregator: &Aggregator,
        client: &mut Client,
        expected_epoch_min: Epoch,
        total_signers_expected: usize,
        block_hashes: Vec<BlockHash>,
        tx_hashes: Vec<TransactionHash>,
    ) -> StdResult<()> {
        let certificate_toolkit = CheckCertificateToolkit::new(self.context.clone());

        let artifact = self.wait_for_artifact(aggregator, expected_epoch_min).await?;
        certificate_toolkit
            .is_creating_certificate_with_enough_signers(
                aggregator,
                &artifact.certificate_hash,
                total_signers_expected,
            )
            .await?;
        self.verify_transactions_with_client(client, tx_hashes).await?;
        self.verify_blocks_with_client(client, block_hashes).await?;

        Ok(())
    }

    pub async fn wait_for_artifact(
        &self,
        aggregator: &Aggregator,
        expected_epoch_min: Epoch,
    ) -> StdResult<CardanoBlocksTransactionsSnapshotListItemMessage> {
        utils::wait_for_latest_artifact_with_condition(
            "Cardano blocks transactions",
            "/artifact/cardano-blocks-transactions",
            |a: &CardanoBlocksTransactionsSnapshotListItemMessage| a.hash.clone(),
            &self.context,
            aggregator,
            |a| a.epoch >= expected_epoch_min,
            |last_invalid_artifact| {
                format!(
                    "no Cardano blocks transactions found with epoch >= {expected_epoch_min}\nlast artifact: {last_invalid_artifact:?}"
                )
            },
        )
        .await
    }

    pub async fn verify_transactions_with_client(
        &self,
        client: &mut Client,
        tx_hashes: Vec<TransactionHash>,
    ) -> StdResult<()> {
        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct ClientCardanoTransactionCertifyResult {
            certified_transactions: Vec<CertifiedTransactionV2>,
            non_certified_transactions: Vec<TransactionHash>,
        }

        #[derive(Debug, serde::Deserialize)]
        struct CertifiedTransactionV2 {
            transaction_hash: String,
        }

        if !client.version().is_above_or_equal("0.13.1") {
            warn!(
                "Client version is below 0.13.1, skipping `cardano-transaction certify --backend v2` check"
            );
            return Ok(());
        }

        let tx_certify_output = client
            .run(ClientCommand::CardanoTransactionV2(
                CardanoTransactionV2Command::Certify {
                    tx_hashes: tx_hashes.clone(),
                },
            ))
            .await?;
        info!("Client verified the Cardano transactions V2"; "tx_hashes" => ?tx_hashes);

        let result: ClientCardanoTransactionCertifyResult =
            tx_certify_output.read_output_as_json()?;

        info!("Asserting that all Cardano transactions V2 were verified by the Client...");
        let certified_tx_hashes_result: Vec<String> = result
            .certified_transactions
            .iter()
            .map(|tx| tx.transaction_hash.clone())
            .collect();

        if tx_hashes.iter().all(|tx| certified_tx_hashes_result.contains(tx)) {
            Ok(())
        } else {
            Err(anyhow!(
                "Not all transactions V2 were certified:\n'{:#?}'",
                result,
            ))
        }
    }

    pub async fn verify_blocks_with_client(
        &self,
        client: &mut Client,
        block_hashes: Vec<BlockHash>,
    ) -> StdResult<()> {
        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct ClientCardanoBlockCertifyResult {
            certified_blocks: Vec<CertifiedBlock>,
            non_certified_blocks: Vec<BlockHash>,
        }

        #[derive(Debug, serde::Deserialize)]
        struct CertifiedBlock {
            block_hash: String,
        }

        if !client.version().is_above_or_equal("0.13.1") {
            warn!("Client version is below 0.13.1, skipping `cardano-block certify` check");
            return Ok(());
        }

        let block_certify_output = client
            .run(ClientCommand::CardanoBlock(CardanoBlockCommand::Certify {
                block_hashes: block_hashes.clone(),
            }))
            .await?;
        info!("Client verified the Cardano blocks"; "block_hashes" => ?block_hashes);
        let result: ClientCardanoBlockCertifyResult = block_certify_output.read_output_as_json()?;

        info!("Asserting that all Cardano blocks were verified by the Client...");
        let certified_blocks_hashes_result: Vec<String> = result
            .certified_blocks
            .iter()
            .map(|block| block.block_hash.clone())
            .collect();

        if block_hashes
            .iter()
            .all(|block| certified_blocks_hashes_result.contains(block))
        {
            Ok(())
        } else {
            Err(anyhow!("Not all blocks were certified:\n'{:#?}'", result,))
        }
    }
}
