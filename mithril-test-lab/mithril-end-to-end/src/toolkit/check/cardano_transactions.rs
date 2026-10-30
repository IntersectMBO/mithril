use anyhow::anyhow;
use slog_scope::info;

use mithril_common::{
    StdResult,
    entities::{Epoch, TransactionHash},
    messages::CardanoTransactionSnapshotListItemMessage,
};

use crate::{
    Aggregator, CardanoTransactionCommand, Client, ClientCommand,
    toolkit::{CheckCertificateToolkit, ScenarioToolkitContext},
};

use super::utils;

#[derive(Debug, Clone)]
pub struct CheckCardanoTransactionsToolkit {
    context: ScenarioToolkitContext,
}

impl CheckCardanoTransactionsToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { context }
    }

    pub async fn is_certified_and_verified(
        &self,
        aggregator: &Aggregator,
        client: &mut Client,
        expected_epoch_min: Epoch,
        total_signers_expected: usize,
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
        self.verify_with_client(client, tx_hashes).await?;

        Ok(())
    }

    pub async fn wait_for_artifact(
        &self,
        aggregator: &Aggregator,
        expected_epoch_min: Epoch,
    ) -> StdResult<CardanoTransactionSnapshotListItemMessage> {
        utils::wait_for_latest_artifact_with_condition(
            "Cardano transactions",
            "/artifact/cardano-transactions",
            |a: &CardanoTransactionSnapshotListItemMessage| a.hash.clone(),
            &self.context,
            aggregator,
            |a| a.epoch >= expected_epoch_min,
            |last_invalid_artifact| {
                format!(
                    "no Cardano transactions found with epoch >= {expected_epoch_min}\nlast artifact: {last_invalid_artifact:?}"
                )
            },
        )
        .await
    }

    pub async fn verify_with_client(
        &self,
        client: &mut Client,
        tx_hashes: Vec<TransactionHash>,
    ) -> StdResult<()> {
        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct ClientCardanoTransactionCertifyResult {
            certified_transactions: Vec<TransactionHash>,
            non_certified_transactions: Vec<TransactionHash>,
        }

        let certify_output = client
            .run(ClientCommand::CardanoTransaction(
                CardanoTransactionCommand::Certify {
                    tx_hashes: tx_hashes.clone(),
                },
            ))
            .await?;
        info!("Client verified the Cardano transactions"; "tx_hashes" => ?tx_hashes);

        let result: ClientCardanoTransactionCertifyResult = certify_output.read_output_as_json()?;

        info!("Asserting that all Cardano transactions were verified by the Client...");
        if tx_hashes.iter().all(|tx| result.certified_transactions.contains(tx)) {
            Ok(())
        } else {
            Err(anyhow!(
                "Not all transactions were certified:\n'{:#?}'",
                result,
            ))
        }
    }
}
