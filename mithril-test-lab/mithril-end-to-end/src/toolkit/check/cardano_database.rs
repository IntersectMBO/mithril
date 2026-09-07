use anyhow::{Context, anyhow};
use reqwest::Url;
use slog_scope::{info, warn};

use mithril_common::{
    StdResult,
    entities::{Epoch, EpochSpecifier},
    messages::{CardanoDatabaseDigestListMessage, CardanoDatabaseSnapshotListItemMessage},
};

use crate::{
    Aggregator, CardanoDbV2Command, Client, ClientCommand, poll_until,
    toolkit::{CheckCertificateToolkit, ScenarioToolkitContext},
    utils::AttemptResult,
};

use super::utils;

#[derive(Debug, Clone)]
pub struct CheckCardanoDatabaseToolkit {
    context: ScenarioToolkitContext,
}

impl CheckCardanoDatabaseToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { context }
    }

    pub async fn is_certified_and_verified(
        &self,
        aggregator: &Aggregator,
        client: &mut Client,
        ipfs_rpc_url: Option<Url>,
        expected_epoch_min: Epoch,
        total_signers_expected: usize,
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
        self.node_producing_cardano_database_digests_map(aggregator).await?;
        self.verify_with_client(client, ipfs_rpc_url, &artifact.hash).await?;

        Ok(())
    }

    pub async fn wait_for_artifact(
        &self,
        aggregator: &Aggregator,
        expected_epoch_min: Epoch,
    ) -> StdResult<CardanoDatabaseSnapshotListItemMessage> {
        utils::wait_for_latest_artifact_with_condition(
            "Cardano database snapshot",
            "/artifact/cardano-database",
            |a: &CardanoDatabaseSnapshotListItemMessage| a.hash.clone(),
            &self.context,
            aggregator,
            |a| a.beacon.epoch >= expected_epoch_min,
            |last_invalid_artifact| {
                format!(
                    "no Cardano database snapshot found with epoch >= {expected_epoch_min}\nlast artifact: {last_invalid_artifact:?}"
                )
            },
        )
        .await
    }

    pub async fn node_producing_cardano_database_digests_map(
        &self,
        aggregator: &Aggregator,
    ) -> StdResult<Vec<(String, String)>> {
        let url = format!(
            "{}/artifact/cardano-database/digests",
            aggregator.endpoint()
        );
        info!("Waiting for the aggregator to produce a Cardano database digests map"; "aggregator" => &aggregator.name());

        async fn fetch_cardano_database_digests_map(
            url: String,
        ) -> StdResult<Option<Vec<(String, String)>>> {
            match utils::get_json_response::<CardanoDatabaseDigestListMessage>(url)
                .await?
                .as_deref()
            {
                Ok(&[]) => Ok(None),
                Ok(cardano_database_digests_map) => Ok(Some(
                    cardano_database_digests_map
                        .iter()
                        .map(|item| (item.immutable_file_name.clone(), item.digest.clone()))
                        .collect(),
                )),
                Err(err) => Err(anyhow!("Invalid Cardano database digests map body: {err}",)),
            }
        }

        match poll_until!(self.context.artifact_production_timeout(), self.context.poll_backoff(), {
            fetch_cardano_database_digests_map(url.clone()).await
        }) {
            AttemptResult::Ok(cardano_database_digests_map) => {
                info!("Aggregator produced a Cardano database digests map"; "total_digests" => &cardano_database_digests_map.len(), "aggregator" => &aggregator.name());
                Ok(cardano_database_digests_map)
            }
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => Err(anyhow!(
            "Timeout exhausted assert_node_producing_cardano_database_digests_map, no response from `{url}`"
        )),
        }.with_context(|| {
            format!(
                "Requesting aggregator `{}`",
                aggregator.name()
            )
        })
    }

    pub async fn verify_with_client(
        &self,
        client: &mut Client,
        ipfs_rpc_url: Option<Url>,
        hash: &str,
    ) -> StdResult<()> {
        client
            .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::List))
            .await?;

        if client.version().is_above_or_equal("0.12.34") {
            client
                .run(ClientCommand::CardanoDbV2(
                    CardanoDbV2Command::ListPerEpoch {
                        epoch_specifier: EpochSpecifier::LatestMinusOffset(5),
                    },
                ))
                .await?;
        } else {
            warn!(
                "Client version is below 0.12.34, skipping `cardano-db snapshot list --epoch latest-5` check"
            );
        }

        client
            .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::Show {
                hash: hash.to_string(),
            }))
            .await?;
        info!("Client list & show the cardano database snapshot"; "hash" => &hash);

        client
            .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::Download {
                hash: hash.to_string(),
                ipfs_rpc_url: None,
            }))
            .await?;
        info!("Client downloaded & restored the cardano database snapshot"; "hash" => &hash, "storage_source" => "local");

        if ipfs_rpc_url.is_some() {
            client
                .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::Download {
                    hash: hash.to_string(),
                    ipfs_rpc_url,
                }))
                .await?;
            info!("Client downloaded & restored the cardano database snapshot"; "hash" => &hash, "storage_source" => "ipfs");
        }

        Ok(())
    }
}
