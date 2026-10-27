use anyhow::{Context, anyhow};
use reqwest::Url;
use slog_scope::{info, warn};

use mithril_common::{
    StdResult,
    entities::{Epoch, EpochSpecifier, ImmutableFileNumber},
    messages::{CardanoDatabaseDigestListMessage, CardanoDatabaseSnapshotListItemMessage},
};

use crate::{
    Aggregator, CardanoDbV2Command, Client, ClientCommand, KuboNode,
    mithril::IPNS_KEY_NAME_FOR_SNAPSHOT,
    poll_until,
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
        client_ipfs_node: Option<&KuboNode>,
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
        self.verify_with_client(
            client,
            client_ipfs_node.map(|n| n.rpc_url.clone()),
            &artifact.hash,
        )
        .await?;

        if aggregator.is_leader()
            && let Some(client_kubo_node) = client_ipfs_node
        {
            let aggregator_kubo_node = aggregator.ipfs_kubo_node().with_context(|| {
                format!(
                    "IPFS devnet is enabled but {} has no Kubo node",
                    aggregator.name()
                )
            })?;
            self.check_immutable_published_to_ipns(
                aggregator,
                aggregator_kubo_node,
                client_kubo_node,
                artifact.beacon.immutable_file_number,
            )
            .await?;
        }

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
            let cdb_download_with_ipfs_output = client
                .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::Download {
                    hash: hash.to_string(),
                    ipfs_rpc_url,
                }))
                .await?;
            info!("Client downloaded & restored the cardano database snapshot"; "hash" => &hash, "storage_source" => "ipfs");

            let number_of_ipfs_downloads = cdb_download_with_ipfs_output
                .count_matching_lines_in_logs(
                    "POST Kubo RPC, ipfs_path: ipfs://[a-zA-Z0-9]+/[0-9]+\\.tar\\.zst, route: api/v0/cat",
                )
                .await?;

            if number_of_ipfs_downloads == 0 {
                anyhow::bail!(
                    "Expected to download at least one immutable from IPFS, but all immutables where fetched from local",
                );
            }
        }

        Ok(())
    }

    pub async fn check_immutable_published_to_ipns(
        &self,
        aggregator: &Aggregator,
        aggregator_kubo_node: &KuboNode,
        client_kubo_node: &KuboNode,
        immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<()> {
        info!(
            "Checking IPNS publication of immutable file #{immutable_file_number}";
            "aggregator" => &aggregator.name(),
        );

        let ipns_key_id = aggregator_kubo_node
            .get_ipns_key_id(IPNS_KEY_NAME_FOR_SNAPSHOT)
            .await?
            .with_context(|| {
                format!(
                    "Failed to get IPNS key ID for key '{IPNS_KEY_NAME_FOR_SNAPSHOT}' and {}",
                    aggregator.name()
                )
            })?;
        info!("IPNS key ID for key '{IPNS_KEY_NAME_FOR_SNAPSHOT}': '{ipns_key_id}'"; "aggregator" => &aggregator.name());

        let ipns_name = format!("/ipns/{ipns_key_id}");
        let ipfs_file_name_for_immutable = format!("{immutable_file_number:0>5}.tar.zst");
        let mut last_error = None;

        match poll_until!(
            self.context.existing_artifact_fetch_timeout(),
            self.context.poll_backoff(),
            {
                match client_kubo_node.resolve_file_in_ipns_dir(
                    &ipns_name,
                    &ipfs_file_name_for_immutable,
                )
                .await
                {
                    Ok(ipfs_dir_path) => Ok(Some(ipfs_dir_path)),
                    Err(error) => {
                        warn!("IPNS publication not yet available, retrying"; "error" => ?error, "aggregator" => &aggregator.name());
                        last_error = Some(error);
                        Ok(None)
                    }
                }
            }
        ) {
            AttemptResult::Ok(ipfs_dir_path) => {
                info!(
                    "Success, '{ipns_name}' resolves to '{ipfs_dir_path}' that contains immutable {immutable_file_number:0>5}";
                    "aggregator" => &aggregator.name()
                );
                Ok(())
            }
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => {
                let error = anyhow!(
                    "Timeout exhausted while checking that '{ipns_name}' contains immutable {immutable_file_number:0>5}"
                );
                Err(match last_error {
                    Some(last_error) => last_error.context(error),
                    None => error,
                })
            }
        }
        .with_context(|| format!("Checking IPNS publication of aggregator `{}`", aggregator.name()))
    }
}
