use std::path::Path;

use anyhow::{Context, anyhow};
use slog_scope::{info, warn};
use thiserror::Error;

use mithril_cardano_node_internal_database::IMMUTABLE_DIR;
use mithril_cardano_node_internal_database::entities::ImmutableFile;
use mithril_cardano_node_leios::entities::CertifyingBlock;
use mithril_cardano_node_leios::{
    CertifyingBlocksReader, LeiosImmutableDatabase, LeiosImmutableDatabaseLayoutProvider,
};
use mithril_common::{
    StdResult,
    entities::{BlockNumber, Epoch, EpochSpecifier, ImmutableFileNumber},
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

/// Error raised when the Leios database restored by the client does not match the restored immutable files.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RestoredLeiosDatabaseError {
    /// No restored immutable file holds a certifying block, so the run proves nothing.
    #[error("No block certifies an endorser block in the restored immutable files")]
    NoCertifyingBlock,

    /// The restored Leios database misses the closure of a certified endorser block.
    #[error(
        "No closure restored for endorser block {endorser_block_hash} certified by block {block_number}"
    )]
    MissingClosure {
        /// Hash of the endorser block.
        endorser_block_hash: String,

        /// Number of the certifying block.
        block_number: BlockNumber,
    },
}

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
        self.verify_with_client(client, client_ipfs_node, &artifact.hash)
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

    /// Checks that the database restored by the client holds the closure of every endorser block
    /// certified in its immutable files, and that at least one endorser block is certified.
    pub fn leios_closures_are_restored(
        &self,
        client: &Client,
        cardano_node_version: &semver::Version,
    ) -> StdResult<()> {
        let certifying_blocks = Self::list_certifying_blocks_with_restored_closure(
            &client.cardano_database_v2_download_dir(),
            cardano_node_version,
        )
        .with_context(|| "Checking that the Leios closures are restored by the client")?;
        info!("Client restored the Leios closures of the certifying blocks"; "closures" => certifying_blocks.len(), "last_certifying_block_number" => ?certifying_blocks.last().map(|block| block.block_number));

        Ok(())
    }

    /// Lists the blocks of the restored immutable files that certify an endorser block, after checking
    /// that there is at least one and that each has its closure in the restored Leios database.
    ///
    /// The last restored immutable file is the copy of the partial immutable file of the ancillary
    /// archive: it is read up to its last whole block.
    fn list_certifying_blocks_with_restored_closure(
        restored_db_directory: &Path,
        cardano_node_version: &semver::Version,
    ) -> StdResult<Vec<CertifyingBlock>> {
        let partial_immutable_file_number = ImmutableFile::list_all_in_dir(restored_db_directory)?
            .last()
            .map(|file| file.number)
            .ok_or_else(|| {
                anyhow!(
                    "No immutable file restored in '{}'",
                    restored_db_directory.display()
                )
            })?;
        let immutable_directory = restored_db_directory.join(IMMUTABLE_DIR);
        let mut certifying_blocks = match partial_immutable_file_number.checked_sub(1) {
            Some(last_completed_immutable_file_number) => CertifyingBlocksReader::list_range(
                &immutable_directory,
                0..=last_completed_immutable_file_number,
            )?,
            None => Vec::new(),
        };
        certifying_blocks.extend(
            CertifyingBlocksReader::list_partial_with_previous_chunk_dir(
                &immutable_directory,
                &immutable_directory,
                partial_immutable_file_number,
            )?,
        );
        if certifying_blocks.is_empty() {
            return Err(RestoredLeiosDatabaseError::NoCertifyingBlock.into());
        }

        let database = LeiosImmutableDatabase::open_read_only(
            restored_db_directory,
            LeiosImmutableDatabaseLayoutProvider::layout_for_cardano_node_version(
                cardano_node_version,
            )?,
        )?;
        for certifying_block in &certifying_blocks {
            if !database.has_closure(&certifying_block.endorser_block_hash)? {
                return Err(RestoredLeiosDatabaseError::MissingClosure {
                    endorser_block_hash: certifying_block.endorser_block_hash.clone(),
                    block_number: certifying_block.block_number,
                }
                .into());
            }
        }

        Ok(certifying_blocks)
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
        client_ipfs_node: Option<&KuboNode>,
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
                ipfs_rpc_auth_token: None,
            }))
            .await?;
        info!("Client downloaded & restored the cardano database snapshot"; "hash" => &hash, "storage_source" => "local");

        if let Some(client_ipfs_node) = client_ipfs_node {
            let cdb_download_with_ipfs_output = client
                .run(ClientCommand::CardanoDbV2(CardanoDbV2Command::Download {
                    hash: hash.to_string(),
                    ipfs_rpc_url: Some(client_ipfs_node.rpc_url.clone()),
                    ipfs_rpc_auth_token: client_ipfs_node.rpc_auth_token.clone(),
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
                    "Expected to download at least one immutable from IPFS, but all immutables were fetched from local",
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

#[cfg(test)]
mod tests {
    use mithril_cardano_node_leios::test::LeiosFixtures;
    use mithril_common::test::TempDir;

    use super::*;

    const LEIOS_CARDANO_NODE_VERSION: semver::Version = semver::Version::new(11, 2, 0);

    #[test]
    fn list_certifying_blocks_with_restored_closure_returns_the_certifying_blocks() {
        let db_directory = TempDir::create("check_cardano_database", "leios_closures_restored");
        LeiosFixtures::copy_to(&db_directory);

        let certifying_blocks =
            CheckCardanoDatabaseToolkit::list_certifying_blocks_with_restored_closure(
                &db_directory,
                &LEIOS_CARDANO_NODE_VERSION,
            )
            .unwrap();

        assert_eq!(
            certifying_blocks
                .iter()
                .map(|block| block.block_number)
                .collect::<Vec<_>>(),
            vec![BlockNumber(36), BlockNumber(47), BlockNumber(55), BlockNumber(59)]
        );
    }

    #[test]
    fn list_certifying_blocks_with_restored_closure_reads_the_partial_last_immutable_file_up_to_its_last_whole_block()
     {
        let db_directory = TempDir::create("check_cardano_database", "leios_torn_partial_file");
        LeiosFixtures::copy_to(&db_directory);
        let last_chunk_path = db_directory.join(IMMUTABLE_DIR).join("00007.chunk");
        let last_chunk = std::fs::read(&last_chunk_path).unwrap();
        std::fs::write(&last_chunk_path, &last_chunk[..last_chunk.len() - 10]).unwrap();

        let certifying_blocks =
            CheckCardanoDatabaseToolkit::list_certifying_blocks_with_restored_closure(
                &db_directory,
                &LEIOS_CARDANO_NODE_VERSION,
            )
            .unwrap();

        assert_eq!(
            certifying_blocks
                .iter()
                .map(|block| block.block_number)
                .collect::<Vec<_>>(),
            vec![BlockNumber(36), BlockNumber(47), BlockNumber(55), BlockNumber(59)]
        );
    }

    #[test]
    fn list_certifying_blocks_with_restored_closure_fails_without_certifying_block() {
        let db_directory = TempDir::create("check_cardano_database", "leios_no_certifying_block");
        LeiosFixtures::copy_immutable_files_to(&db_directory, &[0, 1, 2, 3]);

        let error = CheckCardanoDatabaseToolkit::list_certifying_blocks_with_restored_closure(
            &db_directory,
            &LEIOS_CARDANO_NODE_VERSION,
        )
        .unwrap_err();

        assert_eq!(
            error.downcast_ref::<RestoredLeiosDatabaseError>(),
            Some(&RestoredLeiosDatabaseError::NoCertifyingBlock)
        );
    }

    #[test]
    fn list_certifying_blocks_with_restored_closure_fails_when_a_closure_is_missing() {
        let db_directory = TempDir::create("check_cardano_database", "leios_closure_missing");
        LeiosFixtures::copy_to(&db_directory);
        LeiosFixtures::delete_closure(
            &LeiosFixtures::open_node_connection(&db_directory),
            LeiosFixtures::ENDORSER_BLOCK_HASHES[1],
        );

        let error = CheckCardanoDatabaseToolkit::list_certifying_blocks_with_restored_closure(
            &db_directory,
            &LEIOS_CARDANO_NODE_VERSION,
        )
        .unwrap_err();

        assert_eq!(
            error.downcast_ref::<RestoredLeiosDatabaseError>(),
            Some(&RestoredLeiosDatabaseError::MissingClosure {
                endorser_block_hash: LeiosFixtures::ENDORSER_BLOCK_HASHES[1].to_string(),
                block_number: BlockNumber(47),
            })
        );
    }
}
