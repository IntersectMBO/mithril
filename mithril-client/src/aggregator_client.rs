//! Mechanisms to exchange data with an aggregator.
//!

use anyhow::Context;
use async_trait::async_trait;

use mithril_aggregator_client::AggregatorHttpClient;

#[cfg(feature = "unstable")]
use mithril_aggregator_client::query::{
    GetCardanoBlockProofQuery, GetCardanoBlocksTransactionsListQuery,
    GetCardanoBlocksTransactionsQuery, GetCardanoTransactionProofV2Query,
};

use mithril_aggregator_client::query::{
    GetAggregatorFeaturesQuery, GetAggregatorStatusQuery, GetCardanoDatabaseListQuery,
    GetCardanoDatabaseQuery, GetCardanoStakeDistributionQuery,
    GetCardanoStakeDistributionsListQuery, GetCardanoTransactionProofQuery,
    GetCardanoTransactionQuery, GetCardanoTransactionsListQuery, GetCertificateQuery,
    GetCertificatesListQuery, GetMithrilStakeDistributionQuery,
    GetMithrilStakeDistributionsListQuery,
    PostIncrementCardanoDatabaseAncillaryRestoredStatisticQuery,
    PostIncrementCardanoDatabaseImmutablesRestoredStatisticQuery,
    PostIncrementCardanoDatabaseRestorationStatisticQuery,
};

#[cfg(feature = "unstable")]
use crate::{
    CardanoBlocksProofs, CardanoBlocksTransactionsSnapshot,
    CardanoBlocksTransactionsSnapshotListItem, CardanoTransactionsProofsV2,
    cardano_block_client::CardanoBlockAggregatorRequest,
    cardano_transaction_v2_client::CardanoTransactionV2AggregatorRequest,
};

use crate::{
    CardanoDatabaseSnapshot, CardanoDatabaseSnapshotListItem, CardanoStakeDistribution,
    CardanoStakeDistributionListItem, CardanoTransactionSnapshot,
    CardanoTransactionSnapshotListItem, CardanoTransactionsProofs, MithrilCertificate,
    MithrilCertificateListItem, MithrilResult, MithrilStakeDistribution,
    MithrilStakeDistributionListItem, common::EpochSpecifier, era::FetchedEra,
};

use crate::{
    cardano_database_client::CardanoDatabaseAggregatorRequest,
    cardano_stake_distribution_client::CardanoStakeDistributionAggregatorRequest,
    cardano_transaction_client::CardanoTransactionAggregatorRequest,
    certificate_client::CertificateAggregatorRequest, era::EraFetcher,
    mithril_stake_distribution_client::MithrilStakeDistributionAggregatorRequest,
};

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CardanoDatabaseAggregatorRequest for AggregatorHttpClient {
    async fn list_latest(&self) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.send(GetCardanoDatabaseListQuery::latest())
            .await
            .with_context(|| "Failed to list latest Cardano database v2 snapshots")
    }

    async fn list_by_epoch(
        &self,
        specifier: EpochSpecifier,
    ) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.send(GetCardanoDatabaseListQuery::for_epoch(specifier))
            .await
            .with_context(|| {
                format!("Failed to list Cardano database v2 snapshots for epoch '{specifier}'")
            })
    }

    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<CardanoDatabaseSnapshot>> {
        self.send(GetCardanoDatabaseQuery::by_hash(hash))
            .await
            .with_context(|| {
                format!("Failed to get Cardano database v2 snapshots with hash '{hash}'")
            })
    }

    async fn increment_cardano_database_complete_restoration_statistic(&self) -> MithrilResult<()> {
        self.send(PostIncrementCardanoDatabaseRestorationStatisticQuery::complete())
            .await
            .with_context(|| "Failed to increment Cardano database complete restoration statistic")
    }

    async fn increment_cardano_database_partial_restoration_statistic(&self) -> MithrilResult<()> {
        self.send(PostIncrementCardanoDatabaseRestorationStatisticQuery::partial())
            .await
            .with_context(|| "Failed to increment Cardano database partial restoration statistic")
    }

    async fn increment_immutables_snapshot_restored_statistic(
        &self,
        number_of_immutable_files_restored: u32,
    ) -> MithrilResult<()> {
        self.send(PostIncrementCardanoDatabaseImmutablesRestoredStatisticQuery::new(number_of_immutable_files_restored))
            .await
            .with_context(|| format!("Failed to increment Cardano database immutable files restored statistic, number of immutable files restored: '{number_of_immutable_files_restored}'"))
    }

    async fn increment_ancillary_downloaded_statistic(&self) -> MithrilResult<()> {
        self.send(PostIncrementCardanoDatabaseAncillaryRestoredStatisticQuery)
            .await
            .with_context(
                || "Failed to increment Cardano database ancillary files restored statistic",
            )
    }

    async fn get_ipfs_share(&self) -> MithrilResult<Option<u8>> {
        let aggregator_features = self
            .send(GetAggregatorFeaturesQuery::current())
            .await
            .with_context(|| "Failed to get aggregator features")?;

        Ok(aggregator_features
            .cardano_database_distribution
            .and_then(|cdd| cdd.ipfs_share))
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CardanoStakeDistributionAggregatorRequest for AggregatorHttpClient {
    async fn list_latest(&self) -> MithrilResult<Vec<CardanoStakeDistributionListItem>> {
        self.send(GetCardanoStakeDistributionsListQuery::latest())
            .await
            .with_context(|| "Failed to list latest Cardano stake distributions")
    }

    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<CardanoStakeDistribution>> {
        self.send(GetCardanoStakeDistributionQuery::by_hash(hash))
            .await
            .with_context(|| format!("Failed to get Cardano stake distribution with hash '{hash}'"))
    }

    async fn get_by_epoch(
        &self,
        specifier: EpochSpecifier,
    ) -> MithrilResult<Option<CardanoStakeDistribution>> {
        self.send(GetCardanoStakeDistributionQuery::for_epoch(specifier))
            .await
            .with_context(|| {
                format!("Failed to get Cardano stake distribution for epoch '{specifier}'")
            })
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CardanoTransactionAggregatorRequest for AggregatorHttpClient {
    async fn get_proof(
        &self,
        hashes: &[String],
    ) -> MithrilResult<Option<CardanoTransactionsProofs>> {
        self.send(GetCardanoTransactionProofQuery::for_hashes(hashes))
            .await
            .with_context(|| {
                format!("Failed to get Cardano transactions proofs for hashes '{hashes:?}'")
            })
    }

    async fn list_latest_snapshots(
        &self,
    ) -> MithrilResult<Vec<CardanoTransactionSnapshotListItem>> {
        self.send(GetCardanoTransactionsListQuery::latest())
            .await
            .with_context(|| "Failed to list latest Cardano transactions snapshots")
    }

    async fn get_snapshot(&self, hash: &str) -> MithrilResult<Option<CardanoTransactionSnapshot>> {
        self.send(GetCardanoTransactionQuery::by_hash(hash))
            .await
            .with_context(|| {
                format!("Failed to get Cardano transaction snapshot with hash '{hash}'")
            })
    }
}

cfg_unstable! {
    #[cfg_attr(target_family = "wasm", async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait)]
    impl CardanoTransactionV2AggregatorRequest for AggregatorHttpClient {
        async fn get_proof(
            &self,
            hashes: &[String],
        ) -> MithrilResult<Option<CardanoTransactionsProofsV2>> {
            self.send(GetCardanoTransactionProofV2Query::for_hashes(hashes))
                .await
                .with_context(|| {
                    format!("Failed to get Cardano transactions proofs for hashes '{hashes:?}'")
                })
        }

        async fn list_latest_snapshots(
            &self,
        ) -> MithrilResult<Vec<CardanoBlocksTransactionsSnapshotListItem>> {
            self.send(GetCardanoBlocksTransactionsListQuery::latest())
                .await
                .with_context(|| "Failed to list latest Cardano transactions v2 snapshots")
        }

        async fn get_snapshot(
            &self,
            hash: &str,
        ) -> MithrilResult<Option<CardanoBlocksTransactionsSnapshot>> {
            self.send(GetCardanoBlocksTransactionsQuery::by_hash(hash))
                .await
                .with_context(|| {
                    format!("Failed to get Cardano transaction v2 snapshot with hash '{hash}'")
                })
        }
    }

    #[cfg_attr(target_family = "wasm", async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait)]
    impl CardanoBlockAggregatorRequest for AggregatorHttpClient {
        async fn get_proof(&self, hashes: &[String]) -> MithrilResult<Option<CardanoBlocksProofs>> {
            self.send(GetCardanoBlockProofQuery::for_hashes(hashes))
                .await
                .with_context(|| format!("Failed to get Cardano blocks proofs for hashes '{hashes:?}'"))
        }

        async fn list_latest_snapshots(
            &self,
        ) -> MithrilResult<Vec<CardanoBlocksTransactionsSnapshotListItem>> {
            self.send(GetCardanoBlocksTransactionsListQuery::latest())
                .await
                .with_context(|| "Failed to list latest Cardano blocks snapshots")
        }

        async fn get_snapshot(
            &self,
            hash: &str,
        ) -> MithrilResult<Option<CardanoBlocksTransactionsSnapshot>> {
            self.send(GetCardanoBlocksTransactionsQuery::by_hash(hash))
                .await
                .with_context(|| format!("Failed to get Cardano block snapshot with hash '{hash}'"))
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateAggregatorRequest for AggregatorHttpClient {
    async fn list_latest(&self) -> MithrilResult<Vec<MithrilCertificateListItem>> {
        self.send(GetCertificatesListQuery::latest())
            .await
            .with_context(|| "Failed to list latest certificates")
    }

    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<MithrilCertificate>> {
        self.send(GetCertificateQuery::by_hash(hash))
            .await
            .with_context(|| format!("Failed to get certificate with hash '{hash}'"))
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl EraFetcher for AggregatorHttpClient {
    async fn fetch_current_era(&self) -> MithrilResult<FetchedEra> {
        let aggregator_status = self
            .send(GetAggregatorStatusQuery::current())
            .await
            .with_context(|| "Failed to get aggregator status")?;

        Ok(FetchedEra {
            era: aggregator_status.mithril_era.to_string(),
        })
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl MithrilStakeDistributionAggregatorRequest for AggregatorHttpClient {
    async fn list_latest(&self) -> MithrilResult<Vec<MithrilStakeDistributionListItem>> {
        self.send(GetMithrilStakeDistributionsListQuery::latest())
            .await
            .with_context(|| "Failed to list latest Mithril stake distributions")
    }

    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<MithrilStakeDistribution>> {
        self.send(GetMithrilStakeDistributionQuery::by_hash(hash))
            .await
            .with_context(|| format!("Failed to get Mithril stake distribution with hash '{hash}'"))
    }
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;
    use serde_json::json;

    use mithril_common::messages::{
        AggregatorFeaturesMessage, AggregatorStatusMessage, CardanoDatabaseDistribution,
    };

    use crate::common::{SupportedEra, test::Dummy};
    use crate::test_utils::TestLogger;

    use super::*;

    fn setup_server_and_client() -> (MockServer, AggregatorHttpClient) {
        let server = MockServer::start();
        let client = AggregatorHttpClient::builder(server.base_url())
            .with_logger(TestLogger::stdout())
            .build()
            .unwrap();

        (server, client)
    }

    #[tokio::test]
    async fn extract_mithril_era_from_status_response() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.any_request();
            then.status(200).json_body(json!(AggregatorStatusMessage {
                mithril_era: SupportedEra::Lagrange,
                ..Dummy::dummy()
            }));
        });

        let mithril_era = client.fetch_current_era().await.unwrap();
        assert_eq!(mithril_era.era, SupportedEra::Lagrange.to_string());
    }

    #[tokio::test]
    async fn extract_cardano_database_distribution_from_feature_response() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.any_request();
            then.status(200).json_body(json!(AggregatorFeaturesMessage {
                cardano_database_distribution: Some(CardanoDatabaseDistribution {
                    supported_locations: vec![],
                    ipns_record: None,
                    ipfs_share: Some(35),
                }),
                ..Dummy::dummy()
            }));
        });

        let share = client.get_ipfs_share().await.unwrap();
        assert_eq!(Some(35), share);
    }
}
