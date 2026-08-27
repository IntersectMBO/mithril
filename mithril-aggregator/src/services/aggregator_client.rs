use async_trait::async_trait;

use mithril_aggregator_client::{
    AggregatorHttpClient,
    query::{GetCertificateQuery, GetCertificatesListQuery, GetEpochSettingsQuery},
};
use mithril_common::{StdResult, entities::Certificate, messages::TryFromMessageAdapter};

use crate::entities::LeaderAggregatorEpochSettings;
use crate::message_adapters::FromEpochSettingsAdapter;
use crate::services::{LeaderAggregatorClient, RemoteCertificateRetriever};

#[async_trait]
impl LeaderAggregatorClient for AggregatorHttpClient {
    async fn retrieve_epoch_settings(&self) -> StdResult<Option<LeaderAggregatorEpochSettings>> {
        let epoch_settings = self.send(GetEpochSettingsQuery::current()).await?;
        FromEpochSettingsAdapter::try_adapt(epoch_settings).map(Some)
    }
}

#[async_trait]
impl RemoteCertificateRetriever for AggregatorHttpClient {
    async fn get_latest_certificate_details(&self) -> StdResult<Option<Certificate>> {
        let latest_certificates_list = self.send(GetCertificatesListQuery::latest()).await?;

        match latest_certificates_list.first() {
            None => Ok(None),
            Some(latest_certificate_list_item) => {
                self.get_certificate_details(&latest_certificate_list_item.hash).await
            }
        }
    }

    async fn get_genesis_certificate_details(&self) -> StdResult<Option<Certificate>> {
        match self.send(GetCertificateQuery::latest_genesis()).await? {
            Some(message) => Ok(Some(message.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_certificate_details(&self, hash: &str) -> StdResult<Option<Certificate>> {
        match self.send(GetCertificateQuery::by_hash(hash)).await? {
            Some(message) => Ok(Some(message.try_into()?)),
            None => Ok(None),
        }
    }
}
