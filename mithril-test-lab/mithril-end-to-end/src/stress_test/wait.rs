use anyhow::anyhow;
use async_recursion::async_recursion;
use reqwest::StatusCode;
use serde::Deserialize;
use slog_scope::warn;
use std::time::Duration;
use tokio::time::sleep;

use mithril_common::{
    StdResult,
    entities::Epoch,
    messages::{
        CardanoDatabaseSnapshotListItemMessage, CertificateListItemMessage, EpochSettingsMessage,
        MithrilStakeDistributionListItemMessage,
    },
};

use crate::Aggregator;

#[async_recursion]
async fn request_first_list_item_with_expected_size<I>(
    url: &str,
    expected_size: usize,
) -> StdResult<I>
where
    for<'a> I: Deserialize<'a> + Sync + Send + Clone,
{
    sleep(Duration::from_millis(300)).await;

    match reqwest::get(url).await {
        Ok(response) => match response.status() {
            StatusCode::OK => match response.json::<Vec<I>>().await.as_deref() {
                Ok(list) if list.len() == expected_size => Ok(list.first().unwrap().clone()),
                Ok(list) if list.len() > expected_size => Err(anyhow!(
                    "Invalid size, expected {expected_size}, got {}",
                    list.len()
                )),
                Ok(_) => request_first_list_item_with_expected_size::<I>(url, expected_size).await,
                Err(err) => Err(anyhow!("Invalid list body : {err}")),
            },
            s if s.is_server_error() => {
                let message =
                    format!("Server error while waiting for the Aggregator, http code: {s}");
                warn!("{message}");
                Err(anyhow!(message))
            }
            _ => request_first_list_item_with_expected_size::<I>(url, expected_size).await,
        },
        Err(err) => Err(anyhow!(err).context(format!("Request to `{url}` failed"))),
    }
}

/// Wait for http response until timeout
pub async fn for_http_response(url: &str, timeout: Duration, message: &str) -> StdResult<()> {
    spin_while_waiting!(
        {
            while reqwest::get(url).await.is_err() {
                sleep(Duration::from_millis(300)).await;
            }
            Ok(())
        },
        timeout,
        message.to_owned(),
        format!("Aggregator did not get a response after {timeout:?} from '{url}'")
    )
}

/// Wait for the aggregator http server to start
pub async fn for_aggregator_http_server_to_start(
    aggregator: &Aggregator,
    timeout: Duration,
) -> StdResult<()> {
    for_http_response(
        &aggregator.endpoint(),
        timeout,
        "Waiting for the aggregator to start",
    )
    .await
}

/// Wait for a given epoch in the epoch settings until timeout
pub async fn for_epoch_settings_at_epoch(
    aggregator: &Aggregator,
    timeout: Duration,
    epoch: Epoch,
) -> StdResult<()> {
    let url = &format!("{}/epoch-settings", aggregator.endpoint());
    spin_while_waiting!(
        {
            while let Ok(response) = reqwest::get(url).await {
                match response.status() {
                    StatusCode::OK => {
                        let epoch_settings = response.json::<EpochSettingsMessage>().await.unwrap();

                        if epoch_settings.epoch >= epoch {
                            break;
                        }
                        sleep(Duration::from_millis(300)).await
                    }
                    s if s.is_server_error() => {
                        warn!(
                            "Server error while waiting for the Aggregator, http code: {}",
                            s
                        );
                        break;
                    }
                    _ => sleep(Duration::from_millis(300)).await,
                }
            }
            Ok(())
        },
        timeout,
        format!("Waiting for epoch {epoch}"),
        format!("Aggregator did not get a response after {timeout:?} from '{url}'")
    )
}

/// Wait for the given number of certificates, return the latest certificate
pub async fn for_certificates(
    aggregator: &Aggregator,
    total: usize,
    timeout: Duration,
) -> StdResult<CertificateListItemMessage> {
    let url = &format!("{}/certificates", aggregator.endpoint());
    spin_while_waiting!(
        {
            request_first_list_item_with_expected_size::<CertificateListItemMessage>(url, total)
                .await
                .map_err(|e| anyhow!(e).context("Request first certificate failure"))
        },
        timeout,
        "Waiting for certificates".to_string(),
        format!("Aggregator did not get a response after {timeout:?} from '{url}'")
    )
}

/// Wait for Mithril Stake Distribution artifacts
pub async fn for_mithril_stake_distribution_artifacts(
    aggregator: &Aggregator,
    total: usize,
    timeout: Duration,
) -> StdResult<MithrilStakeDistributionListItemMessage> {
    let url = &format!(
        "{}/artifact/mithril-stake-distributions",
        aggregator.endpoint()
    );
    spin_while_waiting!(
        {
            request_first_list_item_with_expected_size::<MithrilStakeDistributionListItemMessage>(
                url, total,
            )
            .await
            .map_err(|e| anyhow!(e).context("Request first mithril stake distribution failure"))
        },
        timeout,
        "Waiting for mithril stake distribution artifacts".to_string(),
        format!("Aggregator did not get a response after {timeout:?} from '{url}'")
    )
}

/// Wait for Cardano Immutable Files artifacts
pub async fn for_immutable_files_artifacts(
    aggregator: &Aggregator,
    total: usize,
    timeout: Duration,
) -> StdResult<CardanoDatabaseSnapshotListItemMessage> {
    let url = &format!("{}/artifact/cardano-database", aggregator.endpoint());
    spin_while_waiting!(
        {
            request_first_list_item_with_expected_size::<CardanoDatabaseSnapshotListItemMessage>(
                url, total,
            )
            .await
            .map_err(|e| anyhow!(e).context("Request first snapshot failure"))
        },
        timeout,
        "Waiting for immutable files artifacts".to_string(),
        format!("Aggregator did not get a response after {timeout:?} from '{url}'")
    )
}
