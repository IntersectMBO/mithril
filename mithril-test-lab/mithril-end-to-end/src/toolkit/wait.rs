use anyhow::{Context, anyhow};
use reqwest::StatusCode;
use slog_scope::{info, warn};

use mithril_cardano_node_internal_database::entities::ImmutableFile;
use mithril_common::{StdResult, entities::Epoch, messages::EpochSettingsMessage};

use crate::{Aggregator, poll_until, toolkit::ScenarioToolkitContext, utils::AttemptResult};

#[derive(Debug, Clone)]
pub struct WaitToolkit {
    context: ScenarioToolkitContext,
}

impl WaitToolkit {
    /// Extra epoch of timeout margin on top of the number of epochs remaining until the target,
    /// so block-production and chain-observation jitter near the boundary does not trip the deadline.
    const TARGET_EPOCH_SLACK: u64 = 1;

    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { context }
    }

    pub async fn for_enough_immutable(&self, aggregator: &Aggregator) -> StdResult<()> {
        info!("Waiting that enough immutable have been written in the devnet"; "aggregator" => aggregator.name());

        let db_directory = aggregator.db_directory();
        match poll_until!(
            self.context.startup_readiness_timeout(),
            self.context.poll_backoff(),
            {
                match ImmutableFile::list_completed_in_dir(db_directory)
                    .with_context(|| {
                        format!(
                            "Immutable file listing failed in dir `{}`",
                            db_directory.display(),
                        )
                    })?
                    .last()
                {
                    Some(_) => Ok(Some(())),
                    None => Ok(None),
                }
            }
        ) {
            AttemptResult::Ok(_) => Ok(()),
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => Err(anyhow!(
                "Timeout exhausted for enough immutable to be written in `{}`",
                db_directory.display()
            )),
        }
    }

    pub async fn for_epoch_settings(
        &self,
        aggregator: &Aggregator,
    ) -> StdResult<EpochSettingsMessage> {
        let aggregator_endpoint = aggregator.endpoint();
        let url = format!("{aggregator_endpoint}/epoch-settings");
        info!("Waiting for the aggregator to expose epoch settings"; "aggregator" => aggregator.name());

        match poll_until!(
            self.context.startup_readiness_timeout(),
            self.context.poll_backoff(),
            {
                match reqwest::get(url.clone()).await {
                    Ok(response) => match response.status() {
                        StatusCode::OK => {
                            let epoch_settings = response
                                .json::<EpochSettingsMessage>()
                                .await
                                .with_context(|| "Invalid EpochSettings body")?;
                            info!("Aggregator ready"; "epoch_settings"  => ?epoch_settings);
                            Ok(Some(epoch_settings))
                        }
                        s if s.is_server_error() => {
                            warn!( "Server error while waiting for the Aggregator, http code: {s}"; "aggregator" => aggregator.name());
                            Ok(None)
                        }
                        _ => Ok(None),
                    },
                    Err(_) => Ok(None),
                }
            }
        ) {
            AttemptResult::Ok(epoch_settings) => Ok(epoch_settings),
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => Err(anyhow!(
                "Timeout exhausted for aggregator to be up, no response from `{url}`"
            )),
        }
    }

    pub async fn for_aggregator_at_target_epoch(
        &self,
        aggregator: &Aggregator,
        target_epoch: Epoch,
        wait_reason: String,
    ) -> StdResult<()> {
        info!(
            "Waiting for the cardano network to be at the target epoch: {}", wait_reason;
            "aggregator" => aggregator.name(),
            "target_epoch" => ?target_epoch
        );

        let current_epoch = aggregator
            .chain_observer()
            .get_current_epoch()
            .await
            .ok()
            .flatten()
            .unwrap_or(Epoch(0));
        let epochs_to_wait = Self::compute_number_of_epochs_to_wait(target_epoch, current_epoch);
        let timeout = self.context.timeout_for_epochs(epochs_to_wait);

        match poll_until!(timeout, self.context.tenth_of_epoch_poll_backoff(), {
            match aggregator
                .chain_observer()
                .get_current_epoch()
                .await
                .with_context(|| "Could not query current epoch")?
            {
                Some(epoch) => {
                    if epoch >= target_epoch {
                        Ok(Some(()))
                    } else {
                        Ok(None)
                    }
                }
                None => Ok(None),
            }
        }) {
            AttemptResult::Ok(_) => {
                info!("Target epoch reached!"; "aggregator" => aggregator.name(), "target_epoch" => ?target_epoch);
                Ok(())
            }
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => {
                Err(anyhow!("Timeout exhausted for target epoch to be reached"))
            }
        }?;

        Ok(())
    }

    /// Number of epochs to wait for the chain to reach `target_epoch` from `current_epoch`,
    /// including the target epoch slack.
    fn compute_number_of_epochs_to_wait(target_epoch: Epoch, current_epoch: Epoch) -> u32 {
        let epochs_to_wait = target_epoch - current_epoch + Self::TARGET_EPOCH_SLACK;
        u32::try_from(*epochs_to_wait).expect("Number of epochs to wait should fit in a u32")
    }
}
