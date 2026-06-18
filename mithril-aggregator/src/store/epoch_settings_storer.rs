use async_trait::async_trait;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use tokio::sync::RwLock;

use mithril_common::StdResult;
use mithril_common::entities::{Epoch, ProtocolParameters};
use mithril_protocol_config::model::MithrilNetworkConfiguration;

use crate::{entities::AggregatorEpochSettings, services::EpochPruningTask};

/// Retrieve the [ProtocolParameters] for the given epoch.
#[async_trait]
pub trait ProtocolParametersRetriever: Sync + Send {
    /// Get the saved `ProtocolParameters` for the given [Epoch] if any.
    async fn get_protocol_parameters(&self, epoch: Epoch) -> StdResult<Option<ProtocolParameters>>;
}

/// Store and get [aggregator epoch settings][AggregatorEpochSettings] for given epoch.
#[async_trait]
pub trait EpochSettingsStorer:
    ProtocolParametersRetriever + EpochPruningTask + Sync + Send
{
    /// Save the given `AggregatorEpochSettings` for the given [Epoch].
    async fn save_epoch_settings(
        &self,
        epoch: Epoch,
        epoch_settings: AggregatorEpochSettings,
    ) -> StdResult<Option<AggregatorEpochSettings>>;

    /// Get the saved `AggregatorEpochSettings` for the given [Epoch] if any.
    async fn get_epoch_settings(&self, epoch: Epoch) -> StdResult<Option<AggregatorEpochSettings>>;

    /// Handle discrepancies at startup in the epoch settings store.
    ///
    /// In case an aggregator has been launched after some epochs of not being up or at initial startup,
    /// the discrepancies in the epoch settings store needs to be fixed.
    ///
    /// The epoch settings needs to be recorded for the working epoch and the next 3 epochs.
    /// We need data over four epochs because the epoch service use epoch settings over a window of
    /// three epochs, and there may be an epoch change between this `handle_discrepancies_at_startup`
    /// call and the epoch service call.
    async fn handle_discrepancies_at_startup(
        &self,
        network_configuration: &MithrilNetworkConfiguration,
    ) -> StdResult<()> {
        for (epoch, epoch_configuration) in [
            (
                network_configuration
                    .epoch
                    .offset_to_signer_retrieval_epoch_saturating(),
                &network_configuration.configuration_for_aggregation,
            ),
            (
                network_configuration.epoch,
                &network_configuration.configuration_for_next_aggregation,
            ),
            (
                network_configuration.epoch.offset_to_recording_epoch(),
                &network_configuration.configuration_for_registration,
            ),
        ] {
            if self.get_epoch_settings(epoch).await?.is_none() {
                self.save_epoch_settings(
                    epoch,
                    AggregatorEpochSettings {
                        protocol_parameters: epoch_configuration.protocol_parameters.clone(),
                        cardano_transactions_signing_config: epoch_configuration
                            .signed_entity_types_config
                            .cardano_transactions
                            .clone(),
                        cardano_blocks_transactions_signing_config: epoch_configuration
                            .signed_entity_types_config
                            .cardano_blocks_transactions
                            .clone(),
                    },
                )
                .await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub struct FakeEpochSettingsStorer {
    pub epoch_settings: RwLock<HashMap<Epoch, AggregatorEpochSettings>>,
}

#[cfg(test)]
impl FakeEpochSettingsStorer {
    pub fn new(data: Vec<(Epoch, AggregatorEpochSettings)>) -> Self {
        let epoch_settings = RwLock::new(data.into_iter().collect());
        Self { epoch_settings }
    }
}

#[cfg(test)]
#[async_trait]
impl ProtocolParametersRetriever for FakeEpochSettingsStorer {
    async fn get_protocol_parameters(&self, epoch: Epoch) -> StdResult<Option<ProtocolParameters>> {
        Ok(self
            .get_epoch_settings(epoch)
            .await?
            .map(|epoch_settings| epoch_settings.protocol_parameters.clone()))
    }
}

#[cfg(test)]
#[async_trait]
impl EpochSettingsStorer for FakeEpochSettingsStorer {
    async fn save_epoch_settings(
        &self,
        epoch: Epoch,
        epoch_settings: AggregatorEpochSettings,
    ) -> StdResult<Option<AggregatorEpochSettings>> {
        let mut epoch_settings_write = self.epoch_settings.write().await;

        Ok(epoch_settings_write.insert(epoch, epoch_settings))
    }

    async fn get_epoch_settings(&self, epoch: Epoch) -> StdResult<Option<AggregatorEpochSettings>> {
        let epoch_settings = self.epoch_settings.read().await;

        Ok(epoch_settings.get(&epoch).cloned())
    }
}

#[cfg(test)]
#[async_trait]
impl EpochPruningTask for FakeEpochSettingsStorer {
    fn pruned_data(&self) -> &'static str {
        "Fake epoch settings"
    }

    async fn prune(&self, _epoch: Epoch) -> StdResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mithril_common::test::double::Dummy;

    use super::*;

    #[tokio::test]
    async fn test_save_epoch_settings_do_not_exist_yet_return_none() {
        let epoch_settings = AggregatorEpochSettings::dummy();
        let epoch = Epoch(1);
        let store = FakeEpochSettingsStorer::new(vec![]);
        let epoch_settings_previous =
            store.save_epoch_settings(epoch, epoch_settings).await.unwrap();

        assert!(epoch_settings_previous.is_none());
    }

    #[tokio::test]
    async fn test_save_epoch_settings_already_exist_return_previous_epoch_settings_stored() {
        let epoch_settings = AggregatorEpochSettings::dummy();
        let epoch = Epoch(1);
        let store = FakeEpochSettingsStorer::new(vec![(epoch, epoch_settings.clone())]);
        let protocol_parameters_new = ProtocolParameters {
            k: epoch_settings.protocol_parameters.k + 1,
            ..epoch_settings.protocol_parameters
        };
        let epoch_settings_previous = store
            .save_epoch_settings(
                epoch,
                AggregatorEpochSettings {
                    protocol_parameters: protocol_parameters_new.clone(),
                    ..epoch_settings.clone()
                },
            )
            .await
            .unwrap();

        assert_eq!(Some(epoch_settings), epoch_settings_previous);
    }

    #[tokio::test]
    async fn test_get_epoch_settings_exist() {
        let epoch_settings = AggregatorEpochSettings::dummy();
        let epoch = Epoch(1);
        let store = FakeEpochSettingsStorer::new(vec![(epoch, epoch_settings.clone())]);
        let epoch_settings_stored = store.get_epoch_settings(epoch).await.unwrap();

        assert_eq!(Some(epoch_settings), epoch_settings_stored);
    }

    #[tokio::test]
    async fn test_get_epoch_settings_do_not_exist() {
        let epoch_settings = AggregatorEpochSettings::dummy();
        let epoch = Epoch(1);
        let store = FakeEpochSettingsStorer::new(vec![(epoch, epoch_settings.clone())]);
        let epoch_settings_stored = store.get_epoch_settings(epoch + 1).await.unwrap();

        assert!(epoch_settings_stored.is_none());
    }

    #[tokio::test]
    async fn test_handle_discrepancies_at_startup_should_complete_at_least_four_epochs() {
        let epoch_settings = AggregatorEpochSettings::dummy();
        let mut aggregation_epoch_settings = epoch_settings.clone();
        aggregation_epoch_settings.protocol_parameters.k += 15;

        let mut next_aggregation_epoch_settings = epoch_settings.clone();
        next_aggregation_epoch_settings.protocol_parameters.k += 26;

        let mut registration_epoch_settings = epoch_settings.clone();
        registration_epoch_settings.protocol_parameters.k += 37;

        let epoch = Epoch(5);
        let store = FakeEpochSettingsStorer::new(vec![]);
        store
            .handle_discrepancies_at_startup(&MithrilNetworkConfiguration {
                epoch,
                configuration_for_aggregation: aggregation_epoch_settings
                    .clone()
                    .into_network_configuration_for_epoch(BTreeSet::new()),
                configuration_for_next_aggregation: next_aggregation_epoch_settings
                    .clone()
                    .into_network_configuration_for_epoch(BTreeSet::new()),
                configuration_for_registration: registration_epoch_settings
                    .clone()
                    .into_network_configuration_for_epoch(BTreeSet::new()),
            })
            .await
            .unwrap();

        let epoch_settings_stored = store.get_epoch_settings(epoch - 1).await.unwrap();
        assert_eq!(Some(aggregation_epoch_settings), epoch_settings_stored);

        let epoch_settings_stored = store.get_epoch_settings(epoch).await.unwrap();
        assert_eq!(Some(next_aggregation_epoch_settings), epoch_settings_stored);

        let epoch_settings_stored = store.get_epoch_settings(epoch + 1).await.unwrap();
        assert_eq!(Some(registration_epoch_settings), epoch_settings_stored);

        let epoch_settings_stored = store.get_epoch_settings(epoch + 2).await.unwrap();
        assert!(epoch_settings_stored.is_none());
    }
}
