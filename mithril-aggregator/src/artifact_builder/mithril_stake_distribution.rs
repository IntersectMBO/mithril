use async_trait::async_trait;

use super::ArtifactBuilder;
use crate::dependency_injection::EpochServiceWrapper;
use mithril_common::{
    StdResult,
    entities::{Certificate, Epoch, MithrilStakeDistribution},
};

/// A [MithrilStakeDistributionArtifact] builder
pub struct MithrilStakeDistributionArtifactBuilder {
    epoch_service: EpochServiceWrapper,
}

impl MithrilStakeDistributionArtifactBuilder {
    /// MithrilStakeDistribution artifact builder factory
    pub fn new(epoch_service: EpochServiceWrapper) -> Self {
        Self { epoch_service }
    }
}

#[async_trait]
impl ArtifactBuilder<Epoch, MithrilStakeDistribution> for MithrilStakeDistributionArtifactBuilder {
    async fn compute_artifact(
        &self,
        epoch: Epoch,
        _certificate: &Certificate,
    ) -> StdResult<MithrilStakeDistribution> {
        let epoch_service = self.epoch_service.read().await;
        let protocol_parameters = epoch_service.next_protocol_parameters()?;
        Ok(MithrilStakeDistribution::new(
            epoch,
            epoch_service.next_signers_with_stake()?.clone(),
            &protocol_parameters.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{
        crypto_helper::ProtocolParameters,
        test::{
            builder::MithrilFixtureBuilder,
            double::{Dummy, fake_data},
        },
    };
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use super::*;

    use crate::{entities::AggregatorEpochSettings, services::FakeEpochServiceBuilder};

    #[tokio::test]
    async fn should_compute_valid_artifact() {
        let signers_with_stake_builder = MithrilFixtureBuilder::default().with_signers(5);
        #[cfg(feature = "future_snark")]
        let signers_with_stake_builder = signers_with_stake_builder.with_epoch(Epoch(1));
        let signers_with_stake = signers_with_stake_builder.build().signers_with_stake();
        let certificate = fake_data::certificate("certificate-123".to_string());
        let epoch_settings = AggregatorEpochSettings {
            protocol_parameters: fake_data::protocol_parameters(),
            ..AggregatorEpochSettings::dummy()
        };
        let epoch_service = FakeEpochServiceBuilder {
            current_epoch_settings: epoch_settings.clone(),
            current_signers_with_stake: signers_with_stake.clone(),
            next_signers_with_stake: signers_with_stake.clone(),
            ..FakeEpochServiceBuilder::dummy(Epoch(1))
        }
        .build();
        let mithril_stake_distribution_artifact_builder =
            MithrilStakeDistributionArtifactBuilder::new(Arc::new(RwLock::new(epoch_service)));
        let artifact = mithril_stake_distribution_artifact_builder
            .compute_artifact(Epoch(1), &certificate)
            .await
            .unwrap();
        let artifact_expected = MithrilStakeDistribution::new(
            Epoch(1),
            signers_with_stake,
            &epoch_settings.protocol_parameters,
        );
        assert_eq!(artifact_expected, artifact);
    }

    #[test]
    fn sort_given_signers_when_created() {
        let signers_with_stake = fake_data::signers_with_stakes(5);

        assert_eq!(
            MithrilStakeDistribution::new(
                Epoch(1),
                signers_with_stake.clone(),
                &ProtocolParameters {
                    k: 1,
                    m: 1,
                    phi_f: 0.5
                }
                .into(),
            ),
            MithrilStakeDistribution::new(
                Epoch(1),
                signers_with_stake.into_iter().rev().collect(),
                &ProtocolParameters {
                    k: 1,
                    m: 1,
                    phi_f: 0.5
                }
                .into(),
            )
        );
    }

    #[test]
    fn hash_value_doesnt_change_if_signers_order_change() {
        let signers_with_stake = fake_data::signers_with_stakes(5);

        let sd = MithrilStakeDistribution::new(
            Epoch(1),
            signers_with_stake.clone(),
            &ProtocolParameters {
                k: 1,
                m: 1,
                phi_f: 0.5,
            }
            .into(),
        );
        let sd2 = MithrilStakeDistribution::new(
            Epoch(1),
            signers_with_stake.into_iter().rev().collect(),
            &ProtocolParameters {
                k: 1,
                m: 1,
                phi_f: 0.5,
            }
            .into(),
        );

        assert_eq!(sd.hash, sd2.hash);
    }
}
