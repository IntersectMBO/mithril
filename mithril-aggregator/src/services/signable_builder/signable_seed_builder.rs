//! ## AggregatorSignableSeedBuilder
//!
//! This service is responsible for computing the seed protocol message
//! that is used by the [SignableBuilder] to compute the final protocol message.
//!
use anyhow::Context;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use mithril_common::{
    StdResult, crypto_helper::ProtocolKey, entities::ProtocolMessagePartValue,
    signable_builder::SignableSeedBuilder,
};

#[cfg(feature = "future_snark")]
use mithril_common::entities::SupportedEra;

use crate::services::EpochService;

/// SignableSeedBuilder aggregator implementation
pub struct AggregatorSignableSeedBuilder {
    epoch_service: Arc<RwLock<dyn EpochService>>,
}

impl AggregatorSignableSeedBuilder {
    /// AggregatorSignableSeedBuilder factory
    pub fn new(epoch_service: Arc<RwLock<dyn EpochService>>) -> Self {
        Self { epoch_service }
    }
}

#[async_trait]
impl SignableSeedBuilder for AggregatorSignableSeedBuilder {
    async fn compute_next_aggregate_verification_key_for_concatenation(
        &self,
    ) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let next_aggregate_verification_key = ProtocolKey::new(
            (*epoch_service)
                .next_aggregate_verification_key()?
                .to_concatenation_aggregate_verification_key()
                .to_owned(),
        )
        .to_json_hex()
        .with_context(|| "convert next avk to json hex failure")?
        .to_string();

        Ok(next_aggregate_verification_key)
    }

    async fn compute_next_aggregate_verification_key_for_snark(
        &self,
    ) -> StdResult<Option<ProtocolMessagePartValue>> {
        #[cfg(feature = "future_snark")]
        {
            let epoch_service = self.epoch_service.read().await;
            if epoch_service.mithril_era()? == SupportedEra::Pythagoras {
                return Ok(None);
            }

            let Some(snark_avk) = (*epoch_service)
                .next_aggregate_verification_key()?
                .to_snark_aggregate_verification_key()
            else {
                return Ok(None);
            };
            let next_aggregate_verification_key = ProtocolKey::new(snark_avk.to_owned())
                .to_bytes_hex()
                .with_context(|| "convert next snark avk to bytes hex failure")?;

            Ok(Some(next_aggregate_verification_key))
        }

        #[cfg(not(feature = "future_snark"))]
        {
            Ok(None)
        }
    }

    async fn compute_next_protocol_parameters(&self) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let next_protocol_parameters = epoch_service.next_protocol_parameters()?.compute_hash();

        Ok(next_protocol_parameters)
    }

    async fn compute_current_epoch(&self) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let current_epoch = epoch_service.epoch_of_current_data()?.to_string();

        Ok(current_epoch)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "future_snark")]
    use mithril_common::entities::SignerWithStake;
    use mithril_common::{
        entities::{Epoch, SupportedEra},
        test::{
            builder::{MithrilFixture, MithrilFixtureBuilder},
            double::Dummy,
        },
    };

    use crate::{entities::AggregatorEpochSettings, services::FakeEpochServiceBuilder};

    use super::*;

    fn build_signable_builder_service_for_era(
        epoch: Epoch,
        fixture: &MithrilFixture,
        next_fixture: &MithrilFixture,
        mithril_era: SupportedEra,
    ) -> AggregatorSignableSeedBuilder {
        let epoch_service = Arc::new(RwLock::new(
            FakeEpochServiceBuilder {
                current_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                next_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: next_fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                signer_registration_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: next_fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                current_signers_with_stake: fixture.signers_with_stake(),
                next_signers_with_stake: next_fixture.signers_with_stake(),
                mithril_era,
                ..FakeEpochServiceBuilder::dummy(epoch)
            }
            .build(),
        ));

        AggregatorSignableSeedBuilder::new(epoch_service)
    }

    fn build_signable_builder_service(
        epoch: Epoch,
        fixture: &MithrilFixture,
        next_fixture: &MithrilFixture,
    ) -> AggregatorSignableSeedBuilder {
        build_signable_builder_service_for_era(epoch, fixture, next_fixture, SupportedEra::dummy())
    }

    #[tokio::test]
    async fn test_compute_next_aggregate_verification_key_protocol_message_value() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default().with_signers(5);
        #[cfg(feature = "future_snark")]
        let fixture = fixture.with_epoch(epoch);
        let fixture = fixture.build();
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4);
        #[cfg(feature = "future_snark")]
        let next_fixture = next_fixture.with_epoch(epoch);
        let next_fixture = next_fixture.build();
        let signable_seed_builder = build_signable_builder_service(epoch, &fixture, &next_fixture);
        let expected_next_aggregate_verification_key =
            next_fixture.compute_and_encode_concatenation_aggregate_verification_key();

        let next_aggregate_verification_key = signable_seed_builder
            .compute_next_aggregate_verification_key_for_concatenation()
            .await
            .unwrap();

        assert_eq!(
            next_aggregate_verification_key,
            expected_next_aggregate_verification_key
        );
    }

    #[cfg(feature = "future_snark")]
    #[tokio::test]
    async fn compute_next_snark_avk_returns_none_during_pythagoras_era() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(5)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(4)
            .build();
        let signable_seed_builder = build_signable_builder_service_for_era(
            epoch,
            &fixture,
            &next_fixture,
            SupportedEra::Pythagoras,
        );

        let result = signable_seed_builder
            .compute_next_aggregate_verification_key_for_snark()
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "SNARK AVK should not be computed during Pythagoras era"
        );
    }

    #[cfg(feature = "future_snark")]
    #[tokio::test]
    async fn compute_next_snark_avk_returns_none_when_snark_avk_unavailable_during_lagrange_era() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(5)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(4)
            .build();
        let next_signers_without_snark =
            SignerWithStake::strip_snark_fields(next_fixture.signers_with_stake());
        let epoch_service = Arc::new(RwLock::new(
            FakeEpochServiceBuilder {
                current_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                next_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: next_fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                signer_registration_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: next_fixture.protocol_parameters(),
                    ..AggregatorEpochSettings::dummy()
                },
                current_signers_with_stake: fixture.signers_with_stake(),
                next_signers_with_stake: next_signers_without_snark,
                mithril_era: SupportedEra::Lagrange,
                ..FakeEpochServiceBuilder::dummy(epoch)
            }
            .build(),
        ));
        let signable_seed_builder = AggregatorSignableSeedBuilder::new(epoch_service);

        let result = signable_seed_builder
            .compute_next_aggregate_verification_key_for_snark()
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "SNARK AVK should not be computed when SNARK is not yet set up during Lagrange era"
        );
    }

    #[cfg(feature = "future_snark")]
    #[tokio::test]
    async fn compute_next_snark_avk_returns_value_during_lagrange_era() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(5)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_epoch(epoch)
            .with_signers(4)
            .build();
        let signable_seed_builder = build_signable_builder_service_for_era(
            epoch,
            &fixture,
            &next_fixture,
            SupportedEra::Lagrange,
        );
        let expected_snark_avk = next_fixture.compute_and_encode_snark_aggregate_verification_key();

        let result = signable_seed_builder
            .compute_next_aggregate_verification_key_for_snark()
            .await
            .unwrap();

        assert_eq!(result, expected_snark_avk);
    }

    #[tokio::test]
    async fn test_compute_next_protocol_parameters_protocol_message_value() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default().with_signers(5);
        #[cfg(feature = "future_snark")]
        let fixture = fixture.with_epoch(epoch);
        let fixture = fixture.build();
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4);
        #[cfg(feature = "future_snark")]
        let next_fixture = next_fixture.with_epoch(epoch);
        let next_fixture = next_fixture.build();
        let signable_seed_builder = build_signable_builder_service(epoch, &fixture, &next_fixture);
        let expected_next_protocol_parameters = next_fixture.protocol_parameters().compute_hash();

        let next_protocol_parameters = signable_seed_builder
            .compute_next_protocol_parameters()
            .await
            .unwrap();

        assert_eq!(next_protocol_parameters, expected_next_protocol_parameters);
    }

    #[tokio::test]
    async fn test_compute_current_epoch_protocol_message_value() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default().with_signers(5);
        #[cfg(feature = "future_snark")]
        let fixture = fixture.with_epoch(epoch);
        let fixture = fixture.build();
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4);
        #[cfg(feature = "future_snark")]
        let next_fixture = next_fixture.with_epoch(epoch);
        let next_fixture = next_fixture.build();
        let signable_seed_builder = build_signable_builder_service(epoch, &fixture, &next_fixture);
        let expected_current_epoch = epoch.to_string();

        let current_epoch = signable_seed_builder.compute_current_epoch().await.unwrap();

        assert_eq!(current_epoch, expected_current_epoch);
    }
}
