//! ## SignerSignableSeedBuilder
//!
//! This service is responsible for computing the seed protocol message
//! that is used by the [SignableBuilder] to compute the final protocol message.
//!
use anyhow::Context;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use mithril_common::{
    StdResult,
    crypto_helper::{ProtocolAggregateVerificationKeyForConcatenation, ProtocolInitializer},
    entities::{ProtocolMessagePartValue, ProtocolParameters, SignerWithStake},
    protocol::SignerBuilder,
    signable_builder::SignableSeedBuilder,
};
#[cfg(feature = "future_snark")]
use mithril_common::{
    crypto_helper::ProtocolKey,
    entities::{Epoch, SupportedEra},
};

use crate::{services::EpochService, store::ProtocolInitializerStorer};

/// SignableSeedBuilder signer implementation
pub struct SignerSignableSeedBuilder {
    epoch_service: Arc<RwLock<dyn EpochService>>,
    protocol_initializer_store: Arc<dyn ProtocolInitializerStorer>,
}

impl SignerSignableSeedBuilder {
    /// SignerSignableSeedBuilder factory
    pub fn new(
        epoch_service: Arc<RwLock<dyn EpochService>>,
        protocol_initializer_store: Arc<dyn ProtocolInitializerStorer>,
    ) -> Self {
        Self {
            epoch_service,
            protocol_initializer_store,
        }
    }

    fn compute_encode_avk(
        &self,
        protocol_initializer: ProtocolInitializer,
        signers_with_stake: &[SignerWithStake],
        #[cfg(feature = "future_snark")] epoch: Epoch,
    ) -> StdResult<String> {
        let signer_builder = SignerBuilder::new(
            signers_with_stake,
            &protocol_initializer.get_protocol_parameters().into(),
            #[cfg(feature = "future_snark")]
            epoch,
        )
        .with_context(|| "SignerSignableSeedBuilder can not compute aggregate verification key")?;

        let encoded_avk: ProtocolAggregateVerificationKeyForConcatenation = signer_builder
            .compute_aggregate_verification_key()
            .to_concatenation_aggregate_verification_key()
            .to_owned()
            .into();
        let encoded_avk = encoded_avk.to_json_hex().with_context(
            || "SignerSignableSeedBuilder can not serialize aggregate verification key",
        )?;

        Ok(encoded_avk)
    }

    #[cfg(feature = "future_snark")]
    fn compute_encode_snark_avk(
        &self,
        protocol_initializer: ProtocolInitializer,
        signers_with_stake: &[SignerWithStake],
        epoch: Epoch,
    ) -> StdResult<Option<String>> {
        let signer_builder = SignerBuilder::new(
            signers_with_stake,
            &protocol_initializer.get_protocol_parameters().into(),
            epoch,
        )
        .with_context(
            || "SignerSignableSeedBuilder can not compute SNARK aggregate verification key",
        )?;

        let aggregate_verification_key = signer_builder.compute_aggregate_verification_key();
        let Some(snark_avk) = aggregate_verification_key.to_snark_aggregate_verification_key()
        else {
            return Ok(None);
        };
        let snark_avk_encoded =
            ProtocolKey::new(snark_avk.to_owned()).to_bytes_hex().with_context(
                || "SignerSignableSeedBuilder can not serialize SNARK aggregate verification key",
            )?;

        Ok(Some(snark_avk_encoded))
    }
}

#[async_trait]
impl SignableSeedBuilder for SignerSignableSeedBuilder {
    async fn compute_next_aggregate_verification_key_for_concatenation(
        &self,
    ) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let epoch = (*epoch_service).epoch_of_current_data()?;
        let next_signer_retrieval_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let next_protocol_initializer = self
            .protocol_initializer_store
            .get_protocol_initializer(next_signer_retrieval_epoch)
            .await?
            .with_context(|| {
                format!("can not get protocol_initializer at epoch {next_signer_retrieval_epoch}")
            })?;
        let next_signers_with_stake = epoch_service.next_signers_with_stake().await?;
        let next_aggregate_verification_key = self.compute_encode_avk(
            next_protocol_initializer,
            &next_signers_with_stake,
            #[cfg(feature = "future_snark")]
            epoch,
        )?;

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

            let epoch = (*epoch_service).epoch_of_current_data()?;
            let next_signer_retrieval_epoch = epoch.offset_to_next_signer_retrieval_epoch();
            let next_protocol_initializer = self
                .protocol_initializer_store
                .get_protocol_initializer(next_signer_retrieval_epoch)
                .await?
                .with_context(|| {
                    format!(
                        "can not get protocol_initializer at epoch {next_signer_retrieval_epoch}"
                    )
                })?;
            let next_signers_with_stake = epoch_service.next_signers_with_stake().await?;
            let next_snark_aggregate_verification_key = self.compute_encode_snark_avk(
                next_protocol_initializer,
                &next_signers_with_stake,
                epoch,
            )?;

            Ok(next_snark_aggregate_verification_key)
        }

        #[cfg(not(feature = "future_snark"))]
        {
            Ok(None)
        }
    }

    async fn compute_next_protocol_parameters(&self) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let epoch = (*epoch_service).epoch_of_current_data()?;
        let next_signer_retrieval_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let next_protocol_initializer = self
            .protocol_initializer_store
            .get_protocol_initializer(next_signer_retrieval_epoch)
            .await?
            .with_context(|| {
                format!("can not get protocol_initializer at epoch {next_signer_retrieval_epoch}")
            })?;
        let next_protocol_parameters: ProtocolParameters =
            next_protocol_initializer.get_protocol_parameters().into();

        Ok(next_protocol_parameters.compute_hash())
    }

    async fn compute_current_epoch(&self) -> StdResult<ProtocolMessagePartValue> {
        let epoch_service = self.epoch_service.read().await;
        let current_epoch = epoch_service.epoch_of_current_data()?.to_string();

        Ok(current_epoch)
    }
}

#[cfg(test)]
mod tests {

    use mithril_common::{
        entities::Epoch, entities::ProtocolParameters, test::builder::MithrilFixtureBuilder,
    };

    use crate::{
        services::mock_epoch_service::MockEpochServiceImpl, store::MockProtocolInitializerStorer,
    };

    use super::*;

    struct MockDependencyInjector {
        mock_epoch_service: MockEpochServiceImpl,
        mock_protocol_initializer_store: MockProtocolInitializerStorer,
    }

    impl MockDependencyInjector {
        fn new() -> MockDependencyInjector {
            MockDependencyInjector {
                mock_epoch_service: MockEpochServiceImpl::new(),
                mock_protocol_initializer_store: MockProtocolInitializerStorer::new(),
            }
        }

        fn build_signable_builder_service(self) -> SignerSignableSeedBuilder {
            SignerSignableSeedBuilder::new(
                Arc::new(RwLock::new(self.mock_epoch_service)),
                Arc::new(self.mock_protocol_initializer_store),
            )
        }
    }

    #[tokio::test]
    async fn test_compute_next_aggregate_verification_key_protocol_message_value() {
        let epoch = Epoch(5);
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4).build();
        let protocol_initializer = next_fixture.signers_fixture()[0].protocol_initializer.clone();
        let next_signers_with_stake = next_fixture.signers_with_stake();
        let mut mock_container = MockDependencyInjector::new();
        mock_container.mock_epoch_service =
            MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                mock_epoch_service
                    .expect_epoch_of_current_data()
                    .return_once(move || Ok(epoch))
                    .once();
                mock_epoch_service
                    .expect_next_signers_with_stake()
                    .return_once(move || Ok(next_signers_with_stake))
                    .once();
            });
        mock_container
            .mock_protocol_initializer_store
            .expect_get_protocol_initializer()
            .return_once(move |_| Ok(Some(protocol_initializer)))
            .once();
        let signable_seed_builder = mock_container.build_signable_builder_service();

        let next_aggregate_verification_key = signable_seed_builder
            .compute_next_aggregate_verification_key_for_concatenation()
            .await
            .unwrap();

        assert_eq!(
            next_aggregate_verification_key,
            next_fixture.compute_and_encode_concatenation_aggregate_verification_key()
        );
    }

    #[tokio::test]
    async fn test_compute_next_protocol_parameters_protocol_message_value() {
        let epoch = Epoch(5);
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4).build();
        let protocol_initializer = next_fixture.signers_fixture()[0].protocol_initializer.clone();
        let protocol_parameters: ProtocolParameters =
            protocol_initializer.get_protocol_parameters().into();
        let expected_next_protocol_parameters = protocol_parameters.compute_hash();
        let mut mock_container = MockDependencyInjector::new();
        mock_container.mock_epoch_service =
            MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                mock_epoch_service
                    .expect_epoch_of_current_data()
                    .return_once(move || Ok(epoch))
                    .once();
            });
        mock_container
            .mock_protocol_initializer_store
            .expect_get_protocol_initializer()
            .return_once(move |_| Ok(Some(protocol_initializer)))
            .once();
        let signable_seed_builder = mock_container.build_signable_builder_service();

        let next_protocol_parameters = signable_seed_builder
            .compute_next_protocol_parameters()
            .await
            .unwrap();

        assert_eq!(next_protocol_parameters, expected_next_protocol_parameters);
    }

    #[tokio::test]
    async fn test_compute_current_epoch_protocol_message_value() {
        let epoch = Epoch(5);
        let expected_current_epoch = epoch.to_string();
        let mut mock_container = MockDependencyInjector::new();
        mock_container.mock_epoch_service =
            MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                mock_epoch_service
                    .expect_epoch_of_current_data()
                    .return_once(move || Ok(epoch))
                    .once();
            });
        let signable_seed_builder = mock_container.build_signable_builder_service();

        let current_epoch = signable_seed_builder.compute_current_epoch().await.unwrap();

        assert_eq!(current_epoch, expected_current_epoch);
    }

    #[cfg(feature = "future_snark")]
    mod snark_aggregate_verification_key {
        use mithril_common::entities::SupportedEra;

        use super::*;

        #[tokio::test]
        async fn returns_snark_avk_during_lagrange_era() {
            let epoch = Epoch(5);
            let next_fixture = MithrilFixtureBuilder::default().with_signers(4).build();
            let protocol_initializer =
                next_fixture.signers_fixture()[0].protocol_initializer.clone();
            let next_signers_with_stake = next_fixture.signers_with_stake();
            let mut mock_container = MockDependencyInjector::new();
            mock_container.mock_epoch_service =
                MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                    mock_epoch_service
                        .expect_mithril_era()
                        .return_once(move || Ok(SupportedEra::Lagrange))
                        .once();
                    mock_epoch_service
                        .expect_epoch_of_current_data()
                        .return_once(move || Ok(epoch))
                        .once();
                    mock_epoch_service
                        .expect_next_signers_with_stake()
                        .return_once(move || Ok(next_signers_with_stake))
                        .once();
                });
            mock_container
                .mock_protocol_initializer_store
                .expect_get_protocol_initializer()
                .return_once(move |_| Ok(Some(protocol_initializer)))
                .once();
            let signable_seed_builder = mock_container.build_signable_builder_service();

            let result = signable_seed_builder
                .compute_next_aggregate_verification_key_for_snark()
                .await
                .unwrap();

            let expected_snark_avk = next_fixture
                .compute_and_encode_snark_aggregate_verification_key()
                .expect("SNARK AVK should be available");
            assert_eq!(result, Some(expected_snark_avk));
        }

        #[tokio::test]
        async fn returns_none_when_snark_avk_unavailable_during_lagrange_era() {
            use mithril_common::entities::SignerWithStake;

            let epoch = Epoch(5);
            let next_fixture = MithrilFixtureBuilder::default().with_signers(4).build();
            let protocol_initializer =
                next_fixture.signers_fixture()[0].protocol_initializer.clone();
            let next_signers_without_snark =
                SignerWithStake::strip_snark_fields(next_fixture.signers_with_stake());
            let mut mock_container = MockDependencyInjector::new();
            mock_container.mock_epoch_service =
                MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                    mock_epoch_service
                        .expect_mithril_era()
                        .return_once(move || Ok(SupportedEra::Lagrange))
                        .once();
                    mock_epoch_service
                        .expect_epoch_of_current_data()
                        .return_once(move || Ok(epoch))
                        .once();
                    mock_epoch_service
                        .expect_next_signers_with_stake()
                        .return_once(move || Ok(next_signers_without_snark))
                        .once();
                });
            mock_container
                .mock_protocol_initializer_store
                .expect_get_protocol_initializer()
                .return_once(move |_| Ok(Some(protocol_initializer)))
                .once();
            let signable_seed_builder = mock_container.build_signable_builder_service();

            let result = signable_seed_builder
                .compute_next_aggregate_verification_key_for_snark()
                .await
                .unwrap();

            assert!(
                result.is_none(),
                "SNARK AVK should not be computed when SNARK is not yet set up during Lagrange era"
            );
        }

        #[tokio::test]
        async fn returns_none_during_pythagoras_era() {
            let mut mock_container = MockDependencyInjector::new();
            mock_container.mock_epoch_service =
                MockEpochServiceImpl::new_with_config(|mock_epoch_service| {
                    mock_epoch_service
                        .expect_mithril_era()
                        .return_once(move || Ok(SupportedEra::Pythagoras))
                        .once();
                });
            let signable_seed_builder = mock_container.build_signable_builder_service();

            let result = signable_seed_builder
                .compute_next_aggregate_verification_key_for_snark()
                .await
                .unwrap();

            assert_eq!(result, None);
        }
    }
}
