use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug};
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::StdResult;
use mithril_common::crypto_helper::ProtocolAggregateVerificationKey;
use mithril_common::entities::{
    CardanoEra, Epoch, ProtocolParameters, SignedEntityConfig, SignedEntityTypeDiscriminants,
    Signer, SignerWithStake, Stake, SupportedEra, TotalSPOs,
};
use mithril_common::logging::LoggerExtensions;
use mithril_common::protocol::{MultiSigner as ProtocolMultiSigner, SignerBuilder};
use mithril_era::EraChecker;
use mithril_persistence::store::StakeStorer;
use mithril_protocol_config::interface::MithrilNetworkConfigurationProvider;
use mithril_protocol_config::model::MithrilNetworkConfiguration;

use crate::{EpochSettingsStorer, VerificationKeyStorer, entities::AggregatorEpochSettings};

/// Errors dedicated to the CertifierService.
#[derive(Debug, Error)]
pub enum EpochServiceError {
    /// One of the data that is held for an epoch duration by the service was not available.
    #[error("Epoch service could not obtain {1} for epoch {0}")]
    UnavailableData(Epoch, String),

    /// Raised when service has not collected data at least once.
    #[error("Epoch service was not initialized, the function `inform_epoch` must be called first")]
    NotYetInitialized,

    /// Raised when service has not computed data for its current epoch.
    #[error(
        "No data computed for epoch {0}, the function `precompute_epoch_data` must be called first"
    )]
    NotYetComputed(Epoch),
}

/// Service that aggregates all data that don't change in a given epoch.
#[async_trait]
pub trait EpochService: Sync + Send {
    /// Inform the service a new epoch has been detected, telling it to update its
    /// internal state for the new epoch.
    async fn inform_epoch(&mut self, epoch: Epoch) -> StdResult<()>;

    /// Update the next signers with stake for the next epoch.
    async fn update_next_signers_with_stake(&mut self) -> StdResult<()>;

    /// Inform the service that it can precompute data for its current epoch.
    ///
    /// Note: must be called after `inform_epoch`.
    async fn precompute_epoch_data(&mut self) -> StdResult<()>;

    /// Get the current Cardano era.
    fn cardano_era(&self) -> StdResult<CardanoEra>;

    /// Get the current Mithril era.
    fn mithril_era(&self) -> StdResult<SupportedEra>;

    /// Get the current epoch for which the data stored in this service are computed.
    fn epoch_of_current_data(&self) -> StdResult<Epoch>;

    /// Get the network configuration for the current epoch.
    fn network_configuration(&self) -> StdResult<&MithrilNetworkConfiguration>;

    /// Get protocol parameters used for signing in the current epoch.
    fn current_protocol_parameters(&self) -> StdResult<&ProtocolParameters> {
        Ok(&self
            .network_configuration()?
            .configuration_for_aggregation
            .protocol_parameters)
    }

    /// Get protocol parameters used for signing in the next epoch.
    fn next_protocol_parameters(&self) -> StdResult<&ProtocolParameters> {
        Ok(&self
            .network_configuration()?
            .configuration_for_next_aggregation
            .protocol_parameters)
    }

    /// Get protocol parameters for signer registration.
    fn signer_registration_protocol_parameters(&self) -> StdResult<&ProtocolParameters> {
        Ok(&self
            .network_configuration()?
            .configuration_for_registration
            .protocol_parameters)
    }

    /// Get aggregate verification key for current epoch
    fn current_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey>;

    /// Get next aggregate verification key for next epoch
    fn next_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey>;

    /// Get signers with stake for the current epoch
    fn current_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>>;

    /// Get signers with stake for the next epoch
    fn next_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>>;

    /// Get signers for the current epoch
    fn current_signers(&self) -> StdResult<&Vec<Signer>>;

    /// Get signers for the next epoch
    fn next_signers(&self) -> StdResult<&Vec<Signer>>;

    /// Get the total stakes of signers for the current epoch
    fn total_stakes_signers(&self) -> StdResult<Stake>;

    /// Get the total stakes of signers for the next epoch
    fn total_next_stakes_signers(&self) -> StdResult<Stake>;

    /// Get the [protocol multi signer][ProtocolMultiSigner] for the current epoch
    fn protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner>;

    /// Get the [protocol multi signer][ProtocolMultiSigner] for the next epoch
    fn next_protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner>;

    /// Get the [SignedEntityConfig] for the current epoch.
    fn signed_entity_config(&self) -> StdResult<&SignedEntityConfig>;

    /// Get the total number of SPOs for the current epoch in the Cardano stake distribution.
    ///
    /// Optional as the stake distribution is not available at Aggregator first startup.
    fn total_spo(&self) -> StdResult<Option<TotalSPOs>>;

    /// Get the total stake for the current epoch in the Cardano stake distribution.
    ///
    /// Optional as the stake distribution is not available at Aggregator first startup.
    fn total_stake(&self) -> StdResult<Option<Stake>>;
}

struct EpochData {
    cardano_era: CardanoEra,
    mithril_era: SupportedEra,
    epoch: Epoch,
    network_configuration: MithrilNetworkConfiguration,
    current_signers_with_stake: Vec<SignerWithStake>,
    next_signers_with_stake: Vec<SignerWithStake>,
    current_signers: Vec<Signer>,
    next_signers: Vec<Signer>,
    total_stakes_signers: Stake,
    total_next_stakes_signers: Stake,
    signed_entity_config: SignedEntityConfig,
    total_spo: Option<TotalSPOs>,
    total_stake: Option<Stake>,
}

struct ComputedEpochData {
    aggregate_verification_key: ProtocolAggregateVerificationKey,
    next_aggregate_verification_key: ProtocolAggregateVerificationKey,
    protocol_multi_signer: ProtocolMultiSigner,
    next_protocol_multi_signer: ProtocolMultiSigner,
}

/// Dependencies required by the [MithrilEpochService].
pub struct EpochServiceDependencies {
    mithril_network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
    epoch_settings_storer: Arc<dyn EpochSettingsStorer>,
    verification_key_store: Arc<dyn VerificationKeyStorer>,
    chain_observer: Arc<dyn ChainObserver>,
    era_checker: Arc<EraChecker>,
    stake_store: Arc<dyn StakeStorer>,
}

impl EpochServiceDependencies {
    /// Create a new instance of [EpochServiceDependencies].
    pub fn new(
        mithril_network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
        epoch_settings_storer: Arc<dyn EpochSettingsStorer>,
        verification_key_store: Arc<dyn VerificationKeyStorer>,
        chain_observer: Arc<dyn ChainObserver>,
        era_checker: Arc<EraChecker>,
        stake_store: Arc<dyn StakeStorer>,
    ) -> Self {
        Self {
            mithril_network_configuration_provider,
            epoch_settings_storer,
            verification_key_store,
            chain_observer,
            era_checker,
            stake_store,
        }
    }
}

/// Implementation of the [epoch service][EpochService].
pub struct MithrilEpochService {
    epoch_data: Option<EpochData>,
    computed_epoch_data: Option<ComputedEpochData>,
    mithril_network_configuration_provider: Arc<dyn MithrilNetworkConfigurationProvider>,
    epoch_settings_storer: Arc<dyn EpochSettingsStorer>,
    verification_key_store: Arc<dyn VerificationKeyStorer>,
    chain_observer: Arc<dyn ChainObserver>,
    era_checker: Arc<EraChecker>,
    stake_store: Arc<dyn StakeStorer>,
    allowed_signed_entity_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
    logger: Logger,
}

impl MithrilEpochService {
    /// Create a new service instance
    pub fn new(
        dependencies: EpochServiceDependencies,
        allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
        logger: Logger,
    ) -> Self {
        Self {
            epoch_data: None,
            computed_epoch_data: None,
            mithril_network_configuration_provider: dependencies
                .mithril_network_configuration_provider,
            epoch_settings_storer: dependencies.epoch_settings_storer,
            verification_key_store: dependencies.verification_key_store,
            chain_observer: dependencies.chain_observer,
            era_checker: dependencies.era_checker,
            stake_store: dependencies.stake_store,
            allowed_signed_entity_discriminants: allowed_discriminants,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn get_cardano_era(&self) -> StdResult<CardanoEra> {
        let cardano_era = self
            .chain_observer
            .get_current_era()
            .await?
            .with_context(|| "No Cardano era returned by the chain observer")?;

        Ok(cardano_era)
    }

    async fn get_total_spo_and_total_stake(
        &self,
        epoch: Epoch,
    ) -> StdResult<(Option<TotalSPOs>, Option<Stake>)> {
        match self.stake_store.get_stakes(epoch).await.with_context(|| {
            format!("Epoch service failed to obtain the stake distribution for epoch: {epoch}")
        })? {
            None => Ok((None, None)),
            Some(sd) => Ok((Some(sd.len() as TotalSPOs), Some(sd.values().sum()))),
        }
    }

    async fn get_signers_with_stake_at_epoch(
        &self,
        signer_retrieval_epoch: Epoch,
    ) -> StdResult<Vec<SignerWithStake>> {
        let signers = self
            .verification_key_store
            .get_signers(signer_retrieval_epoch)
            .await?
            .unwrap_or_default();

        Ok(signers)
    }

    async fn insert_epoch_settings(
        &self,
        recording_epoch: Epoch,
        epoch_settings: &AggregatorEpochSettings,
    ) -> StdResult<()> {
        self.epoch_settings_storer
            .save_epoch_settings(
                recording_epoch,
                epoch_settings.clone()
            )
            .await
            .with_context(|| format!("Epoch service failed to insert future_epoch_settings to epoch {recording_epoch}"))
            .map(|_| ())
    }

    fn unwrap_data(&self) -> Result<&EpochData, EpochServiceError> {
        self.epoch_data.as_ref().ok_or(EpochServiceError::NotYetInitialized)
    }

    fn unwrap_computed_data(&self) -> Result<&ComputedEpochData, EpochServiceError> {
        let epoch = self.unwrap_data()?.epoch;

        self.computed_epoch_data
            .as_ref()
            .ok_or(EpochServiceError::NotYetComputed(epoch))
    }
}

#[async_trait]
impl EpochService for MithrilEpochService {
    async fn inform_epoch(&mut self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> inform_epoch(epoch: {epoch:?})");

        let cardano_era = self.get_cardano_era().await?;

        let mithril_era = self.era_checker.current_era();

        let signer_retrieval_epoch = epoch.offset_to_signer_retrieval_epoch_saturating();
        let next_signer_retrieval_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let signer_registration_epoch = epoch.offset_to_recording_epoch();

        let network_configuration = self
            .mithril_network_configuration_provider
            .get_network_configuration(epoch)
            .await?;

        let signer_registration_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: network_configuration
                .configuration_for_registration
                .protocol_parameters
                .clone(),
            cardano_transactions_signing_config: network_configuration
                .configuration_for_registration
                .signed_entity_types_config
                .cardano_transactions
                .clone(),
            cardano_blocks_transactions_signing_config: network_configuration
                .configuration_for_registration
                .signed_entity_types_config
                .cardano_blocks_transactions
                .clone(),
        };
        self.insert_epoch_settings(
            signer_registration_epoch,
            &signer_registration_epoch_settings,
        )
        .await?;

        let current_signers_with_stake =
            self.get_signers_with_stake_at_epoch(signer_retrieval_epoch).await?;
        let next_signers_with_stake = self
            .get_signers_with_stake_at_epoch(next_signer_retrieval_epoch)
            .await?;
        let current_signers = Signer::vec_from(current_signers_with_stake.clone());
        let next_signers = Signer::vec_from(next_signers_with_stake.clone());
        let total_stakes_signers = current_signers_with_stake.iter().map(|s| s.stake).sum();
        let total_next_stakes_signers = next_signers_with_stake.iter().map(|s| s.stake).sum();

        let signed_entity_config = SignedEntityConfig {
            allowed_discriminants: self
                .allowed_signed_entity_discriminants
                .intersection(
                    &network_configuration
                        .configuration_for_aggregation
                        .enabled_signed_entity_types,
                )
                .cloned()
                .collect(),
            cardano_transactions_signing_config: network_configuration
                .configuration_for_aggregation
                .signed_entity_types_config
                .cardano_transactions
                .clone(),
            cardano_blocks_transactions_signing_config: network_configuration
                .configuration_for_aggregation
                .signed_entity_types_config
                .cardano_blocks_transactions
                .clone(),
        };

        let (total_spo, total_stake) =
            self.get_total_spo_and_total_stake(signer_retrieval_epoch).await?;

        self.epoch_data = Some(EpochData {
            cardano_era,
            mithril_era,
            epoch,
            network_configuration,
            current_signers_with_stake,
            next_signers_with_stake,
            current_signers,
            next_signers,
            total_stakes_signers,
            total_next_stakes_signers,
            signed_entity_config,
            total_spo,
            total_stake,
        });
        self.computed_epoch_data = None;

        Ok(())
    }

    async fn update_next_signers_with_stake(&mut self) -> StdResult<()> {
        debug!(self.logger, ">> update_next_signers_with_stake");

        let data = self.unwrap_data().with_context(
            || "can't update next signers with stake if inform_epoch has not been called first",
        )?;

        let next_signer_retrieval_epoch = data.epoch.offset_to_next_signer_retrieval_epoch();
        let next_signers_with_stake = self
            .get_signers_with_stake_at_epoch(next_signer_retrieval_epoch)
            .await?;

        self.epoch_data.as_mut().unwrap().next_signers_with_stake = next_signers_with_stake;

        self.precompute_epoch_data()
            .await
            .with_context(|| "Epoch service failed to precompute epoch data")?;

        Ok(())
    }

    async fn precompute_epoch_data(&mut self) -> StdResult<()> {
        debug!(self.logger, ">> precompute_epoch_data");

        let data = self.unwrap_data().with_context(
            || "can't precompute epoch data if inform_epoch has not been called first",
        )?;

        let protocol_multi_signer = SignerBuilder::new(
            &data.current_signers_with_stake,
            &data
                .network_configuration
                .configuration_for_aggregation
                .protocol_parameters,
        )
        .with_context(|| "Epoch service failed to build protocol multi signer")?
        .build_multi_signer();

        let next_protocol_multi_signer = SignerBuilder::new(
            &data.next_signers_with_stake,
            &data
                .network_configuration
                .configuration_for_next_aggregation
                .protocol_parameters,
        )
        .with_context(|| "Epoch service failed to build next protocol multi signer")?
        .build_multi_signer();

        self.computed_epoch_data = Some(ComputedEpochData {
            aggregate_verification_key: protocol_multi_signer.compute_aggregate_verification_key(),
            next_aggregate_verification_key: next_protocol_multi_signer
                .compute_aggregate_verification_key(),
            protocol_multi_signer,
            next_protocol_multi_signer,
        });

        Ok(())
    }

    fn cardano_era(&self) -> StdResult<CardanoEra> {
        Ok(self.unwrap_data()?.cardano_era.clone())
    }

    fn mithril_era(&self) -> StdResult<SupportedEra> {
        Ok(self.unwrap_data()?.mithril_era)
    }

    fn epoch_of_current_data(&self) -> StdResult<Epoch> {
        Ok(self.unwrap_data()?.epoch)
    }

    fn network_configuration(&self) -> StdResult<&MithrilNetworkConfiguration> {
        Ok(&self.unwrap_data()?.network_configuration)
    }

    fn current_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey> {
        Ok(&self.unwrap_computed_data()?.aggregate_verification_key)
    }

    fn next_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey> {
        Ok(&self.unwrap_computed_data()?.next_aggregate_verification_key)
    }

    fn current_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>> {
        Ok(&self.unwrap_data()?.current_signers_with_stake)
    }

    fn next_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>> {
        Ok(&self.unwrap_data()?.next_signers_with_stake)
    }

    fn current_signers(&self) -> StdResult<&Vec<Signer>> {
        Ok(&self.unwrap_data()?.current_signers)
    }

    fn next_signers(&self) -> StdResult<&Vec<Signer>> {
        Ok(&self.unwrap_data()?.next_signers)
    }

    fn total_stakes_signers(&self) -> StdResult<Stake> {
        Ok(self.unwrap_data()?.total_stakes_signers)
    }

    fn total_next_stakes_signers(&self) -> StdResult<Stake> {
        Ok(self.unwrap_data()?.total_next_stakes_signers)
    }

    fn protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner> {
        Ok(&self.unwrap_computed_data()?.protocol_multi_signer)
    }

    fn next_protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner> {
        Ok(&self.unwrap_computed_data()?.next_protocol_multi_signer)
    }

    fn signed_entity_config(&self) -> StdResult<&SignedEntityConfig> {
        Ok(&self.unwrap_data()?.signed_entity_config)
    }

    fn total_spo(&self) -> StdResult<Option<TotalSPOs>> {
        Ok(self.unwrap_data()?.total_spo)
    }

    fn total_stake(&self) -> StdResult<Option<Stake>> {
        Ok(self.unwrap_data()?.total_stake)
    }
}

#[cfg(test)]
pub(crate) struct FakeEpochService {
    epoch_data: Option<EpochData>,
    computed_epoch_data: Option<ComputedEpochData>,
    inform_epoch_error: bool,
    precompute_epoch_data_error: bool,
    update_next_signers_with_stake_error: bool,
}

#[cfg(test)]
pub(crate) struct FakeEpochServiceBuilder {
    pub cardano_era: CardanoEra,
    pub mithril_era: SupportedEra,
    pub epoch: Epoch,
    pub current_epoch_settings: AggregatorEpochSettings,
    pub next_epoch_settings: AggregatorEpochSettings,
    pub signer_registration_epoch_settings: AggregatorEpochSettings,
    pub current_signers_with_stake: Vec<SignerWithStake>,
    pub next_signers_with_stake: Vec<SignerWithStake>,
    pub signed_entity_config: SignedEntityConfig,
    pub total_spo: Option<TotalSPOs>,
    pub total_stake: Option<Stake>,
}

#[cfg(test)]
impl FakeEpochServiceBuilder {
    pub fn dummy(epoch: Epoch) -> Self {
        use mithril_common::test::double::{Dummy, fake_data};
        let signers = fake_data::signers_with_stakes(3);

        Self {
            cardano_era: "DummyEra".to_string(),
            mithril_era: SupportedEra::dummy(),
            epoch,
            current_epoch_settings: AggregatorEpochSettings::dummy(),
            next_epoch_settings: AggregatorEpochSettings::dummy(),
            signer_registration_epoch_settings: AggregatorEpochSettings::dummy(),
            current_signers_with_stake: signers.clone(),
            next_signers_with_stake: signers,
            signed_entity_config: SignedEntityConfig::dummy(),
            total_spo: None,
            total_stake: None,
        }
    }

    pub fn build(self) -> FakeEpochService {
        let current_signers = Signer::vec_from(self.current_signers_with_stake.clone());
        let next_signers = Signer::vec_from(self.next_signers_with_stake.clone());
        let total_stakes_signers = self.current_signers_with_stake.iter().map(|s| s.stake).sum();
        let total_next_stakes_signers = self.next_signers_with_stake.iter().map(|s| s.stake).sum();

        let protocol_multi_signer = SignerBuilder::new(
            &self.current_signers_with_stake,
            &self.current_epoch_settings.protocol_parameters,
        )
        .with_context(|| "Could not build protocol_multi_signer for epoch service")
        .unwrap()
        .build_multi_signer();
        let next_protocol_multi_signer = SignerBuilder::new(
            &self.next_signers_with_stake,
            &self.next_epoch_settings.protocol_parameters,
        )
        .with_context(|| "Could not build protocol_multi_signer for epoch service")
        .unwrap()
        .build_multi_signer();

        let network_configuration = MithrilNetworkConfiguration {
            epoch: self.epoch,
            configuration_for_aggregation: self
                .current_epoch_settings
                .into_network_configuration_for_epoch(
                    self.signed_entity_config.allowed_discriminants.clone(),
                ),
            configuration_for_next_aggregation: self
                .next_epoch_settings
                .into_network_configuration_for_epoch(
                    self.signed_entity_config.allowed_discriminants.clone(),
                ),
            configuration_for_registration: self
                .signer_registration_epoch_settings
                .into_network_configuration_for_epoch(
                    self.signed_entity_config.allowed_discriminants.clone(),
                ),
        };

        FakeEpochService {
            epoch_data: Some(EpochData {
                cardano_era: self.cardano_era,
                mithril_era: self.mithril_era,
                epoch: self.epoch,
                network_configuration,
                current_signers_with_stake: self.current_signers_with_stake,
                next_signers_with_stake: self.next_signers_with_stake,
                current_signers,
                next_signers,
                total_stakes_signers,
                total_next_stakes_signers,
                signed_entity_config: self.signed_entity_config,
                total_spo: self.total_spo,
                total_stake: self.total_stake,
            }),
            computed_epoch_data: Some(ComputedEpochData {
                aggregate_verification_key: protocol_multi_signer
                    .compute_aggregate_verification_key(),
                next_aggregate_verification_key: next_protocol_multi_signer
                    .compute_aggregate_verification_key(),
                protocol_multi_signer,
                next_protocol_multi_signer,
            }),
            inform_epoch_error: false,
            precompute_epoch_data_error: false,
            update_next_signers_with_stake_error: false,
        }
    }
}

#[cfg(test)]
impl FakeEpochService {
    pub fn from_fixture(
        epoch: Epoch,
        fixture: &mithril_common::test::builder::MithrilFixture,
    ) -> Self {
        use mithril_common::entities::{
            CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig,
        };
        use mithril_common::test::double::Dummy;

        let current_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: fixture.protocol_parameters(),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig::dummy(),
            ),
        };
        let next_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: fixture.protocol_parameters(),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig::dummy(),
            ),
        };
        let signer_registration_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: fixture.protocol_parameters(),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig::dummy()),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig::dummy(),
            ),
        };

        FakeEpochServiceBuilder {
            current_epoch_settings,
            next_epoch_settings,
            signer_registration_epoch_settings,
            current_signers_with_stake: fixture.signers_with_stake(),
            next_signers_with_stake: fixture.signers_with_stake(),
            ..FakeEpochServiceBuilder::dummy(epoch)
        }
        .build()
    }

    /// Note: using this will make all 'get' method from [EpochService] trait
    /// return a [EpochServiceError::NotYetInitialized] error.
    pub fn without_data() -> Self {
        Self {
            epoch_data: None,
            computed_epoch_data: None,
            inform_epoch_error: false,
            precompute_epoch_data_error: false,
            update_next_signers_with_stake_error: false,
        }
    }

    pub fn toggle_errors(
        &mut self,
        inform_epoch: bool,
        precompute_epoch: bool,
        update_next_signers_with_stake: bool,
    ) {
        self.inform_epoch_error = inform_epoch;
        self.precompute_epoch_data_error = precompute_epoch;
        self.update_next_signers_with_stake_error = update_next_signers_with_stake;
    }

    fn unwrap_data(&self) -> Result<&EpochData, EpochServiceError> {
        self.epoch_data.as_ref().ok_or(EpochServiceError::NotYetInitialized)
    }

    fn unwrap_computed_data(&self) -> Result<&ComputedEpochData, EpochServiceError> {
        let epoch = self.unwrap_data()?.epoch;

        self.computed_epoch_data
            .as_ref()
            .ok_or(EpochServiceError::NotYetComputed(epoch))
    }
}

#[cfg(test)]
#[async_trait]
impl EpochService for FakeEpochService {
    async fn inform_epoch(&mut self, epoch: Epoch) -> StdResult<()> {
        if self.inform_epoch_error {
            anyhow::bail!("inform_epoch fake error, given epoch: {epoch}");
        }
        Ok(())
    }

    async fn update_next_signers_with_stake(&mut self) -> StdResult<()> {
        if self.update_next_signers_with_stake_error {
            anyhow::bail!("update_next_signers_with_stake fake error");
        }
        Ok(())
    }

    async fn precompute_epoch_data(&mut self) -> StdResult<()> {
        if self.precompute_epoch_data_error {
            anyhow::bail!("precompute_epoch_data fake error");
        }
        Ok(())
    }

    fn cardano_era(&self) -> StdResult<CardanoEra> {
        Ok(self.unwrap_data()?.cardano_era.clone())
    }

    fn mithril_era(&self) -> StdResult<SupportedEra> {
        Ok(self.unwrap_data()?.mithril_era)
    }

    fn epoch_of_current_data(&self) -> StdResult<Epoch> {
        Ok(self.unwrap_data()?.epoch)
    }

    fn network_configuration(&self) -> StdResult<&MithrilNetworkConfiguration> {
        Ok(&self.unwrap_data()?.network_configuration)
    }

    fn current_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey> {
        Ok(&self.unwrap_computed_data()?.aggregate_verification_key)
    }

    fn next_aggregate_verification_key(&self) -> StdResult<&ProtocolAggregateVerificationKey> {
        Ok(&self.unwrap_computed_data()?.next_aggregate_verification_key)
    }

    fn current_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>> {
        Ok(&self.unwrap_data()?.current_signers_with_stake)
    }

    fn next_signers_with_stake(&self) -> StdResult<&Vec<SignerWithStake>> {
        Ok(&self.unwrap_data()?.next_signers_with_stake)
    }

    fn current_signers(&self) -> StdResult<&Vec<Signer>> {
        Ok(&self.unwrap_data()?.current_signers)
    }

    fn next_signers(&self) -> StdResult<&Vec<Signer>> {
        Ok(&self.unwrap_data()?.next_signers)
    }

    fn total_stakes_signers(&self) -> StdResult<Stake> {
        Ok(self.unwrap_data()?.total_stakes_signers)
    }

    fn total_next_stakes_signers(&self) -> StdResult<Stake> {
        Ok(self.unwrap_data()?.total_next_stakes_signers)
    }

    fn protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner> {
        Ok(&self.unwrap_computed_data()?.protocol_multi_signer)
    }

    fn next_protocol_multi_signer(&self) -> StdResult<&ProtocolMultiSigner> {
        Ok(&self.unwrap_computed_data()?.next_protocol_multi_signer)
    }

    fn signed_entity_config(&self) -> StdResult<&SignedEntityConfig> {
        Ok(&self.unwrap_data()?.signed_entity_config)
    }

    fn total_spo(&self) -> StdResult<Option<u32>> {
        Ok(self.unwrap_data()?.total_spo)
    }

    fn total_stake(&self) -> StdResult<Option<u64>> {
        Ok(self.unwrap_data()?.total_stake)
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Stake, StakeDistribution, SupportedEra,
    };
    use mithril_common::test::{
        builder::{MithrilFixture, MithrilFixtureBuilder, StakeDistributionGenerationMethod},
        double::{Dummy, fake_data},
    };
    use mithril_protocol_config::{
        model::{MithrilNetworkConfigurationForEpoch, SignedEntityTypeConfiguration},
        test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider,
    };

    use crate::store::{FakeEpochSettingsStorer, MockVerificationKeyStorer};
    use crate::test::TestLogger;
    use crate::test::double::mocks::MockStakeStore;

    use super::*;

    fn build_uniform_stake_distribution(
        total_spo: TotalSPOs,
        stake_by_spo: Stake,
    ) -> StakeDistribution {
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(total_spo as usize)
            .with_stake_distribution(StakeDistributionGenerationMethod::Uniform(stake_by_spo))
            .build();

        fixture.stake_distribution()
    }

    #[derive(Debug, Clone, PartialEq)]
    struct ExpectedEpochData {
        cardano_era: CardanoEra,
        mithril_era: SupportedEra,
        epoch: Epoch,
        protocol_parameters: ProtocolParameters,
        next_protocol_parameters: ProtocolParameters,
        signer_registration_protocol_parameters: ProtocolParameters,
        current_signers_with_stake: BTreeSet<SignerWithStake>,
        next_signers_with_stake: BTreeSet<SignerWithStake>,
        current_signers: BTreeSet<Signer>,
        next_signers: BTreeSet<Signer>,
        signed_entity_config: SignedEntityConfig,
        total_spo: Option<TotalSPOs>,
        total_stake: Option<Stake>,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct ExpectedComputedEpochData {
        aggregate_verification_key: ProtocolAggregateVerificationKey,
        next_aggregate_verification_key: ProtocolAggregateVerificationKey,
    }

    impl ExpectedEpochData {
        async fn from_service(service: &MithrilEpochService) -> StdResult<Self> {
            Ok(Self {
                cardano_era: service.cardano_era()?,
                mithril_era: service.mithril_era()?,
                epoch: service.epoch_of_current_data()?,
                protocol_parameters: service.current_protocol_parameters()?.clone(),
                next_protocol_parameters: service.next_protocol_parameters()?.clone(),
                signer_registration_protocol_parameters: service
                    .signer_registration_protocol_parameters()?
                    .clone(),
                current_signers_with_stake: service
                    .current_signers_with_stake()?
                    .clone()
                    .into_iter()
                    .collect(),
                next_signers_with_stake: service
                    .next_signers_with_stake()?
                    .clone()
                    .into_iter()
                    .collect(),
                current_signers: service.current_signers()?.clone().into_iter().collect(),
                next_signers: service.next_signers()?.clone().into_iter().collect(),
                signed_entity_config: service.signed_entity_config()?.clone(),
                total_spo: service.total_spo()?,
                total_stake: service.total_stake()?,
            })
        }
    }

    impl ExpectedComputedEpochData {
        async fn from_service(service: &MithrilEpochService) -> StdResult<Self> {
            Ok(Self {
                aggregate_verification_key: service.current_aggregate_verification_key()?.clone(),
                next_aggregate_verification_key: service.next_aggregate_verification_key()?.clone(),
            })
        }
    }

    struct EpochServiceBuilder {
        allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
        cardano_era: CardanoEra,
        mithril_era: SupportedEra,
        current_epoch: Epoch,
        signers_with_stake: Vec<SignerWithStake>,
        next_signers_with_stake: Vec<SignerWithStake>,
        stored_current_epoch_settings: AggregatorEpochSettings,
        stored_next_epoch_settings: AggregatorEpochSettings,
        stored_signer_registration_epoch_settings: AggregatorEpochSettings,
        total_spo: TotalSPOs,
        total_stake: Stake,
    }

    impl EpochServiceBuilder {
        fn new(epoch: Epoch, epoch_fixture: MithrilFixture) -> Self {
            Self {
                allowed_discriminants: BTreeSet::new(),
                cardano_era: String::new(),
                mithril_era: SupportedEra::dummy(),
                current_epoch: epoch,
                signers_with_stake: epoch_fixture.signers_with_stake(),
                next_signers_with_stake: epoch_fixture.signers_with_stake(),
                stored_current_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: epoch_fixture.protocol_parameters(),
                    cardano_transactions_signing_config: Some(
                        CardanoTransactionsSigningConfig::dummy(),
                    ),
                    cardano_blocks_transactions_signing_config: Some(
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                    ),
                },
                stored_next_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: epoch_fixture.protocol_parameters(),
                    cardano_transactions_signing_config: Some(
                        CardanoTransactionsSigningConfig::dummy(),
                    ),
                    cardano_blocks_transactions_signing_config: Some(
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                    ),
                },
                stored_signer_registration_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: epoch_fixture.protocol_parameters(),
                    cardano_transactions_signing_config: Some(
                        CardanoTransactionsSigningConfig::dummy(),
                    ),
                    cardano_blocks_transactions_signing_config: Some(
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                    ),
                },
                total_spo: 1,
                total_stake: 10,
            }
        }

        async fn build(self) -> MithrilEpochService {
            let signer_retrieval_epoch =
                self.current_epoch.offset_to_signer_retrieval_epoch().unwrap();
            let next_signer_retrieval_epoch =
                self.current_epoch.offset_to_next_signer_retrieval_epoch();

            let verification_key_store = {
                let mut store = MockVerificationKeyStorer::new();
                let signers_with_stake = self.signers_with_stake.clone();
                store
                    .expect_get_signers()
                    .with(eq(signer_retrieval_epoch))
                    .returning(move |_| Ok(Some(signers_with_stake.clone())));

                let next_signers_with_stake = self.next_signers_with_stake.clone();
                store
                    .expect_get_signers()
                    .with(eq(next_signer_retrieval_epoch))
                    .returning(move |_| Ok(Some(next_signers_with_stake.clone())));
                store
            };

            let chain_observer = FakeChainObserver::default();
            chain_observer.set_current_era(self.cardano_era).await;
            let era_checker = EraChecker::new(self.mithril_era, Epoch::default());

            let stake_store = {
                assert!(
                    self.total_stake.is_multiple_of(self.total_spo as u64),
                    "'total_stake' must be a multiple of 'total_spo' to create a uniform stake distribution"
                );
                let stake_per_spo = self.total_stake / self.total_spo as u64;

                let stake_distribution =
                    build_uniform_stake_distribution(self.total_spo, stake_per_spo);

                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .with(eq(signer_retrieval_epoch))
                    .returning(move |_| Ok(Some(stake_distribution.clone())));

                stake_store
            };

            let configuration_for_aggregation = self
                .stored_current_epoch_settings
                .into_network_configuration_for_epoch(self.allowed_discriminants.clone());

            let configuration_for_next_aggregation = self
                .stored_next_epoch_settings
                .into_network_configuration_for_epoch(self.allowed_discriminants.clone());

            let configuration_for_registration = self
                .stored_signer_registration_epoch_settings
                .into_network_configuration_for_epoch(self.allowed_discriminants.clone());

            let network_configuration_provider = FakeMithrilNetworkConfigurationProvider::new(
                configuration_for_aggregation,
                configuration_for_next_aggregation,
                configuration_for_registration,
            );

            MithrilEpochService::new(
                EpochServiceDependencies::new(
                    Arc::new(network_configuration_provider),
                    Arc::new(FakeEpochSettingsStorer::new(Vec::new())),
                    Arc::new(verification_key_store),
                    Arc::new(chain_observer),
                    Arc::new(era_checker),
                    Arc::new(stake_store),
                ),
                self.allowed_discriminants,
                TestLogger::stdout(),
            )
        }
    }

    #[tokio::test]
    async fn inform_epoch_get_data_from_its_dependencies() {
        let current_epoch_fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let next_epoch_fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(ProtocolParameters::new(8, 80, 0.80))
            .with_signers(5)
            .build();
        let signer_registration_protocol_parameters = fake_data::protocol_parameters();

        let epoch = Epoch(5);
        let builder = EpochServiceBuilder {
            next_signers_with_stake: next_epoch_fixture.signers_with_stake(),
            stored_next_epoch_settings: AggregatorEpochSettings {
                protocol_parameters: next_epoch_fixture.protocol_parameters(),
                ..AggregatorEpochSettings::dummy()
            },
            stored_signer_registration_epoch_settings: AggregatorEpochSettings {
                protocol_parameters: signer_registration_protocol_parameters.clone(),
                ..AggregatorEpochSettings::dummy()
            },
            allowed_discriminants: SignedEntityConfig::dummy().allowed_discriminants,
            cardano_era: "CardanoEra".to_string(),
            mithril_era: SupportedEra::eras()[0],
            total_spo: 10,
            total_stake: 20_000_000,
            ..EpochServiceBuilder::new(epoch, current_epoch_fixture.clone())
        };

        let mut service = builder.build().await;

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");

        let data = ExpectedEpochData::from_service(&service)
            .await
            .expect("extracting data from service should not fail");

        assert_eq!(
            data.clone(),
            ExpectedEpochData {
                cardano_era: "CardanoEra".to_string(),
                mithril_era: SupportedEra::eras()[0],
                epoch,
                protocol_parameters: current_epoch_fixture.protocol_parameters(),
                next_protocol_parameters: next_epoch_fixture.protocol_parameters(),
                signer_registration_protocol_parameters,
                current_signers_with_stake: current_epoch_fixture
                    .signers_with_stake()
                    .into_iter()
                    .collect(),
                next_signers_with_stake: next_epoch_fixture
                    .signers_with_stake()
                    .into_iter()
                    .collect(),
                current_signers: current_epoch_fixture.signers().into_iter().collect(),
                next_signers: next_epoch_fixture.signers().into_iter().collect(),
                signed_entity_config: SignedEntityConfig::dummy(),
                total_spo: Some(10),
                total_stake: Some(20_000_000),
            }
        );
    }

    #[tokio::test]
    async fn inform_epoch_get_signed_entity_config_from_its_dependencies_and_store() {
        let epoch = Epoch(5);

        let cardano_transactions_signing_config = Some(CardanoTransactionsSigningConfig {
            security_parameter: BlockNumberOffset(29),
            step: BlockNumber(986),
        });
        let cardano_blocks_transactions_signing_config =
            Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(45),
                step: BlockNumber(999),
            });

        let allowed_discriminants = BTreeSet::from([
            SignedEntityTypeDiscriminants::CardanoTransactions,
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            SignedEntityTypeDiscriminants::CardanoDatabase,
        ]);

        let mut service = EpochServiceBuilder {
            allowed_discriminants: allowed_discriminants.clone(),
            stored_current_epoch_settings: AggregatorEpochSettings {
                cardano_transactions_signing_config: cardano_transactions_signing_config.clone(),
                cardano_blocks_transactions_signing_config:
                    cardano_blocks_transactions_signing_config.clone(),
                ..AggregatorEpochSettings::dummy()
            },
            ..EpochServiceBuilder::new(epoch, MithrilFixtureBuilder::default().build())
        }
        .build()
        .await;

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");

        let signed_entity_config = service
            .signed_entity_config()
            .expect("extracting data from service should not fail");

        assert_eq!(
            signed_entity_config.clone(),
            SignedEntityConfig {
                allowed_discriminants,
                cardano_transactions_signing_config,
                cardano_blocks_transactions_signing_config,
            }
        );
    }

    #[tokio::test]
    async fn inform_epoch_compute_allowed_discriminants_from_intersection_of_aggregation_network_config_and_configured_discriminants()
     {
        let epoch = Epoch(5);
        let allowed_discriminants = BTreeSet::from([
            SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            SignedEntityTypeDiscriminants::CardanoDatabase,
            SignedEntityTypeDiscriminants::CardanoTransactions,
        ]);
        let enabled_discriminants = BTreeSet::from([
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            SignedEntityTypeDiscriminants::CardanoTransactions,
        ]);

        let mut service = MithrilEpochService {
            mithril_network_configuration_provider: Arc::new(
                FakeMithrilNetworkConfigurationProvider::new(
                    MithrilNetworkConfigurationForEpoch {
                        enabled_signed_entity_types: enabled_discriminants,
                        ..Dummy::dummy()
                    },
                    MithrilNetworkConfigurationForEpoch::dummy(),
                    MithrilNetworkConfigurationForEpoch::dummy(),
                ),
            ),
            ..EpochServiceBuilder {
                allowed_discriminants: allowed_discriminants.clone(),
                ..EpochServiceBuilder::new(epoch, MithrilFixtureBuilder::default().build())
            }
            .build()
            .await
        };

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");

        let signed_entity_config = service
            .signed_entity_config()
            .expect("extracting data from service should not fail");

        assert_eq!(
            BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            ]),
            signed_entity_config.allowed_discriminants
        );
    }

    #[tokio::test]
    async fn compute_data_with_data_from_inform_epoch() {
        let current_epoch_fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let next_epoch_fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(ProtocolParameters::new(8, 80, 0.80))
            .with_signers(5)
            .build();

        let epoch = Epoch(5);
        let mut service =
            EpochServiceBuilder {
                stored_next_epoch_settings: AggregatorEpochSettings {
                    protocol_parameters: next_epoch_fixture.protocol_parameters(),
                    cardano_transactions_signing_config: Some(
                        CardanoTransactionsSigningConfig::dummy(),
                    ),
                    cardano_blocks_transactions_signing_config: Some(
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                    ),
                },
                next_signers_with_stake: next_epoch_fixture.signers_with_stake().clone(),
                ..EpochServiceBuilder::new(epoch, current_epoch_fixture.clone())
            }
            .build()
            .await;

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");
        service
            .precompute_epoch_data()
            .await
            .expect("precompute_epoch_data should not fail");

        let data = ExpectedComputedEpochData::from_service(&service)
            .await
            .expect("extracting data from service should not fail");

        assert_eq!(
            data,
            ExpectedComputedEpochData {
                aggregate_verification_key: current_epoch_fixture
                    .compute_aggregate_verification_key(),
                next_aggregate_verification_key: next_epoch_fixture
                    .compute_aggregate_verification_key(),
            }
        );
    }

    #[tokio::test]
    async fn inform_epoch_reset_computed_data() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let avk = fixture.compute_aggregate_verification_key();
        let epoch = Epoch(4);
        let mut service = EpochServiceBuilder::new(epoch, fixture.clone()).build().await;
        let signer_builder = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .unwrap();
        service.computed_epoch_data = Some(ComputedEpochData {
            aggregate_verification_key: avk.clone(),
            next_aggregate_verification_key: avk.clone(),
            protocol_multi_signer: signer_builder.build_multi_signer(),
            next_protocol_multi_signer: signer_builder.build_multi_signer(),
        });

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");

        assert!(service.computed_epoch_data.is_none());
    }

    #[tokio::test]
    async fn update_next_signers_with_stake_succeeds() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let next_fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let next_avk = next_fixture.compute_aggregate_verification_key();
        let epoch = Epoch(4);
        let mut service = EpochServiceBuilder {
            next_signers_with_stake: next_fixture.signers_with_stake().clone(),
            ..EpochServiceBuilder::new(epoch, fixture.clone())
        }
        .build()
        .await;
        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");
        service.epoch_data = Some(EpochData {
            next_signers_with_stake: vec![],
            ..service.epoch_data.unwrap()
        });
        service.computed_epoch_data = None;

        service
            .update_next_signers_with_stake()
            .await
            .expect("update_next_signers_with_stake should not fail");

        let expected_next_signers_with_stake = next_fixture.signers_with_stake();
        assert_eq!(
            expected_next_signers_with_stake,
            service.epoch_data.unwrap().next_signers_with_stake
        );

        assert_eq!(
            next_avk,
            service.computed_epoch_data.unwrap().next_aggregate_verification_key
        );
    }

    #[tokio::test]
    async fn inform_epoch_insert_registration_epoch_settings_in_the_store() {
        let expected_epoch_settings = AggregatorEpochSettings {
            protocol_parameters: ProtocolParameters::new(6, 89, 0.124),
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(1),
                step: BlockNumber(11),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(111),
                    step: BlockNumber(1111),
                },
            ),
        };

        let mut aggregation_configuration = MithrilNetworkConfigurationForEpoch::dummy();
        aggregation_configuration
            .signed_entity_types_config
            .cardano_transactions = Some(CardanoTransactionsSigningConfig {
            security_parameter: BlockNumberOffset(2),
            step: BlockNumber(22),
        });

        let mut next_aggregation_configuration = MithrilNetworkConfigurationForEpoch::dummy();
        next_aggregation_configuration
            .signed_entity_types_config
            .cardano_transactions = Some(CardanoTransactionsSigningConfig {
            security_parameter: BlockNumberOffset(3),
            step: BlockNumber(33),
        });

        let epoch = Epoch(4);
        let mut service = MithrilEpochService {
            mithril_network_configuration_provider: Arc::new(
                FakeMithrilNetworkConfigurationProvider::new(
                    aggregation_configuration,
                    next_aggregation_configuration,
                    MithrilNetworkConfigurationForEpoch {
                        protocol_parameters: expected_epoch_settings.protocol_parameters.clone(),
                        signed_entity_types_config: SignedEntityTypeConfiguration {
                            cardano_transactions: expected_epoch_settings
                                .cardano_transactions_signing_config
                                .clone(),
                            cardano_blocks_transactions: expected_epoch_settings
                                .cardano_blocks_transactions_signing_config
                                .clone(),
                        },
                        ..Dummy::dummy()
                    },
                ),
            ),
            ..EpochServiceBuilder::new(epoch, MithrilFixtureBuilder::default().build())
                .build()
                .await
        };

        service
            .inform_epoch(epoch)
            .await
            .expect("inform_epoch should not fail");

        let inserted_epoch_settings = service
            .epoch_settings_storer
            .get_epoch_settings(epoch.offset_to_recording_epoch())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "epoch settings should have been inserted for epoch {}",
                    epoch.offset_to_recording_epoch()
                )
            })
            .unwrap();

        assert_eq!(inserted_epoch_settings, expected_epoch_settings);
    }

    #[tokio::test]
    async fn cant_get_data_if_inform_epoch_has_not_been_called() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let service = EpochServiceBuilder::new(Epoch(4), fixture.clone()).build().await;

        for (name, res) in [
            ("cardano_era", service.cardano_era().err()),
            ("mithril_era", service.mithril_era().err()),
            (
                "epoch_of_current_data",
                service.epoch_of_current_data().err(),
            ),
            (
                "current_protocol_parameters",
                service.current_protocol_parameters().err(),
            ),
            (
                "next_protocol_parameters",
                service.next_protocol_parameters().err(),
            ),
            (
                "signer_registration_protocol_parameters",
                service.signer_registration_protocol_parameters().err(),
            ),
            (
                "current_signers_with_stake",
                service.current_signers_with_stake().err(),
            ),
            (
                "next_signers_with_stake",
                service.next_signers_with_stake().err(),
            ),
            ("current_signers", service.current_signers().err()),
            ("next_signers", service.next_signers().err()),
            (
                "current_aggregate_verification_key",
                service.current_aggregate_verification_key().err(),
            ),
            (
                "next_aggregate_verification_key",
                service.next_aggregate_verification_key().err(),
            ),
            (
                "protocol_multi_signer",
                service.protocol_multi_signer().err(),
            ),
            (
                "next_protocol_multi_signer",
                service.next_protocol_multi_signer().err(),
            ),
            ("signed_entity_config", service.signed_entity_config().err()),
            ("total_spo", service.total_spo().err()),
            ("total_stake", service.total_stake().err()),
        ] {
            let error =
                res.unwrap_or_else(|| panic!("getting {name} should have returned an error"));

            match error.downcast_ref::<EpochServiceError>() {
                Some(EpochServiceError::NotYetInitialized) => (),
                _ => panic!("Expected an NotYetInitialized error, got: {error:?}"),
            }
        }
    }

    #[tokio::test]
    async fn can_only_get_non_computed_data_if_inform_epoch_has_been_called_but_not_precompute_epoch_data()
     {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let mut service = EpochServiceBuilder::new(Epoch(4), fixture.clone()).build().await;
        service.inform_epoch(Epoch(4)).await.unwrap();

        assert!(service.cardano_era().is_ok());
        assert!(service.mithril_era().is_ok());
        assert!(service.epoch_of_current_data().is_ok());
        assert!(service.current_protocol_parameters().is_ok());
        assert!(service.next_protocol_parameters().is_ok());
        assert!(service.signer_registration_protocol_parameters().is_ok());
        assert!(service.current_signers_with_stake().is_ok());
        assert!(service.next_signers_with_stake().is_ok());
        assert!(service.current_signers().is_ok());
        assert!(service.next_signers().is_ok());
        assert!(service.signed_entity_config().is_ok());
        assert!(service.total_spo().is_ok());
        assert!(service.total_stake().is_ok());

        for (name, res) in [
            (
                "current_aggregate_verification_key",
                service.current_aggregate_verification_key().err(),
            ),
            (
                "next_aggregate_verification_key",
                service.next_aggregate_verification_key().err(),
            ),
            (
                "protocol_multi_signer",
                service.protocol_multi_signer().err(),
            ),
            (
                "next_protocol_multi_signer",
                service.next_protocol_multi_signer().err(),
            ),
        ] {
            let error =
                res.unwrap_or_else(|| panic!("getting {name} should have returned an error"));

            match error.downcast_ref::<EpochServiceError>() {
                Some(EpochServiceError::NotYetComputed(Epoch(4))) => (),
                _ => panic!("Expected an NotYetComputed error for epoch 4, got: {error:?}"),
            }
        }
    }
}
