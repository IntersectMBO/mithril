use slog::Logger;
use std::sync::Arc;
use tokio::sync::RwLock;

use mithril_common::{
    api_version::APIVersionProvider,
    entities::{Epoch, SignerWithStake, StakeDistribution},
    signable_builder::SignableBuilderService,
    test::builder::MithrilFixture,
};

use mithril_era::{EraChecker, EraReader};
use mithril_persistence::store::StakeStorer;
use mithril_signed_entity_lock::SignedEntityTypeLock;
use mithril_ticker::TickerService;

use crate::{
    EpochSettingsStorer, MetricsService, SignerRegisterer, SignerRegistrationRoundOpener,
    SingleSignatureAuthenticator, VerificationKeyStorer,
    database::repository::{
        CertificateRepository, SignedEntityStorer, SignerGetter, StakePoolStore,
    },
    event_store::{EventMessage, TransmitterService},
    services::{
        CertificateChainSynchronizer, CertifierService, EpochService, LegacyProverService,
        MessageService, ProverService, SignedEntityService, SignerRecorder, SignerSynchronizer,
        StakeDistributionService, UpkeepService,
    },
};

/// EpochServiceWrapper wraps
pub type EpochServiceWrapper = Arc<RwLock<dyn EpochService>>;

/// Dependencies container for the serve command
pub struct ServeCommandDependenciesContainer {
    /// Application root logger
    pub(crate) root_logger: Logger,

    /// Stake Store used by the StakeDistributionService
    /// It shall be a private dependency.
    pub(crate) stake_store: Arc<StakePoolStore>,

    /// It shall be a private dependency.
    /// Certificate store.
    pub certificate_repository: Arc<CertificateRepository>,

    /// Verification key store.
    pub verification_key_store: Arc<dyn VerificationKeyStorer>,

    /// Epoch settings storer.
    pub epoch_settings_storer: Arc<dyn EpochSettingsStorer>,

    /// Certificate chain synchronizer service
    pub(crate) certificate_chain_synchronizer: Arc<dyn CertificateChainSynchronizer>,

    /// Signer registerer service
    pub signer_registerer: Arc<dyn SignerRegisterer>,

    /// Signer synchronizer service
    pub(crate) signer_synchronizer: Arc<dyn SignerSynchronizer>,

    /// Signer registration round opener service
    pub(crate) signer_registration_round_opener: Arc<dyn SignerRegistrationRoundOpener>,

    /// Era checker service
    pub(crate) era_checker: Arc<EraChecker>,

    /// Era reader service
    pub(crate) era_reader: Arc<EraReader>,

    /// Event Transmitter Service
    pub(crate) event_transmitter: Arc<TransmitterService<EventMessage>>,

    /// API Version provider
    pub(crate) api_version_provider: Arc<APIVersionProvider>,

    /// Stake Distribution Service
    pub(crate) stake_distribution_service: Arc<dyn StakeDistributionService>,

    /// Signer Recorder
    pub(crate) signer_recorder: Arc<dyn SignerRecorder>,

    /// Signable Builder Service
    pub signable_builder_service: Arc<dyn SignableBuilderService>,

    /// Signed Entity Service
    pub(crate) signed_entity_service: Arc<dyn SignedEntityService>,

    /// Certifier Service
    pub certifier_service: Arc<dyn CertifierService>,

    /// Epoch service
    pub(crate) epoch_service: EpochServiceWrapper,

    /// Ticker Service
    pub(crate) ticker_service: Arc<dyn TickerService>,

    /// Signed Entity storer
    pub signed_entity_storer: Arc<dyn SignedEntityStorer>,

    /// Signer getter service
    pub(crate) signer_getter: Arc<dyn SignerGetter>,

    /// HTTP message service
    pub message_service: Arc<dyn MessageService>,

    /// Prover service
    pub legacy_prover_service: Arc<dyn LegacyProverService>,

    /// Legacy Prover service
    pub prover_service: Arc<dyn ProverService>,

    /// Signed Entity Type Lock
    pub signed_entity_type_lock: Arc<SignedEntityTypeLock>,

    /// Upkeep service
    pub(crate) upkeep_service: Arc<dyn UpkeepService>,

    /// Single signer authenticator
    pub(crate) single_signer_authenticator: Arc<SingleSignatureAuthenticator>,

    /// Metrics service
    pub(crate) metrics_service: Arc<MetricsService>,
}

#[doc(hidden)]
impl ServeCommandDependenciesContainer {
    /// `TEST METHOD ONLY`
    ///
    /// Fill the stores of this container in a way to simulate an aggregator state
    /// using the data from a precomputed fixture.
    ///
    /// Data will be inserted in the given `next_aggregation_epoch`, the current aggregation epoch
    /// (`next_aggregation_epoch - 1`), and the signer registration epoch (`next_aggregation_epoch + 1`).
    ///
    /// Note: `epoch_settings` store must have data for the inserted epochs, this should be done
    /// automatically when building the [ServeCommandDependenciesContainer] by `handle_discrepancies_at_startup`
    pub async fn init_state_from_fixture(
        &self,
        fixture: &MithrilFixture,
        next_aggregation_epoch: Epoch,
    ) {
        self.init_state_from_fixture_internal(
            fixture,
            [
                next_aggregation_epoch.offset_to_signer_retrieval_epoch().unwrap(),
                next_aggregation_epoch,
                next_aggregation_epoch.offset_to_recording_epoch(),
            ],
        )
        .await
    }

    /// `TEST METHOD ONLY`
    ///
    /// Fill the stores of this container in a way to simulate an aggregator state ready to sign a
    /// genesis certificate using the data from a precomputed fixture.
    ///
    /// Data will be inserted in the given `next_aggregation_epoch`, the current aggregation epoch
    /// (`next_aggregation_epoch - 1`).
    ///
    /// Note: `epoch_settings` store must have data for the inserted epochs, this should be done
    /// automatically when building the [ServeCommandDependenciesContainer] by `handle_discrepancies_at_startup`
    pub async fn init_state_from_fixture_for_genesis(
        &self,
        fixture: &MithrilFixture,
        next_aggregation_epoch: Epoch,
    ) {
        self.init_state_from_fixture_internal(
            fixture,
            [
                next_aggregation_epoch.offset_to_signer_retrieval_epoch().unwrap(),
                next_aggregation_epoch,
            ],
        )
        .await
    }

    async fn init_state_from_fixture_internal<const N: usize>(
        &self,
        fixture: &MithrilFixture,
        epochs_to_fill: [Epoch; N],
    ) {
        for epoch in epochs_to_fill {
            self.fill_verification_key_store(epoch, &fixture.signers_with_stake())
                .await;
            self.fill_stakes_store(epoch, fixture.signers_with_stake()).await;
        }
    }

    async fn fill_verification_key_store(&self, target_epoch: Epoch, signers: &[SignerWithStake]) {
        for signer in signers {
            self.signer_recorder
                .record_signer_registration(signer.party_id.clone())
                .await
                .expect("record_signer_registration should not fail");
            self.verification_key_store
                .save_verification_key(target_epoch, signer.clone())
                .await
                .expect("save_verification_key should not fail");
        }
    }

    async fn fill_stakes_store(&self, target_epoch: Epoch, signers: Vec<SignerWithStake>) {
        let _ = self
            .stake_store
            .save_stakes(
                target_epoch,
                signers.iter().map(|s| s.into()).collect::<StakeDistribution>(),
            )
            .await
            .expect("save_stakes should not fail");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use crate::{ServeCommandConfiguration, dependency_injection::DependenciesBuilder};

    use super::*;

    /// Initialize dependency container with a unique temporary snapshot directory build from test path.
    /// This macro should used directly in a function test to be able to retrieve the function name.
    #[macro_export]
    macro_rules! initialize_dependencies {
        () => {{ initialize_dependencies(mithril_common::temp_dir!()) }};
    }

    pub async fn initialize_dependencies(tmp_path: PathBuf) -> ServeCommandDependenciesContainer {
        let config = ServeCommandConfiguration::new_sample(tmp_path);

        let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));

        builder.build_serve_dependencies_container().await.unwrap()
    }
}
