use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::anyhow;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_test::TestServer;
use reqwest::Url;
use slog::Logger;
use tokio::sync::RwLock;

use mithril_common::{
    StdError, StdResult,
    entities::{Epoch, Signer, TimePoint},
    logging::LoggerExtensions,
    messages::{
        EpochSettingsMessage, ProtocolConfigurationMessage, RegisterSignatureMessageHttp,
        RegisterSignerMessage, SignedEntityTypeDiscriminantsMessage, SignerMessagePart,
    },
    test::messages_extensions::SignedEntityTypeDiscriminantsMessageTestExtension,
};
use mithril_protocol_config::{
    model::MithrilNetworkConfigurationForEpoch,
    test::double::FakeMithrilNetworkConfigurationProviderWithEpochMarkers,
};
use mithril_ticker::{MithrilTickerService, TickerService};

pub struct FakeAggregatorHttpServer {
    server: TestServer,
    store: Arc<RwLock<FakeAggregatorStore>>,
    network_configuration_provider: Arc<FakeMithrilNetworkConfigurationProviderWithEpochMarkers>,
    url: Url,
}

impl FakeAggregatorHttpServer {
    pub fn spawn(
        ticker_service: Arc<MithrilTickerService>,
        network_configuration_provider: Arc<
            FakeMithrilNetworkConfigurationProviderWithEpochMarkers,
        >,
        logger: Logger,
    ) -> StdResult<FakeAggregatorHttpServer> {
        let store = Arc::new(RwLock::new(FakeAggregatorStore::default()));
        let state = FakeAggregatorRoutesState {
            ticker_service,
            network_configuration_provider: network_configuration_provider.clone(),
            store: store.clone(),
            logger: logger.new_with_component_name::<Self>(),
        };
        let router = Router::new()
            .route("/epoch-settings", get(epoch_settings))
            .route(
                "/protocol-configuration/{epoch}",
                get(protocol_configuration_by_epoch),
            )
            .route("/register-signer", post(register_signer))
            .route("/register-signatures", post(register_signatures))
            .with_state(state);

        let server = TestServer::builder().http_transport().build(router);
        let url = server.server_address().unwrap();

        Ok(FakeAggregatorHttpServer {
            server,
            store,
            network_configuration_provider,
            url,
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn server_url(&self, path: &str) -> String {
        self.server.server_url(path).unwrap().to_string()
    }

    pub async fn set_network_configuration_marker(
        &self,
        marker_epoch: Epoch,
        marker: MithrilNetworkConfigurationForEpoch,
    ) {
        self.network_configuration_provider
            .insert_marker(marker_epoch, marker)
            .await;
    }

    pub async fn get_registered_signers(&self, epoch: &Epoch) -> Option<Vec<SignerMessagePart>> {
        let store = self.store.read().await;
        store.registered_signers.get(epoch).cloned()
    }

    pub async fn release_epoch_settings(&self) {
        let mut store = self.store.write().await;
        store.withhold_epoch_settings = false;
    }

    pub async fn register_signer(&self, epoch: Epoch, signer: SignerMessagePart) {
        let store = &mut self.store.write().await.registered_signers;
        store.entry(epoch).or_default().push(signer);
    }

    pub async fn protocol_config_send_unknown_signed_entities(&self) {
        let mut store = self.store.write().await;
        store.protocol_config_send_unknown_signed_entities = true;
    }

    pub async fn protocol_config_send_discontinued_signed_entities(&self) {
        let mut store = self.store.write().await;
        store.protocol_config_send_discontinued_signed_entities = true;
    }
}

#[derive(Clone)]
struct FakeAggregatorRoutesState {
    ticker_service: Arc<MithrilTickerService>,
    network_configuration_provider: Arc<FakeMithrilNetworkConfigurationProviderWithEpochMarkers>,
    store: Arc<RwLock<FakeAggregatorStore>>,
    logger: Logger,
}

struct FakeAggregatorStore {
    registered_signers: HashMap<Epoch, Vec<SignerMessagePart>>,
    withhold_epoch_settings: bool,
    protocol_config_send_unknown_signed_entities: bool,
    protocol_config_send_discontinued_signed_entities: bool,
}

impl Default for FakeAggregatorStore {
    fn default() -> Self {
        Self {
            registered_signers: HashMap::new(),
            withhold_epoch_settings: true,
            protocol_config_send_unknown_signed_entities: false,
            protocol_config_send_discontinued_signed_entities: false,
        }
    }
}

impl FakeAggregatorRoutesState {
    async fn get_time_point(&self) -> StdResult<TimePoint> {
        let time_point = self.ticker_service.get_current_time_point().await?;
        Ok(time_point)
    }

    async fn get_current_signers(&self) -> StdResult<Vec<SignerMessagePart>> {
        let time_point = self.get_time_point().await?;
        let epoch = time_point.epoch.offset_to_signer_retrieval_epoch()?;
        let store = &self.store.read().await.registered_signers;

        Ok(store.get(&epoch).cloned().unwrap_or_default())
    }

    async fn get_next_signers(&self) -> StdResult<Vec<SignerMessagePart>> {
        let time_point = self.get_time_point().await?;
        let epoch = time_point.epoch.offset_to_next_signer_retrieval_epoch();
        let store = &self.store.read().await.registered_signers;

        Ok(store.get(&epoch).cloned().unwrap_or_default())
    }
}

fn internal_server_error(err: StdError) -> (StatusCode, Json<String>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(err.to_string()))
}

async fn epoch_settings(
    state: State<FakeAggregatorRoutesState>,
) -> Result<Response, (StatusCode, Json<String>)> {
    slog::debug!(state.logger, "/epoch-settings");

    if state.store.read().await.withhold_epoch_settings {
        Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        let time_point = state.get_time_point().await.map_err(internal_server_error)?;
        let current_signers = state.get_current_signers().await.map_err(internal_server_error)?;
        let next_signers = state.get_next_signers().await.map_err(internal_server_error)?;

        #[allow(deprecated)]
        Ok(Json(EpochSettingsMessage {
            epoch: time_point.epoch,
            signer_registration_protocol_parameters: None,
            current_signers,
            next_signers,
            cardano_transactions_signing_config: None,
        })
        .into_response())
    }
}

async fn protocol_configuration_by_epoch(
    Path(epoch): Path<u64>,
    state: State<FakeAggregatorRoutesState>,
) -> Response {
    slog::debug!(state.logger, "/protocol-configuration/{epoch}");
    match state
        .network_configuration_provider
        .get_marker_at_or_before(Epoch(epoch))
        .await
    {
        Some(config) => {
            let store = state.store.read().await;

            let mut available_signed_entity_types: BTreeSet<_> = config
                .enabled_signed_entity_types
                .into_iter()
                .map(Into::into)
                .collect();

            if store.protocol_config_send_unknown_signed_entities {
                available_signed_entity_types.insert(SignedEntityTypeDiscriminantsMessage::Unknown);
            }

            if store.protocol_config_send_discontinued_signed_entities {
                available_signed_entity_types
                    .append(&mut SignedEntityTypeDiscriminantsMessage::all_discontinued());
            }

            let message = ProtocolConfigurationMessage {
                protocol_parameters: config.protocol_parameters,
                cardano_transactions_signing_config: config
                    .signed_entity_types_config
                    .cardano_transactions,
                cardano_blocks_transactions_signing_config: config
                    .signed_entity_types_config
                    .cardano_blocks_transactions,
                available_signed_entity_types,
            };
            slog::debug!(
                state.logger, "/protocol-configuration/{epoch}";
                "json" => &serde_json::to_string(&message).unwrap()
            );
            (StatusCode::OK, Json(message)).into_response()
        }
        None => internal_server_error(anyhow!("No configuration found for epoch {epoch}"))
            .into_response(),
    }
}

async fn register_signatures(
    state: State<FakeAggregatorRoutesState>,
    Json(message): Json<RegisterSignatureMessageHttp>,
) -> Response {
    slog::debug!(state.logger, "/register-signatures"; "signature" => ?message);
    StatusCode::CREATED.into_response()
}

async fn register_signer(
    state: State<FakeAggregatorRoutesState>,
    Json(message): Json<RegisterSignerMessage>,
) -> Response {
    slog::debug!(state.logger, "/register-signer"; "signer" => ?message);
    let store = &mut state.store.write().await.registered_signers;
    let signer = SignerMessagePart {
        party_id: message.party_id,
        verification_key_for_concatenation: message.verification_key_for_concatenation,
        verification_key_signature_for_concatenation: message
            .verification_key_signature_for_concatenation,
        operational_certificate: message.operational_certificate,
        kes_evolutions: message.kes_evolutions,
        #[cfg(feature = "future_snark")]
        verification_key_for_snark: None,
        #[cfg(feature = "future_snark")]
        verification_key_signature_for_snark: None,
    };
    store.entry(message.epoch).or_default().push(signer);

    StatusCode::CREATED.into_response()
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::chain_observer::ChainObserver;
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::entities::ChainPoint;
    use mithril_common::test::double::{Dummy, fake_data};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;

    use crate::test_extensions::stdout_logger;

    use super::*;

    async fn init() -> (
        Arc<FakeChainObserver>,
        Arc<FakeMithrilNetworkConfigurationProviderWithEpochMarkers>,
        FakeAggregatorHttpServer,
    ) {
        let immutable_observer = Arc::new(DumbImmutableFileObserver::new());
        immutable_observer.shall_return(Some(1)).await;
        let chain_observer = Arc::new(FakeChainObserver::new(Some(TimePoint {
            epoch: Epoch(1),
            immutable_file_number: 1,
            chain_point: ChainPoint::dummy(),
        })));
        let ticker_service = Arc::new(MithrilTickerService::new(
            chain_observer.clone(),
            immutable_observer.clone(),
        ));
        let network_configuration_provider =
            Arc::new(FakeMithrilNetworkConfigurationProviderWithEpochMarkers::default());

        (
            chain_observer,
            network_configuration_provider.clone(),
            FakeAggregatorHttpServer::spawn(
                ticker_service,
                network_configuration_provider,
                stdout_logger(),
            )
            .unwrap(),
        )
    }

    fn to_register_signer_message(
        registration_epoch: Epoch,
        signer: &Signer,
    ) -> RegisterSignerMessage {
        let signer_msg: SignerMessagePart = signer.clone().into();
        RegisterSignerMessage {
            epoch: registration_epoch,
            party_id: signer_msg.party_id.clone(),
            verification_key_for_concatenation: signer_msg
                .verification_key_for_concatenation
                .clone(),
            verification_key_signature_for_concatenation: signer_msg
                .verification_key_signature_for_concatenation
                .clone(),
            operational_certificate: signer_msg.operational_certificate.clone(),
            kes_evolutions: signer_msg.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: signer_msg.verification_key_for_snark.clone(),
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: signer_msg
                .verification_key_signature_for_snark
                .clone(),
        }
    }

    async fn post_register_signer(
        client: &reqwest::Client,
        fake_aggregator: &FakeAggregatorHttpServer,
        registration_epoch: Epoch,
        signer: &Signer,
    ) -> StdResult<()> {
        client
            .post(fake_aggregator.server_url("/register-signer"))
            .json(&to_register_signer_message(registration_epoch, signer))
            .send()
            .await?;
        Ok(())
    }

    async fn fetch_epoch_settings(
        client: &reqwest::Client,
        fake_aggregator: &FakeAggregatorHttpServer,
    ) -> StdResult<EpochSettingsMessage> {
        let message = client
            .get(fake_aggregator.server_url("/epoch-settings"))
            .send()
            .await?
            .json()
            .await?;
        Ok(message)
    }

    async fn fetch_protocol_config(
        client: &reqwest::Client,
        fake_aggregator: &FakeAggregatorHttpServer,
        epoch: Epoch,
    ) -> StdResult<ProtocolConfigurationMessage> {
        let message = client
            .get(fake_aggregator.server_url(&format!("/protocol-configuration/{epoch}")))
            .send()
            .await?
            .json()
            .await?;
        Ok(message)
    }

    #[tokio::test]
    async fn registers_signers_by_registration_epoch() {
        let client = reqwest::Client::new();
        let (chain_observer, _, fake_aggregator) = init().await;
        let fake_signers = fake_data::signers(2);
        let epoch = chain_observer.get_current_epoch().await.unwrap().unwrap();
        let registration_epoch = epoch.offset_to_recording_epoch();

        post_register_signer(
            &client,
            &fake_aggregator,
            registration_epoch,
            &fake_signers[0],
        )
        .await
        .unwrap();
        let signers = fake_aggregator
            .get_registered_signers(&registration_epoch)
            .await
            .expect("we should have a result, None found!");

        assert_eq!(1, signers.len());

        post_register_signer(
            &client,
            &fake_aggregator,
            registration_epoch,
            &fake_signers[1],
        )
        .await
        .unwrap();

        let signers = fake_aggregator
            .get_registered_signers(&registration_epoch)
            .await
            .expect("we should have a result, None found!");

        assert_eq!(2, signers.len());
    }

    #[tokio::test]
    async fn returns_current_and_next_signers_in_epoch_settings() {
        let client = reqwest::Client::new();
        let (chain_observer, _, fake_aggregator) = init().await;
        let fake_signers = fake_data::signers(3);
        let epoch = chain_observer.get_current_epoch().await.unwrap().unwrap();

        fake_aggregator.release_epoch_settings().await;

        post_register_signer(&client, &fake_aggregator, epoch, &fake_signers[0])
            .await
            .unwrap();
        let epoch_settings = fetch_epoch_settings(&client, &fake_aggregator).await.unwrap();

        assert_eq!(0, epoch_settings.current_signers.len());
        assert_eq!(1, epoch_settings.next_signers.len());

        post_register_signer(&client, &fake_aggregator, epoch, &fake_signers[1])
            .await
            .unwrap();
        let epoch_settings = fetch_epoch_settings(&client, &fake_aggregator).await.unwrap();

        assert_eq!(0, epoch_settings.current_signers.len());
        assert_eq!(2, epoch_settings.next_signers.len());

        let epoch = chain_observer.next_epoch().await.unwrap();
        post_register_signer(&client, &fake_aggregator, epoch, &fake_signers[2])
            .await
            .unwrap();
        let epoch_settings = fetch_epoch_settings(&client, &fake_aggregator).await.unwrap();

        assert_eq!(2, epoch_settings.current_signers.len());
        assert_eq!(1, epoch_settings.next_signers.len());
    }

    #[tokio::test]
    async fn can_include_unknown_signed_entity_type_in_protocol_configuration() {
        let client = reqwest::Client::new();
        let (_, configuration_provider, fake_aggregator) = init().await;

        configuration_provider
            .insert_marker(
                Epoch(0),
                MithrilNetworkConfigurationForEpoch {
                    enabled_signed_entity_types: BTreeSet::new(),
                    ..Dummy::dummy()
                },
            )
            .await;

        let no_unknown = fetch_protocol_config(&client, &fake_aggregator, Epoch(1))
            .await
            .unwrap();
        assert!(
            !no_unknown
                .available_signed_entity_types
                .contains(&SignedEntityTypeDiscriminantsMessage::Unknown)
        );

        fake_aggregator.protocol_config_send_unknown_signed_entities().await;

        let with_unknown = fetch_protocol_config(&client, &fake_aggregator, Epoch(2))
            .await
            .unwrap();
        assert!(
            with_unknown
                .available_signed_entity_types
                .contains(&SignedEntityTypeDiscriminantsMessage::Unknown)
        );
    }

    #[tokio::test]
    async fn can_include_discontinued_signed_entity_types_in_protocol_configuration() {
        let client = reqwest::Client::new();
        let (_, configuration_provider, fake_aggregator) = init().await;

        configuration_provider
            .insert_marker(
                Epoch(0),
                MithrilNetworkConfigurationForEpoch {
                    enabled_signed_entity_types: BTreeSet::new(),
                    ..Dummy::dummy()
                },
            )
            .await;

        let no_discontinued = fetch_protocol_config(&client, &fake_aggregator, Epoch(1))
            .await
            .unwrap();
        assert!(
            SignedEntityTypeDiscriminantsMessage::all_discontinued()
                .is_disjoint(&no_discontinued.available_signed_entity_types)
        );

        fake_aggregator
            .protocol_config_send_discontinued_signed_entities()
            .await;

        let with_discontinued = fetch_protocol_config(&client, &fake_aggregator, Epoch(2))
            .await
            .unwrap();
        assert!(
            SignedEntityTypeDiscriminantsMessage::all_discontinued()
                .is_subset(&with_discontinued.available_signed_entity_types)
        );
    }
}
