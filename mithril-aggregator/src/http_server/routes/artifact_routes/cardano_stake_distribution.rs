use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;
use warp::Filter;
use warp::filters::BoxedFilter;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    artifact_cardano_stake_distributions(router_state)
        .or(artifact_cardano_stake_distribution_by_id(router_state))
        .or(artifact_cardano_stake_distribution_by_epoch(router_state))
        .boxed()
}

/// GET /artifact/cardano-stake-distributions
fn artifact_cardano_stake_distributions(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-stake-distributions")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and_then(handlers::list_artifacts)
}

/// GET /artifact/cardano-stake-distribution/:id
fn artifact_cardano_stake_distribution_by_id(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-stake-distribution" / String)
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::get_artifact_by_signed_entity_id)
}

/// GET /artifact/cardano-stake-distribution/epoch/:epoch
fn artifact_cardano_stake_distribution_by_epoch(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-stake-distribution" / "epoch" / String)
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and(middlewares::with_epoch_service(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.max_artifact_epoch_offset
        }))
        .and_then(handlers::get_artifact_by_epoch)
}

pub mod handlers {
    use slog::{Logger, warn};
    use std::convert::Infallible;
    use std::sync::Arc;
    use warp::http::StatusCode;

    use crate::MetricsService;
    use crate::dependency_injection::EpochServiceWrapper;
    use crate::http_server::{parameters, routes::middlewares::ClientMetadata, routes::reply};
    use crate::services::MessageService;

    pub const LIST_MAX_ITEMS: usize = 20;

    /// List CardanoStakeDistribution artifacts
    pub async fn list_artifacts(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
    ) -> Result<impl warp::Reply, Infallible> {
        match http_message_service
            .get_cardano_stake_distribution_list_message(LIST_MAX_ITEMS)
            .await
        {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger, "get_cardano_stake_distribution_list::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Get Artifact by signed entity id
    pub async fn get_artifact_by_signed_entity_id(
        signed_entity_id: String,
        client_metadata: ClientMetadata,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_artifact_detail_cardano_stake_distribution_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        match http_message_service
            .get_cardano_stake_distribution_message(&signed_entity_id)
            .await
        {
            Ok(Some(message)) => Ok(reply::json(&message, StatusCode::OK)),
            Ok(None) => {
                warn!(logger, "get_cardano_stake_distribution_details::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
            Err(err) => {
                warn!(logger, "get_cardano_stake_distribution_details::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Get Artifact by epoch
    pub async fn get_artifact_by_epoch(
        epoch: String,
        client_metadata: ClientMetadata,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        metrics_service: Arc<MetricsService>,
        epoch_service: EpochServiceWrapper,
        max_artifact_epoch_offset: u64,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_artifact_detail_cardano_stake_distribution_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let expanded_epoch = match parameters::expand_epoch(&epoch, epoch_service).await {
            Ok(epoch) => epoch,
            Err(err) => {
                warn!(logger, "get_artifact_by_epoch::invalid_epoch"; "error" => ?err);
                return Ok(reply::bad_request(
                    "invalid_epoch".to_string(),
                    err.to_string(),
                ));
            }
        };

        if expanded_epoch.has_offset_greater_than(max_artifact_epoch_offset) {
            return Ok(reply::bad_request(
                "invalid_epoch".to_string(),
                format!(
                    "offset greater than maximum allowed value: epoch:`{epoch}`, max offset:`{max_artifact_epoch_offset}`"
                ),
            ));
        }

        match http_message_service
            .get_cardano_stake_distribution_message_by_epoch(
                // Reminder: Cardano stake distribution is recorded with a `-1` epoch offset
                expanded_epoch.apply_offset_for_latest(1),
            )
            .await
        {
            Ok(Some(message)) => Ok(reply::json(&message, StatusCode::OK)),
            Ok(None) => {
                warn!(
                    logger,
                    "get_cardano_stake_distribution_details_by_epoch::not_found"
                );
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
            Err(err) => {
                warn!(logger, "get_cardano_stake_distribution_details_by_epoch::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use anyhow::anyhow;
    use serde_json::Value::Null;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::{
        MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER,
        entities::Epoch,
        messages::{CardanoStakeDistributionListItemMessage, CardanoStakeDistributionMessage},
        test::double::Dummy,
    };

    use crate::{
        http_server::routes::router::RouterConfig,
        initialize_dependencies,
        services::{FakeEpochServiceBuilder, MockMessageService},
    };

    use super::*;

    fn setup_router(
        state: RouterState,
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS]);

        warp::any().and(routes(&state).with(cors))
    }

    #[tokio::test]
    async fn test_cardano_stake_distributions_returns_ok() {
        let message = vec![CardanoStakeDistributionListItemMessage::dummy()];
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_list_message()
            .return_once(|_| Ok(message))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-stake-distributions";

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            path,
            "application/json",
            &Null,
            &response,
            &StatusCode::OK,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distributions_returns_ko_500_when_error() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_list_message()
            .return_once(|_| Err(anyhow!("an error occured")))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-stake-distributions";

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            path,
            "application/json",
            &Null,
            &response,
            &StatusCode::INTERNAL_SERVER_ERROR,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_increments_artifact_detail_total_served_since_startup_metric()
     {
        let method = Method::GET.as_str();
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_counter_value = dependency_manager
            .metrics_service
            .get_artifact_detail_cardano_stake_distribution_total_served_since_startup()
            .get(&["TEST", "CLI"]);
        {
            let path = "/artifact/cardano-stake-distribution/{hash}";

            request()
                .method(method)
                .path(path)
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 1,
                dependency_manager
                    .metrics_service
                    .get_artifact_detail_cardano_stake_distribution_total_served_since_startup()
                    .get(&["TEST", "CLI"])
            );
        }

        {
            let base_path = "/artifact/cardano-stake-distribution/epoch";

            request()
                .method(method)
                .path(&format!("{base_path}/123"))
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 2,
                dependency_manager
                    .metrics_service
                    .get_artifact_detail_cardano_stake_distribution_total_served_since_startup()
                    .get(&["TEST", "CLI"])
            );
        }
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_returns_ok() {
        let message = CardanoStakeDistributionMessage::dummy();
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message()
            .return_once(|_| Ok(Some(message)))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-stake-distribution/{hash}";

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            path,
            "application/json",
            &Null,
            &response,
            &StatusCode::OK,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_returns_404_not_found_when_no_record() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message()
            .return_once(|_| Ok(None))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-stake-distribution/{hash}";

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            path,
            "application/json",
            &Null,
            &response,
            &StatusCode::NOT_FOUND,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_returns_ko_500_when_error() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message()
            .return_once(|_| Err(anyhow!("an error occured")))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-stake-distribution/{hash}";

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            path,
            "application/json",
            &Null,
            &response,
            &StatusCode::INTERNAL_SERVER_ERROR,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_by_epoch_returns_ok() {
        let message = CardanoStakeDistributionMessage::dummy();
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message_by_epoch()
            .return_once(|_| Ok(Some(message)))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-stake-distribution/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/123"))
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            &format!("{base_path}/{{epoch}}"),
            "application/json",
            &Null,
            &response,
            &StatusCode::OK,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_by_epoch_returns_400_bad_request_when_invalid_epoch() {
        let mock_http_message_service = MockMessageService::new();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-stake-distribution/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/invalid-epoch"))
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            &format!("{base_path}/{{epoch}}"),
            "application/json",
            &Null,
            &response,
            &StatusCode::BAD_REQUEST,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_by_epoch_returns_400_bad_request_when_offset_greater_than_max_configured()
     {
        let epoch_service = FakeEpochServiceBuilder::dummy(Epoch(100)).build();
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message_by_epoch()
            .return_once(|_| Ok(Some(CardanoStakeDistributionMessage::dummy())))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.epoch_service = Arc::new(RwLock::new(epoch_service));
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-stake-distribution/epoch";

        let router = setup_router(RouterState::new(
            Arc::new(dependency_manager),
            RouterConfig {
                max_artifact_epoch_offset: 10,
                ..RouterConfig::dummy()
            },
        ));

        let response = request()
            .method(method)
            .path(&format!("{base_path}/latest-10"))
            .reply(&router)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = request()
            .method(method)
            .path(&format!("{base_path}/latest-11"))
            .reply(&router)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_by_epoch_returns_404_not_found_when_no_record() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message_by_epoch()
            .return_once(|_| Ok(None))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-stake-distribution/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/123"))
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            &format!("{base_path}/{{epoch}}"),
            "application/json",
            &Null,
            &response,
            &StatusCode::NOT_FOUND,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cardano_stake_distribution_by_epoch_returns_ko_500_when_error() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_stake_distribution_message_by_epoch()
            .return_once(|_| Err(anyhow!("an error occured")))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-stake-distribution/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/123"))
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        APISpec::verify_conformity(
            APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
            method,
            &format!("{base_path}/{{epoch}}"),
            "application/json",
            &Null,
            &response,
            &StatusCode::INTERNAL_SERVER_ERROR,
        )
        .unwrap();
    }
}
