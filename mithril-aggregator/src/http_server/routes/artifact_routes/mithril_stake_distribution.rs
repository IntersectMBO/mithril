use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;
use warp::Filter;
use warp::filters::BoxedFilter;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    artifact_mithril_stake_distributions(router_state)
        .or(artifact_mithril_stake_distribution_by_id(router_state))
        .boxed()
}

/// GET /artifact/mithril-stake-distributions
fn artifact_mithril_stake_distributions(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "mithril-stake-distributions")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and_then(handlers::list_artifacts)
}

/// GET /artifact/mithril-stake-distribution/:id
fn artifact_mithril_stake_distribution_by_id(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "mithril-stake-distribution" / String)
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::get_artifact_by_signed_entity_id)
}

pub mod handlers {
    use slog::{Logger, warn};
    use std::convert::Infallible;
    use std::sync::Arc;
    use warp::http::StatusCode;

    use crate::MetricsService;
    use crate::http_server::routes::middlewares::ClientMetadata;
    use crate::http_server::routes::reply;
    use crate::services::MessageService;

    pub const LIST_MAX_ITEMS: usize = 20;

    /// List MithrilStakeDistribution artifacts
    pub async fn list_artifacts(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
    ) -> Result<impl warp::Reply, Infallible> {
        match http_message_service
            .get_mithril_stake_distribution_list_message(LIST_MAX_ITEMS)
            .await
        {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"list_artifacts_mithril_stake_distribution"; "error" => ?err);
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
            .get_artifact_detail_mithril_stake_distribution_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        match http_message_service
            .get_mithril_stake_distribution_message(&signed_entity_id)
            .await
        {
            Ok(Some(message)) => Ok(reply::json(&message, StatusCode::OK)),
            Ok(None) => {
                warn!(logger, "get_mithril_stake_distribution_details::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
            Err(err) => {
                warn!(logger,"get_mithril_stake_distribution_details::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::Value::Null;
    use std::sync::Arc;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::{
        MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER,
        messages::{MithrilStakeDistributionListItemMessage, MithrilStakeDistributionMessage},
        test::double::Dummy,
    };
    use mithril_persistence::sqlite::HydrationError;

    use crate::{initialize_dependencies, services::MockMessageService};

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
    async fn test_mithril_stake_distributions_get_ok() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_mithril_stake_distribution_list_message()
            .return_once(|_| Ok(vec![MithrilStakeDistributionListItemMessage::dummy()]))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distributions";

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
    async fn test_mithril_stake_distributions_get_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_mithril_stake_distribution_list_message()
            .return_once(|_| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distributions";

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
    async fn test_mithril_stake_distribution_increments_artifact_detail_total_served_since_startup_metric()
     {
        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distribution/{hash}";
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_counter_value = dependency_manager
            .metrics_service
            .get_artifact_detail_mithril_stake_distribution_total_served_since_startup()
            .get(&["TEST", "CLI"]);

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
                .get_artifact_detail_mithril_stake_distribution_total_served_since_startup()
                .get(&["TEST", "CLI"]),
        );
    }

    #[tokio::test]
    async fn test_mithril_stake_distribution_get_ok() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_mithril_stake_distribution_message()
            .return_once(|_| Ok(Some(MithrilStakeDistributionMessage::dummy())))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distribution/{hash}";

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
    async fn test_mithril_stake_distribution_returns_404_no_found_when_no_record() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_mithril_stake_distribution_message()
            .return_once(|_| Ok(None))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distribution/{hash}";

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
    async fn test_mithril_stake_distribution_get_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_mithril_stake_distribution_message()
            .return_once(|_| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/mithril-stake-distribution/{hash}";

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
}
