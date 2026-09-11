use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;
use warp::Filter;
use warp::filters::BoxedFilter;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    artifact_cardano_database_list(router_state)
        .or(artifact_cardano_database_list_by_epoch(router_state))
        .or(artifact_cardano_database_digest_list(router_state))
        .or(artifact_cardano_database_by_id(router_state))
        .or(serve_cardano_database_dir(router_state))
        .boxed()
}

/// GET /artifact/cardano-database
fn artifact_cardano_database_list(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-database")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and_then(handlers::list_artifacts)
}

/// GET /artifact/cardano-database/epoch/:epoch
fn artifact_cardano_database_list_by_epoch(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-database" / "epoch" / String)
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_epoch_service(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.max_artifact_epoch_offset
        }))
        .and_then(handlers::list_artifacts_by_epoch)
}

/// GET /artifact/cardano-database/:id
fn artifact_cardano_database_by_id(
    dependency_manager: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-database" / String)
        .and(warp::get())
        .and(middlewares::with_client_metadata(dependency_manager))
        .and(middlewares::with_logger(dependency_manager))
        .and(middlewares::with_http_message_service(dependency_manager))
        .and(middlewares::with_metrics_service(dependency_manager))
        .and_then(handlers::get_artifact_by_signed_entity_id)
}

/// GET /artifact/cardano-database/digests
fn artifact_cardano_database_digest_list(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("artifact" / "cardano-database" / "digests")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and_then(handlers::list_digests)
}

fn serve_cardano_database_dir(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path(crate::http_server::CARDANO_DATABASE_DOWNLOAD_PATH)
        .and(warp::fs::dir(
            router_state.configuration.cardano_db_artifacts_directory.clone(),
        ))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.allow_http_serve_directory
        }))
        .and_then(handlers::ensure_downloaded_file_is_a_cardano_database_artifact)
}

mod handlers {
    use slog::{Logger, debug, warn};
    use std::convert::Infallible;
    use std::sync::Arc;
    use warp::http::StatusCode;

    use crate::MetricsService;
    use crate::dependency_injection::EpochServiceWrapper;
    use crate::http_server::{parameters, routes::middlewares::ClientMetadata, routes::reply};
    use crate::services::MessageService;

    pub const LIST_MAX_ITEMS: usize = 20;

    /// List artifacts
    pub async fn list_artifacts(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
    ) -> Result<impl warp::Reply, Infallible> {
        match http_message_service
            .get_cardano_database_list_message(LIST_MAX_ITEMS)
            .await
        {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"list_artifacts_cardano_database"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// List artifacts for an epoch
    pub async fn list_artifacts_by_epoch(
        epoch: String,
        logger: Logger,
        epoch_service: EpochServiceWrapper,
        http_message_service: Arc<dyn MessageService>,
        max_artifact_epoch_offset: u64,
    ) -> Result<impl warp::Reply, Infallible> {
        let expanded_epoch = match parameters::expand_epoch(&epoch, epoch_service).await {
            Ok(epoch) => epoch,
            Err(err) => {
                warn!(logger,"list_by_epoch_artifacts_cardano_database::invalid_epoch"; "error" => ?err);
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
            .get_cardano_database_list_message_by_epoch(LIST_MAX_ITEMS, *expanded_epoch)
            .await
        {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"list_by_epoch_artifacts_cardano_database"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Get artifact by signed entity id
    pub async fn get_artifact_by_signed_entity_id(
        signed_entity_id: String,
        client_metadata: ClientMetadata,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_artifact_detail_cardano_database_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        match http_message_service
            .get_cardano_database_message(&signed_entity_id)
            .await
        {
            Ok(Some(signed_entity)) => Ok(reply::json(&signed_entity, StatusCode::OK)),
            Ok(None) => {
                warn!(logger, "cardano_database_details::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
            Err(err) => {
                warn!(logger,"cardano_database_details::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Download a file if it's a Cardano_database artifact file
    // TODO: this function should probable be unit tested once the file naming convention is defined
    pub async fn ensure_downloaded_file_is_a_cardano_database_artifact(
        reply: warp::fs::File,
        logger: Logger,
        allow_http_serve_directory: bool,
    ) -> Result<impl warp::Reply, Infallible> {
        let filepath = reply.path().to_path_buf();
        debug!(
            logger,
            ">> ensure_downloaded_file_is_a_cardano_database / file: `{}`",
            filepath.display()
        );

        if !allow_http_serve_directory {
            warn!(logger, "ensure_downloaded_file_is_a_cardano_database::error"; "error" => "http serve directory is disabled");
            return Ok(reply::empty(StatusCode::FORBIDDEN));
        }

        // TODO: enhance this check with a regular expression once the file naming convention is defined
        let file_is_a_cardano_database_archive = filepath.to_string_lossy().contains("ancillary")
            || filepath.to_string_lossy().contains("immutable")
            || filepath.to_string_lossy().contains("digests");
        match file_is_a_cardano_database_archive {
            true => Ok(reply::add_content_disposition_header(reply, &filepath)),
            false => {
                warn!(logger,"ensure_downloaded_file_is_a_cardano_database::error"; "error" => "file is not a Cardano database archive");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }

    /// List digests
    pub async fn list_digests(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
    ) -> Result<impl warp::Reply, Infallible> {
        match http_message_service.get_cardano_database_digest_list_message().await {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"list_digests_cardano_database"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::{always, eq};
    use serde_json::Value::Null;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::entities::Epoch;
    use mithril_common::messages::{
        CardanoDatabaseDigestListItemMessage, CardanoDatabaseSnapshotListItemMessage,
        CardanoDatabaseSnapshotMessage,
    };
    use mithril_common::test::double::Dummy;
    use mithril_common::{MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER};
    use mithril_persistence::sqlite::HydrationError;

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
    async fn test_cardano_database_get_ok() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_list_message()
            .return_once(|_| Ok(vec![CardanoDatabaseSnapshotListItemMessage::dummy()]))
            .once();

        let mut dependency_manager = initialize_dependencies!().await;

        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database";

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
    async fn test_cardano_database_get_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_list_message()
            .return_once(|_| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database";

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
    async fn test_cardano_database_get_by_epoch_ok() {
        let epoch_service = FakeEpochServiceBuilder::dummy(Epoch(100)).build();
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_list_message_by_epoch()
            .with(always(), eq(&Epoch(85)))
            .return_once(|_, _| Ok(vec![CardanoDatabaseSnapshotListItemMessage::dummy()]))
            .once();

        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.epoch_service = Arc::new(RwLock::new(epoch_service));
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-database/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/latest-15"))
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
    async fn test_cardano_database_get_by_epoch_reject_query_with_offset_greater_than_max_configured()
     {
        let epoch_service = FakeEpochServiceBuilder::dummy(Epoch(100)).build();
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_list_message_by_epoch()
            .returning(|_, _| Ok(vec![CardanoDatabaseSnapshotListItemMessage::dummy()]));

        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.epoch_service = Arc::new(RwLock::new(epoch_service));
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let router = setup_router(RouterState::new(
            Arc::new(dependency_manager),
            RouterConfig {
                max_artifact_epoch_offset: 10,
                ..RouterConfig::dummy()
            },
        ));

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-database/epoch";

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
    async fn test_cardano_database_get_by_epoch_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_list_message_by_epoch()
            .return_once(|_, _| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();

        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let base_path = "/artifact/cardano-database/epoch";

        let response = request()
            .method(method)
            .path(&format!("{base_path}/120"))
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

    #[tokio::test]
    async fn test_cardano_database_detail_increments_artifact_detail_total_served_since_startup_metric()
     {
        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/{hash}";
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_counter_value = dependency_manager
            .metrics_service
            .get_artifact_detail_cardano_database_total_served_since_startup()
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
                .get_artifact_detail_cardano_database_total_served_since_startup()
                .get(&["TEST", "CLI"]),
        );
    }

    #[tokio::test]
    async fn test_cardano_database_detail_get_ok() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_message()
            .return_once(|_| Ok(Some(CardanoDatabaseSnapshotMessage::dummy())))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/{hash}";

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
    async fn test_cardano_database_detail_returns_404_not_found_when_no_cardano_database_snapshot()
    {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_message()
            .return_once(|_| Ok(None))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/{hash}";

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
    async fn test_cardano_database_detail_get_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_message()
            .return_once(|_| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/{hash}";

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
    async fn test_cardano_database_get_digests_ok() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_digest_list_message()
            .return_once(|| Ok(vec![CardanoDatabaseDigestListItemMessage::dummy()]))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/digests";

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
    async fn test_cardano_database_get_digests_ko() {
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_cardano_database_digest_list_message()
            .return_once(|| Err(HydrationError::InvalidData("invalid data".to_string()).into()))
            .once();
        let mut dependency_manager = initialize_dependencies!().await;
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let method = Method::GET.as_str();
        let path = "/artifact/cardano-database/digests";

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
