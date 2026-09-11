use warp::Filter;
use warp::filters::BoxedFilter;

use crate::http_server::routes::router::RouterState;
use crate::http_server::routes::{MAX_CONTENT_LENGTH, middlewares};

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    post_cardano_database_immutable_files_restored(router_state)
        .or(post_cardano_database_ancillary_files_restored(router_state))
        .or(post_cardano_database_complete_restoration(router_state))
        .or(post_cardano_database_partial_restoration(router_state))
        .boxed()
}

/// POST /statistics/cardano-database/immutable-files-restored
fn post_cardano_database_immutable_files_restored(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("statistics" / "cardano-database" / "immutable-files-restored")
        .and(warp::post())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::json_with_max_length(MAX_CONTENT_LENGTH))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::post_cardano_database_immutable_files_restored)
}

/// POST /statistics/cardano-database/ancillary-files-restored
fn post_cardano_database_ancillary_files_restored(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("statistics" / "cardano-database" / "ancillary-files-restored")
        .and(warp::post())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::post_cardano_database_ancillary_files_restored)
}

/// POST /statistics/cardano-database/complete-restoration
fn post_cardano_database_complete_restoration(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("statistics" / "cardano-database" / "complete-restoration")
        .and(warp::post())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_event_transmitter(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::post_cardano_database_complete_restoration)
}

/// POST /statistics/cardano-database/partial-restoration
fn post_cardano_database_partial_restoration(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("statistics" / "cardano-database" / "partial-restoration")
        .and(warp::post())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_event_transmitter(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::post_cardano_database_partial_restoration)
}

mod handlers {
    use slog::warn;
    use std::{convert::Infallible, sync::Arc};
    use warp::http::StatusCode;

    use mithril_common::messages::CardanoDatabaseImmutableFilesRestoredMessage;

    use crate::MetricsService;
    use crate::event_store::{EventMessage, TransmitterService};
    use crate::http_server::routes::middlewares::ClientMetadata;
    use crate::http_server::routes::reply;

    pub async fn post_cardano_database_immutable_files_restored(
        client_metadata: ClientMetadata,
        message: CardanoDatabaseImmutableFilesRestoredMessage,
        _logger: slog::Logger,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_cardano_database_immutable_files_restored_since_startup()
            .increment_by(
                &[
                    client_metadata.origin_tag.as_deref().unwrap_or_default(),
                    client_metadata.client_type.as_deref().unwrap_or_default(),
                ],
                message.nb_immutable_files,
            );

        Ok(reply::empty(StatusCode::CREATED))
    }

    pub async fn post_cardano_database_ancillary_files_restored(
        client_metadata: ClientMetadata,
        _logger: slog::Logger,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_cardano_database_ancillary_files_restored_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        Ok(reply::empty(StatusCode::CREATED))
    }

    pub async fn post_cardano_database_complete_restoration(
        client_metadata: ClientMetadata,
        logger: slog::Logger,
        event_transmitter: Arc<TransmitterService<EventMessage>>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_cardano_database_complete_restoration_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let headers: Vec<(&str, &str)> = Vec::new();
        let message = EventMessage::new(
            "HTTP::statistics",
            "cardano_database_restoration",
            &"complete".to_string(),
            headers,
        );

        if let Err(e) = event_transmitter.try_send(message.clone()) {
            warn!(logger, "Event message error"; "error" => ?e);
            return Ok(reply::internal_server_error(e));
        };

        Ok(reply::empty(StatusCode::CREATED))
    }

    pub async fn post_cardano_database_partial_restoration(
        client_metadata: ClientMetadata,
        logger: slog::Logger,
        event_transmitter: Arc<TransmitterService<EventMessage>>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_cardano_database_partial_restoration_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let headers: Vec<(&str, &str)> = Vec::new();
        let message = EventMessage::new(
            "HTTP::statistics",
            "cardano_database_restoration",
            &"partial".to_string(),
            headers,
        );

        if let Err(e) = event_transmitter.try_send(message.clone()) {
            warn!(logger, "Event message error"; "error" => ?e);
            return Ok(reply::internal_server_error(e));
        };

        Ok(reply::empty(StatusCode::CREATED))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::mpsc::UnboundedReceiver;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::messages::CardanoDatabaseImmutableFilesRestoredMessage;
    use mithril_common::{
        MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER, temp_dir, test::double::Dummy,
    };

    use crate::ServeCommandDependenciesContainer;
    use crate::event_store::EventMessage;
    use crate::{
        ServeCommandConfiguration, dependency_injection::DependenciesBuilder,
        initialize_dependencies,
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

    mod post_cardano_database_immutable_files_restored {
        use super::*;

        const HTTP_METHOD: Method = Method::POST;
        const PATH: &str = "/statistics/cardano-database/immutable-files-restored";

        #[tokio::test]
        async fn conform_to_open_api_when_created() {
            let message = CardanoDatabaseImmutableFilesRestoredMessage::dummy();

            let dependency_manager = Arc::new(initialize_dependencies!().await);
            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&message)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let result = APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &message,
                &response,
                &StatusCode::CREATED,
            );

            result.unwrap();
        }

        #[tokio::test]
        async fn increments_metric() {
            let dependency_manager = Arc::new(initialize_dependencies!().await);
            let metric_counter = dependency_manager
                .metrics_service
                .get_cardano_database_immutable_files_restored_since_startup();
            let message = CardanoDatabaseImmutableFilesRestoredMessage {
                nb_immutable_files: 3,
            };

            let initial_counter_value = metric_counter.get(&["TEST", "CLI"]);

            request()
                .method(HTTP_METHOD.as_str())
                .json(&message)
                .path(PATH)
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 3,
                metric_counter.get(&["TEST", "CLI"])
            );
        }
    }

    mod post_cardano_database_ancillary_files_restored {
        use super::*;

        const HTTP_METHOD: Method = Method::POST;
        const PATH: &str = "/statistics/cardano-database/ancillary-files-restored";

        #[tokio::test]
        async fn conform_to_open_api_when_created() {
            let dependency_manager = Arc::new(initialize_dependencies!().await);
            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let result = APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &Value::Null,
                &response,
                &StatusCode::CREATED,
            );

            result.unwrap();
        }

        #[tokio::test]
        async fn increments_metric() {
            let dependency_manager = Arc::new(initialize_dependencies!().await);
            let metric_counter = dependency_manager
                .metrics_service
                .get_cardano_database_ancillary_files_restored_since_startup();

            let initial_counter_value = metric_counter.get(&["TEST", "CLI"]);

            request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 1,
                metric_counter.get(&["TEST", "CLI"])
            );
        }
    }

    async fn setup_dependencies(
        snapshot_directory: PathBuf,
    ) -> (
        Arc<ServeCommandDependenciesContainer>,
        UnboundedReceiver<EventMessage>,
    ) {
        let config = ServeCommandConfiguration::new_sample(snapshot_directory);
        let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));
        let rx = builder.get_event_transmitter_receiver().await.unwrap();
        let dependencies_manager =
            Arc::new(builder.build_serve_dependencies_container().await.unwrap());
        (dependencies_manager, rx)
    }

    mod post_cardano_database_complete_restoration {
        use super::*;

        const HTTP_METHOD: Method = Method::POST;
        const PATH: &str = "/statistics/cardano-database/complete-restoration";

        #[tokio::test]
        async fn conform_to_open_api_when_created() {
            let (dependency_manager, _rx) = setup_dependencies(temp_dir!()).await;

            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let result = APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &Value::Null,
                &response,
                &StatusCode::CREATED,
            );

            result.unwrap();
        }

        #[tokio::test]
        async fn should_conform_to_openapi_when_server_error() {
            let (dependency_manager, mut rx) = setup_dependencies(temp_dir!()).await;
            rx.close();

            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &Value::Null,
                &response,
                &StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap();
        }

        #[tokio::test]
        async fn should_send_event() {
            let (dependency_manager, mut rx) = setup_dependencies(temp_dir!()).await;

            request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let message = rx.try_recv().unwrap();
            assert_eq!("HTTP::statistics", message.source);
            assert_eq!("cardano_database_restoration", message.action);
            assert_eq!("complete", message.content);
        }

        #[tokio::test]
        async fn increments_metric() {
            let (dependency_manager, _rx) = setup_dependencies(temp_dir!()).await;
            let metric_counter = dependency_manager
                .metrics_service
                .get_cardano_database_complete_restoration_since_startup();

            let initial_counter_value = metric_counter.get(&["TEST", "CLI"]);

            request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 1,
                metric_counter.get(&["TEST", "CLI"])
            );
        }
    }

    mod post_cardano_database_partial_restoration {
        use super::*;

        const HTTP_METHOD: Method = Method::POST;
        const PATH: &str = "/statistics/cardano-database/partial-restoration";

        #[tokio::test]
        async fn conform_to_open_api_when_created() {
            let (dependency_manager, _rx) = setup_dependencies(temp_dir!()).await;
            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let result = APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &Value::Null,
                &response,
                &StatusCode::CREATED,
            );

            result.unwrap();
        }

        #[tokio::test]
        async fn should_conform_to_openapi_when_server_error() {
            let (dependency_manager, mut rx) = setup_dependencies(temp_dir!()).await;
            rx.close();

            let response = request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            APISpec::verify_conformity(
                APISpec::get_default_spec_file_from(crate::http_server::API_SPEC_LOCATION),
                HTTP_METHOD.as_str(),
                PATH,
                "application/json",
                &Value::Null,
                &response,
                &StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap();
        }

        #[tokio::test]
        async fn should_send_event() {
            let (dependency_manager, mut rx) = setup_dependencies(temp_dir!()).await;

            request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .reply(&setup_router(RouterState::new_with_dummy_config(
                    dependency_manager.clone(),
                )))
                .await;

            let message = rx.try_recv().unwrap();
            assert_eq!("HTTP::statistics", message.source);
            assert_eq!("cardano_database_restoration", message.action);
            assert_eq!("partial", message.content);
        }

        #[tokio::test]
        async fn increments_metric() {
            let (dependency_manager, _rx) = setup_dependencies(temp_dir!()).await;
            let metric_counter = dependency_manager
                .metrics_service
                .get_cardano_database_partial_restoration_since_startup();

            let initial_counter_value = metric_counter.get(&["TEST", "CLI"]);

            request()
                .method(HTTP_METHOD.as_str())
                .json(&Value::Null)
                .path(PATH)
                .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
                .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
                .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                    dependency_manager.clone(),
                    &["TEST"],
                )))
                .await;

            assert_eq!(
                initial_counter_value + 1,
                metric_counter.get(&["TEST", "CLI"])
            );
        }
    }
}
