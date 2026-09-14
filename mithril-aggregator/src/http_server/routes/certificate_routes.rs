use warp::Filter;
use warp::filters::BoxedFilter;

use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    certificate_certificates(router_state)
        .or(certificate_genesis(router_state))
        .or(certificate_certificate_hash(router_state))
        .boxed()
}

/// GET /certificates
fn certificate_certificates(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("certificates")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and_then(handlers::certificate_certificates)
}

/// GET /certificate/genesis
fn certificate_genesis(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("certificate" / "genesis")
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::certificate_genesis)
}

/// GET /certificate/{certificate_hash}
fn certificate_certificate_hash(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("certificate" / String)
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::certificate_certificate_hash)
}

mod handlers {
    use slog::{Logger, warn};
    use std::convert::Infallible;
    use std::sync::Arc;
    use warp::http::StatusCode;

    use crate::MetricsService;
    use crate::http_server::routes::middlewares::ClientMetadata;
    use crate::{http_server::routes::reply, services::MessageService};

    pub const LIST_MAX_ITEMS: usize = 20;

    /// List all Certificates
    pub async fn certificate_certificates(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
    ) -> Result<impl warp::Reply, Infallible> {
        match http_message_service
            .get_certificate_list_message(LIST_MAX_ITEMS)
            .await
        {
            Ok(certificates) => Ok(reply::json(&certificates, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"certificate_certificates::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Certificate by certificate hash
    pub async fn certificate_genesis(
        client_metadata: ClientMetadata,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_certificate_detail_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        match http_message_service.get_latest_genesis_certificate_message().await {
            Ok(Some(certificate)) => Ok(reply::json(&certificate, StatusCode::OK)),
            Ok(None) => Ok(reply::empty(StatusCode::NOT_FOUND)),
            Err(err) => {
                warn!(logger,"certificate_certificate_genesis::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }

    /// Certificate by certificate hash
    pub async fn certificate_certificate_hash(
        certificate_hash: String,
        client_metadata: ClientMetadata,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_certificate_detail_total_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        match http_message_service.get_certificate_message(&certificate_hash).await {
            Ok(Some(certificate)) => Ok(reply::json(&certificate, StatusCode::OK)),
            Ok(None) => Ok(reply::empty(StatusCode::NOT_FOUND)),
            Err(err) => {
                warn!(logger,"certificate_certificate_hash::error"; "error" => ?err);
                Ok(reply::server_error(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use serde_json::Value::Null;
    use std::sync::Arc;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::{
        MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER, messages::CertificateMessage,
        test::double::fake_data,
    };

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
    async fn test_certificate_certificates_get_ok() {
        let dependency_manager = initialize_dependencies!().await;
        dependency_manager
            .certificate_repository
            .create_certificate(fake_data::genesis_certificate("{certificate_hash}"))
            .await
            .expect("certificate store save should have succeeded");

        let method = Method::GET.as_str();
        let path = "/certificates";

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
    async fn test_certificate_when_error_retrieving_certificates_returns_ko_500() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut message_service = MockMessageService::new();
        message_service
            .expect_get_certificate_list_message()
            .returning(|_| Err(anyhow!("an error")));
        dependency_manager.message_service = Arc::new(message_service);

        let method = Method::GET.as_str();
        let path = "/certificates";

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
    async fn test_certificate_certificate_hash_increments_certificate_detail_total_served_since_startup_metric()
     {
        let method = Method::GET.as_str();
        let path = "/certificate/{certificate_hash}";

        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let metric = dependency_manager
            .metrics_service
            .get_certificate_detail_total_served_since_startup();
        let initial_counter_value_with_tag = metric.get(&["TEST", "CLI"]);
        let initial_counter_value_with_unknown_tags =
            metric.get(&["UNKNOWN_ORIGIN", "UNKNOWN_CLIENT_TYPE"]);

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
            initial_counter_value_with_tag + 1,
            metric.get(&["TEST", "CLI"])
        );
        assert_eq!(
            initial_counter_value_with_unknown_tags,
            metric.get(&["UNKNOWN_ORIGIN", "UNKNOWN_CLIENT_TYPE"])
        );
    }

    #[tokio::test]
    async fn test_certificate_certificate_hash_get_ok() {
        let dependency_manager = initialize_dependencies!().await;
        dependency_manager
            .certificate_repository
            .create_certificate(fake_data::genesis_certificate("{certificate_hash}"))
            .await
            .expect("certificate store save should have succeeded");

        let method = Method::GET.as_str();
        let path = "/certificate/{certificate_hash}";

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
    async fn test_certificate_certificate_hash_get_ko_404() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/certificate/{certificate_hash}";

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
    async fn test_certificate_when_error_on_retrieving_certificate_hash_returns_ko_500() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut message_service = MockMessageService::new();
        message_service
            .expect_get_certificate_message()
            .returning(|_| Err(anyhow!("an error")));
        dependency_manager.message_service = Arc::new(message_service);

        let method = Method::GET.as_str();
        let path = "/certificate/{certificate_hash}";

        let response = request()
            .method(method)
            .path(&path.replace("{certificate_hash}", "whatever"))
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
    async fn test_certificate_genesis_increments_certificate_detail_total_served_since_startup_metric()
     {
        let method = Method::GET.as_str();
        let path = "/certificate/genesis";

        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let metric = dependency_manager
            .metrics_service
            .get_certificate_detail_total_served_since_startup();
        let initial_counter_value_with_tag = metric.get(&["TEST", "CLI"]);
        let initial_counter_value_with_unknown_tags =
            metric.get(&["UNKNOWN_ORIGIN", "UNKNOWN_CLIENT_TYPE"]);

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
            initial_counter_value_with_tag + 1,
            metric.get(&["TEST", "CLI"])
        );
        assert_eq!(
            initial_counter_value_with_unknown_tags,
            metric.get(&["UNKNOWN_ORIGIN", "UNKNOWN_CLIENT_TYPE"])
        );
    }

    #[tokio::test]
    async fn test_certificate_genesis_get_ok() {
        let dependency_manager = initialize_dependencies!().await;
        dependency_manager
            .certificate_repository
            .create_certificate(fake_data::genesis_certificate("certificate_genesis_1"))
            .await
            .expect("certificate store save should have succeeded");
        dependency_manager
            .certificate_repository
            .create_certificate(fake_data::genesis_certificate("certificate_genesis_2"))
            .await
            .expect("certificate store save should have succeeded");

        let method = Method::GET.as_str();
        let path = "/certificate/genesis";

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

        let returned_genesis: CertificateMessage = serde_json::from_slice(response.body()).unwrap();
        assert_eq!("certificate_genesis_2", &returned_genesis.hash);
    }

    #[tokio::test]
    async fn test_certificate_genesis_get_ko_404() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/certificate/genesis";

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
    async fn test_certificate_when_error_on_retrieving_certificate_genesis_returns_ko_500() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut message_service = MockMessageService::new();
        message_service
            .expect_get_latest_genesis_certificate_message()
            .returning(|| Err(anyhow!("an error")));
        dependency_manager.message_service = Arc::new(message_service);

        let method = Method::GET.as_str();
        let path = "/certificate/genesis";

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
