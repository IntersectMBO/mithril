use warp::Filter;
use warp::filters::BoxedFilter;

use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    protocol_configuration(router_state).boxed()
}

/// GET /protocol-configuration
fn protocol_configuration(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("protocol-configuration" / u64)
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.allowed_discriminants.clone()
        }))
        .and_then(handlers::protocol_configuration)
}

mod handlers {
    use slog::{Logger, warn};
    use std::{collections::BTreeSet, convert::Infallible, sync::Arc};
    use warp::http::StatusCode;

    use mithril_common::entities::{Epoch, SignedEntityTypeDiscriminants};

    use crate::{http_server::routes::reply, services::MessageService};

    /// Protocol Configuration
    pub async fn protocol_configuration(
        epoch: u64,
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
    ) -> Result<impl warp::Reply, Infallible> {
        let epoch = Epoch(epoch);

        let protocol_configuration_message = http_message_service
            .get_protocol_configuration_message(epoch, allowed_discriminants)
            .await;

        match protocol_configuration_message {
            Ok(Some(message)) => Ok(reply::json(&message, warp::http::StatusCode::OK)),
            Ok(None) => {
                warn!(logger, "protocol_configuration::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
            Err(err) => {
                slog::warn!(logger, "protocol_configuration::error"; "error" => ?err);
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
    use mithril_common::messages::ProtocolConfigurationMessage;
    use mithril_common::test::double::Dummy;

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
    async fn test_protocol_configuration_get_ok() {
        let method = Method::GET.as_str();
        let base_path = "/protocol-configuration";
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_protocol_configuration_message()
            .return_once(|_, _| Ok(Some(ProtocolConfigurationMessage::dummy())))
            .once();
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let response = request()
            .method(method)
            .path(&format!("{base_path}/42"))
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
    async fn test_protocol_configuration_return_404_when_no_configuration_found() {
        let method = Method::GET.as_str();
        let base_path = "/protocol-configuration";
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_protocol_configuration_message()
            .return_once(|_, _| Ok(None))
            .once();
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let response = request()
            .method(method)
            .path(&format!("{base_path}/42"))
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
    async fn test_protocol_configuration_get_ko_500() {
        let method = Method::GET.as_str();
        let base_path = "/protocol-configuration";
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_protocol_configuration_message()
            .return_once(|_, _| Err(anyhow!("an error")))
            .once();
        dependency_manager.message_service = Arc::new(mock_http_message_service);

        let response = request()
            .method(method)
            .path(&format!("{base_path}/42"))
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
