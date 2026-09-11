use warp::Filter;
use warp::filters::BoxedFilter;

use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    epoch_settings(router_state).boxed()
}

/// GET /epoch-settings
fn epoch_settings(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("epoch-settings")
        .and(warp::get())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_http_message_service(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.allowed_discriminants.clone()
        }))
        .and_then(handlers::epoch_settings)
}

mod handlers {
    use slog::{Logger, warn};
    use std::collections::BTreeSet;
    use std::convert::Infallible;
    use std::sync::Arc;
    use warp::http::StatusCode;

    use mithril_common::entities::SignedEntityTypeDiscriminants;

    use crate::http_server::routes::reply;
    use crate::services::MessageService;

    /// Epoch Settings
    pub async fn epoch_settings(
        logger: Logger,
        http_message_service: Arc<dyn MessageService>,
        allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
    ) -> Result<impl warp::Reply, Infallible> {
        let epoch_settings_message = http_message_service
            .get_epoch_settings_message(allowed_discriminants)
            .await;

        match epoch_settings_message {
            Ok(message) => Ok(reply::json(&message, StatusCode::OK)),
            Err(err) => {
                warn!(logger,"epoch_settings::error"; "error" => ?err);
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
    use mithril_common::messages::EpochSettingsMessage;
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
    async fn test_epoch_settings_get_ok() {
        let method = Method::GET.as_str();
        let path = "/epoch-settings";
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_epoch_settings_message()
            .return_once(|_| Ok(EpochSettingsMessage::dummy()))
            .once();
        dependency_manager.message_service = Arc::new(mock_http_message_service);

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
    async fn test_epoch_settings_get_ko_500() {
        let method = Method::GET.as_str();
        let path = "/epoch-settings";
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_http_message_service = MockMessageService::new();
        mock_http_message_service
            .expect_get_epoch_settings_message()
            .return_once(|_| Err(anyhow!("an error")))
            .once();
        dependency_manager.message_service = Arc::new(mock_http_message_service);

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
