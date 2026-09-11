use super::middlewares;
use crate::http_server::routes::router::RouterState;
use warp::Filter;
use warp::filters::BoxedFilter;

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    root(router_state).boxed()
}

/// GET /
fn root(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path::end()
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_api_version_provider(router_state))
        .and(middlewares::extract_config(router_state, |config| {
            config.allowed_discriminants.clone()
        }))
        .and(middlewares::extract_config(router_state, |config| {
            config.aggregate_signature_type
        }))
        .and(middlewares::extract_config(router_state, |config| {
            config.cardano_prover_max_hashes_allowed_by_request
        }))
        .and_then(handlers::root)
}

mod handlers {
    use std::collections::BTreeSet;
    use std::{convert::Infallible, sync::Arc};

    use mithril_common::AggregateSignatureType;
    use slog::Logger;
    use warp::http::StatusCode;

    use mithril_common::api_version::APIVersionProvider;
    use mithril_common::entities::SignedEntityTypeDiscriminants;
    use mithril_common::messages::{
        AggregatorCapabilities, AggregatorFeaturesMessage, CardanoTransactionsProverCapabilities,
    };

    use crate::http_server::routes::reply::json;
    use crate::unwrap_to_internal_server_error;

    /// Root
    pub async fn root(
        logger: Logger,
        api_version_provider: Arc<APIVersionProvider>,
        allowed_signed_entity_type_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
        aggregate_signature_type: AggregateSignatureType,
        max_hashes_allowed_by_request: usize,
    ) -> Result<impl warp::Reply, Infallible> {
        let open_api_version = unwrap_to_internal_server_error!(
            api_version_provider.compute_current_version(),
            logger => "root::error"
        );

        let mut capabilities = AggregatorCapabilities {
            signed_entity_types: allowed_signed_entity_type_discriminants
                .into_iter()
                .map(Into::into)
                .collect(),
            aggregate_signature_type,
            cardano_transactions_prover: None,
        };

        if capabilities
            .signed_entity_types
            .contains(&SignedEntityTypeDiscriminants::CardanoTransactions.into())
        {
            capabilities.cardano_transactions_prover =
                Some(CardanoTransactionsProverCapabilities {
                    max_hashes_allowed_by_request,
                });
        }

        Ok(json(
            &AggregatorFeaturesMessage {
                open_api_version: open_api_version.to_string(),
                documentation_url: env!("CARGO_PKG_HOMEPAGE").to_string(),
                capabilities,
            },
            StatusCode::OK,
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value::Null;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use warp::http::{Method, StatusCode};
    use warp::test::request;

    use mithril_api_spec::APISpec;
    use mithril_common::AggregateSignatureType;
    use mithril_common::entities::SignedEntityTypeDiscriminants;
    use mithril_common::messages::{
        AggregatorCapabilities, AggregatorFeaturesMessage, CardanoTransactionsProverCapabilities,
    };
    use mithril_common::test::double::Dummy;

    use crate::http_server::routes::router::RouterConfig;
    use crate::initialize_dependencies;

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
    async fn test_root_route_ok() {
        let method = Method::GET.as_str();
        let path = "/";
        let config = RouterConfig {
            allowed_discriminants: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoDatabase,
            ]),
            cardano_prover_max_hashes_allowed_by_request: 500,
            ..RouterConfig::dummy()
        };
        let dependency_manager = initialize_dependencies!().await;

        let expected_open_api_version = dependency_manager
            .api_version_provider
            .clone()
            .compute_current_version()
            .unwrap()
            .to_string();

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new(
                Arc::new(dependency_manager),
                config,
            )))
            .await;

        let response_body: AggregatorFeaturesMessage =
            serde_json::from_slice(response.body()).unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            response_body,
            AggregatorFeaturesMessage {
                open_api_version: expected_open_api_version,
                documentation_url: env!("CARGO_PKG_HOMEPAGE").to_string(),
                capabilities: AggregatorCapabilities {
                    signed_entity_types: BTreeSet::from_iter([
                        SignedEntityTypeDiscriminants::CardanoStakeDistribution.into(),
                        SignedEntityTypeDiscriminants::MithrilStakeDistribution.into(),
                        SignedEntityTypeDiscriminants::CardanoTransactions.into(),
                        SignedEntityTypeDiscriminants::CardanoDatabase.into(),
                    ]),
                    aggregate_signature_type: AggregateSignatureType::Concatenation,
                    cardano_transactions_prover: Some(CardanoTransactionsProverCapabilities {
                        max_hashes_allowed_by_request: 500
                    }),
                },
            }
        );

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
    async fn test_root_route_ok_with_cardano_transactions_enabled() {
        let method = Method::GET.as_str();
        let path = "/";
        let config = RouterConfig {
            allowed_discriminants: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_prover_max_hashes_allowed_by_request: 99,
            ..RouterConfig::dummy()
        };
        let dependency_manager = initialize_dependencies!().await;

        let response = request()
            .method(method)
            .path(path)
            .reply(&setup_router(RouterState::new(
                Arc::new(dependency_manager),
                config,
            )))
            .await;

        let response_body: AggregatorFeaturesMessage =
            serde_json::from_slice(response.body()).unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            response_body.capabilities.cardano_transactions_prover,
            Some(CardanoTransactionsProverCapabilities {
                max_hashes_allowed_by_request: 99
            })
        );

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
}
