use crate::ServeCommandDependenciesContainer;
use crate::http_server::SERVER_BASE_PATH;
use crate::http_server::routes::{
    artifact_routes, certificate_routes, epoch_routes, protocol_configuration_routes, root_routes,
    signatures_routes, signer_routes, statistics_routes, status,
};

use mithril_common::api_version::APIVersionProvider;
use mithril_common::entities::SignedEntityTypeDiscriminants;
#[cfg(test)]
use mithril_common::test::double::Dummy;
use mithril_common::{
    AggregateSignatureType, CardanoNetwork, MITHRIL_API_VERSION_HEADER, MITHRIL_CLIENT_TYPE_HEADER,
    MITHRIL_ORIGIN_TAG_HEADER,
};

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use warp::http::Method;
use warp::http::StatusCode;
use warp::{Filter, Rejection, Reply};

use super::{middlewares, proof_routes};

/// HTTP Server configuration
pub struct RouterConfig {
    pub network: CardanoNetwork,
    pub allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
    pub cardano_prover_max_hashes_allowed_by_request: usize,
    pub cardano_db_artifacts_directory: PathBuf,
    pub max_artifact_epoch_offset: u64,
    pub cardano_node_version: String,
    pub allow_http_serve_directory: bool,
    pub origin_tag_white_list: HashSet<String>,
    pub aggregate_signature_type: AggregateSignatureType,
    pub leader_aggregator_endpoint: Option<String>,
    pub certificate_chain_aggregator_endpoint: Option<String>,
}

#[cfg(test)]
impl Dummy for RouterConfig {
    fn dummy() -> Self {
        Self {
            network: CardanoNetwork::TestNet(87),
            allowed_discriminants: BTreeSet::from([
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            ]),
            cardano_prover_max_hashes_allowed_by_request: 1_000,
            cardano_db_artifacts_directory: PathBuf::from("/dummy/cardano-db/directory"),
            max_artifact_epoch_offset: 100,
            cardano_node_version: "1.2.3".to_string(),
            allow_http_serve_directory: false,
            origin_tag_white_list: HashSet::from(["DUMMY_TAG".to_string()]),
            aggregate_signature_type: AggregateSignatureType::Concatenation,
            leader_aggregator_endpoint: None,
            certificate_chain_aggregator_endpoint: None,
        }
    }
}

#[cfg(test)]
impl RouterConfig {
    pub fn dummy_with_origin_tag_white_list(origin_tag_white_list: &[&str]) -> Self {
        Self {
            origin_tag_white_list: origin_tag_white_list
                .iter()
                .map(|tag| tag.to_string())
                .collect(),
            ..RouterConfig::dummy()
        }
    }
}

/// Shared state for the router
pub struct RouterState {
    pub dependencies: Arc<ServeCommandDependenciesContainer>,
    pub configuration: RouterConfig,
}

impl RouterState {
    /// `RouterState` factory
    pub fn new(
        dependencies: Arc<ServeCommandDependenciesContainer>,
        configuration: RouterConfig,
    ) -> Self {
        Self {
            dependencies,
            configuration,
        }
    }
}

#[cfg(test)]
impl RouterState {
    pub fn new_with_dummy_config(dependencies: Arc<ServeCommandDependenciesContainer>) -> Self {
        Self {
            dependencies,
            configuration: RouterConfig::dummy(),
        }
    }

    pub fn new_with_origin_tag_white_list(
        dependencies: Arc<ServeCommandDependenciesContainer>,
        origin_tag_white_list: &[&str],
    ) -> Self {
        Self {
            dependencies,
            configuration: RouterConfig::dummy_with_origin_tag_white_list(origin_tag_white_list),
        }
    }
}

/// Routes
pub fn routes(
    state: Arc<RouterState>,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "content-type",
            MITHRIL_API_VERSION_HEADER,
            MITHRIL_ORIGIN_TAG_HEADER,
            MITHRIL_CLIENT_TYPE_HEADER,
        ])
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS]);

    warp::any()
        .and(warp::path(SERVER_BASE_PATH))
        .and(
            certificate_routes::routes(&state)
                .or(artifact_routes::cardano_database::routes(&state))
                .or(artifact_routes::mithril_stake_distribution::routes(&state))
                .or(artifact_routes::cardano_stake_distribution::routes(&state))
                .or(artifact_routes::cardano_transaction::routes(&state))
                .or(artifact_routes::cardano_blocks_transactions::routes(&state))
                .or(proof_routes::routes(&state))
                .or(signer_routes::routes(&state))
                .or(signatures_routes::routes(&state))
                .or(epoch_routes::routes(&state))
                .or(protocol_configuration_routes::routes(&state))
                .or(statistics_routes::routes(&state))
                .or(root_routes::routes(&state))
                .or(status::routes(&state)),
        )
        .recover(handle_custom)
        .and(middlewares::with_api_version_provider(&state))
        .map(|reply, api_version_provider: Arc<APIVersionProvider>| {
            warp::reply::with_header(
                reply,
                MITHRIL_API_VERSION_HEADER,
                &api_version_provider.compute_current_version().unwrap().to_string(),
            )
        })
        .with(cors)
        .with(middlewares::log_route_call(&state))
}

pub async fn handle_custom(reject: Rejection) -> Result<impl Reply, Rejection> {
    if reject.is_not_found() {
        Ok(StatusCode::NOT_FOUND)
    } else {
        Err(reject)
    }
}

#[cfg(test)]
mod tests {
    use warp::test::RequestBuilder;

    use mithril_common::{MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER};

    use crate::initialize_dependencies;

    use super::*;

    #[tokio::test]
    async fn test_404_response_should_include_status_code_and_headers() {
        let container = Arc::new(initialize_dependencies!().await);
        let state = RouterState::new_with_dummy_config(container);
        let routes = routes(Arc::new(state));

        let response = warp::test::request()
            .path("/aggregator/a-route-that-does-not-exist")
            // We need to set the Origin header to trigger the CORS middleware
            .header("Origin", "http://localhost")
            .reply(&routes)
            .await;
        let response_headers = response.headers();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response_headers.get(MITHRIL_API_VERSION_HEADER).is_some(),
            "API version header should be present, headers: {response_headers:?}",
        );
        assert!(
            response_headers.get("access-control-allow-origin").is_some(),
            "CORS headers should be present, headers: {response_headers:?}",
        );
    }

    #[tokio::test]
    async fn test_authorized_request_headers() {
        fn request_with_access_control_request_headers(headers: String) -> RequestBuilder {
            warp::test::request()
                .method("OPTIONS")
                .path("/aggregator")
                // We need to set the Origin header to trigger the CORS middleware
                .header("Origin", "http://localhost")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", headers)
        }

        let container = Arc::new(initialize_dependencies!().await);
        let state = RouterState::new_with_dummy_config(container);
        let routes = routes(Arc::new(state));

        assert!(
            !request_with_access_control_request_headers("unauthorized_header".to_string())
                .reply(&routes)
                .await
                .status()
                .is_success()
        );

        assert!(request_with_access_control_request_headers(format!(
            "{MITHRIL_API_VERSION_HEADER},{MITHRIL_ORIGIN_TAG_HEADER},{MITHRIL_CLIENT_TYPE_HEADER}"
        ))
        .reply(&routes)
        .await
        .status()
        .is_success());
    }
}
