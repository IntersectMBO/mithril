use serde::{Deserialize, Serialize};
use warp::Filter;
use warp::filters::BoxedFilter;

use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;

#[derive(Deserialize, Serialize, Debug)]
struct CardanoTransactionProofQueryParams {
    transaction_hashes: String,
}

impl CardanoTransactionProofQueryParams {
    pub fn split_transactions_hashes(&self) -> Vec<String> {
        self.transaction_hashes.split(',').map(|s| s.to_string()).collect()
    }

    pub fn sanitize(&self) -> Vec<String> {
        let mut transaction_hashes = self.split_transactions_hashes();
        transaction_hashes.sort();
        transaction_hashes.dedup();
        transaction_hashes
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct CardanoBlockProofQueryParams {
    block_hashes: String,
}

impl CardanoBlockProofQueryParams {
    pub fn split_blocks_hashes(&self) -> Vec<String> {
        self.block_hashes.split(',').map(|s| s.to_string()).collect()
    }

    pub fn sanitize(&self) -> Vec<String> {
        let mut block_hashes = self.split_blocks_hashes();
        block_hashes.sort();
        block_hashes.dedup();
        block_hashes
    }
}

pub fn routes(router_state: &RouterState) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    proof_cardano_transaction(router_state)
        .or(proof_v2_cardano_transaction(router_state))
        .or(proof_v2_cardano_block(router_state))
        .boxed()
}

/// GET /proof/cardano-transaction
fn proof_cardano_transaction(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("proof" / "cardano-transaction")
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(warp::query::<CardanoTransactionProofQueryParams>())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_signed_entity_service(router_state))
        .and(middlewares::validators::with_prover_transactions_hash_validator(router_state))
        .and(middlewares::with_legacy_prover_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::proof_cardano_transaction)
}

/// GET /proof/v2/cardano-transaction
fn proof_v2_cardano_transaction(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("proof" / "v2" / "cardano-transaction")
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(warp::query::<CardanoTransactionProofQueryParams>())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_signed_entity_service(router_state))
        .and(middlewares::validators::with_prover_transactions_hash_validator(router_state))
        .and(middlewares::with_prover_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::proof_v2_cardano_transaction)
}

/// GET /proof/v2/cardano-block
fn proof_v2_cardano_block(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("proof" / "v2" / "cardano-block")
        .and(warp::get())
        .and(middlewares::with_client_metadata(router_state))
        .and(warp::query::<CardanoBlockProofQueryParams>())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_signed_entity_service(router_state))
        .and(middlewares::validators::with_prover_block_hash_validator(
            router_state,
        ))
        .and(middlewares::with_prover_service(router_state))
        .and(middlewares::with_metrics_service(router_state))
        .and_then(handlers::proof_v2_cardano_block)
}

mod handlers {
    use slog::{Logger, debug, warn};
    use std::{convert::Infallible, sync::Arc};
    use warp::http::StatusCode;

    use mithril_common::{
        StdResult,
        entities::{
            BlockNumberOffset, CardanoBlocksTransactionsSnapshot, CardanoTransactionsSnapshot,
        },
        messages::{
            CardanoBlocksProofsMessage, CardanoTransactionsProofsMessage,
            CardanoTransactionsProofsV2Message,
        },
        signable_builder::SignedEntity,
    };

    use crate::{
        MetricsService,
        http_server::{
            routes::{middlewares::ClientMetadata, reply},
            validators::ProverHashValidator,
        },
        message_adapters::ToCardanoTransactionsProofsMessageAdapter,
        services::{LegacyProverService, ProverService, SignedEntityService},
        unwrap_to_internal_server_error,
    };

    use super::{CardanoBlockProofQueryParams, CardanoTransactionProofQueryParams};

    pub async fn proof_cardano_transaction(
        client_metadata: ClientMetadata,
        transaction_parameters: CardanoTransactionProofQueryParams,
        logger: Logger,
        signed_entity_service: Arc<dyn SignedEntityService>,
        validator: ProverHashValidator,
        prover_service: Arc<dyn LegacyProverService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_proof_cardano_transaction_total_proofs_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let transaction_hashes = transaction_parameters.split_transactions_hashes();
        debug!(
            logger, ">> proof_cardano_transaction";
            "transaction_hashes" => &transaction_parameters.transaction_hashes
        );

        if let Err(error) = validator.validate(&transaction_hashes) {
            warn!(logger, "proof_cardano_transaction::bad_request");
            return Ok(reply::bad_request(error.label, error.message));
        }

        let sanitized_hashes = transaction_parameters.sanitize();

        // Fallback to 0, it should be impossible to have more than u32::MAX transactions.
        metrics_service
            .get_proof_cardano_transaction_total_transactions_served_since_startup()
            .increment_by(
                &[
                    client_metadata.origin_tag.as_deref().unwrap_or_default(),
                    client_metadata.client_type.as_deref().unwrap_or_default(),
                ],
                sanitized_hashes.len().try_into().unwrap_or(0),
            );

        match unwrap_to_internal_server_error!(
            signed_entity_service
                .get_last_cardano_transaction_snapshot()
                .await,
            logger => "proof_cardano_transaction::error"
        ) {
            Some(signed_entity) => {
                let message = unwrap_to_internal_server_error!(
                    build_response_message(prover_service, signed_entity, sanitized_hashes).await,
                    logger => "proof_cardano_transaction"
                );
                Ok(reply::json(&message, StatusCode::OK))
            }
            None => {
                warn!(logger, "proof_cardano_transaction::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }

    pub async fn proof_v2_cardano_transaction(
        client_metadata: ClientMetadata,
        transaction_parameters: CardanoTransactionProofQueryParams,
        logger: Logger,
        signed_entity_service: Arc<dyn SignedEntityService>,
        validator: ProverHashValidator,
        prover_service: Arc<dyn ProverService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_proof_v2_cardano_transaction_total_proofs_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let transaction_hashes = transaction_parameters.split_transactions_hashes();
        debug!(
            logger, ">> proof_v2_cardano_transaction";
            "transaction_hashes" => &transaction_parameters.transaction_hashes
        );

        if let Err(error) = validator.validate(&transaction_hashes) {
            warn!(logger, "proof_v2_cardano_transaction::bad_request");
            return Ok(reply::bad_request(error.label, error.message));
        }

        let sanitized_hashes = transaction_parameters.sanitize();
        metrics_service
            .get_proof_v2_cardano_transaction_total_transactions_served_since_startup()
            .increment_by(
                &[
                    client_metadata.origin_tag.as_deref().unwrap_or_default(),
                    client_metadata.client_type.as_deref().unwrap_or_default(),
                ],
                sanitized_hashes.len().try_into().unwrap_or(0),
            );

        match unwrap_to_internal_server_error!(
            signed_entity_service
                .get_last_cardano_blocks_transactions_snapshot()
                .await,
            logger => "proof_v2_cardano_transaction::error"
        ) {
            Some(signed_entity) => {
                let message = unwrap_to_internal_server_error!(
                    build_response_message_for_v2_cardano_transaction(
                        prover_service,
                        signed_entity,
                        sanitized_hashes
                    )
                    .await,
                    logger => "proof_v2_cardano_transaction"
                );
                Ok(reply::json(&message, StatusCode::OK))
            }
            None => {
                warn!(logger, "proof_v2_cardano_transaction::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }

    pub async fn proof_v2_cardano_block(
        client_metadata: ClientMetadata,
        block_parameters: CardanoBlockProofQueryParams,
        logger: Logger,
        signed_entity_service: Arc<dyn SignedEntityService>,
        validator: ProverHashValidator,
        prover_service: Arc<dyn ProverService>,
        metrics_service: Arc<MetricsService>,
    ) -> Result<impl warp::Reply, Infallible> {
        metrics_service
            .get_proof_v2_cardano_block_total_proofs_served_since_startup()
            .increment(&[
                client_metadata.origin_tag.as_deref().unwrap_or_default(),
                client_metadata.client_type.as_deref().unwrap_or_default(),
            ]);

        let block_hashes = block_parameters.split_blocks_hashes();
        debug!(
            logger, ">> proof_v2_cardano_block";
            "block_hashes" => &block_parameters.block_hashes
        );

        if let Err(error) = validator.validate(&block_hashes) {
            warn!(logger, "proof_v2_cardano_block::bad_request");
            return Ok(reply::bad_request(error.label, error.message));
        }

        let sanitized_hashes = block_parameters.sanitize();
        metrics_service
            .get_proof_v2_cardano_block_total_blocks_served_since_startup()
            .increment_by(
                &[
                    client_metadata.origin_tag.as_deref().unwrap_or_default(),
                    client_metadata.client_type.as_deref().unwrap_or_default(),
                ],
                sanitized_hashes.len().try_into().unwrap_or(0),
            );

        match unwrap_to_internal_server_error!(
            signed_entity_service
                .get_last_cardano_blocks_transactions_snapshot()
                .await,
            logger => "proof_v2_cardano_block::error"
        ) {
            Some(signed_entity) => {
                let message = unwrap_to_internal_server_error!(
                    build_response_message_for_v2_cardano_block(
                        prover_service,
                        signed_entity,
                        sanitized_hashes
                    )
                    .await,
                    logger => "proof_v2_cardano_block"
                );
                Ok(reply::json(&message, StatusCode::OK))
            }
            None => {
                warn!(logger, "proof_v2_cardano_block::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }

    pub async fn build_response_message(
        prover_service: Arc<dyn LegacyProverService>,
        signed_entity: SignedEntity<CardanoTransactionsSnapshot>,
        transaction_hashes: Vec<String>,
    ) -> StdResult<CardanoTransactionsProofsMessage> {
        let transactions_set_proofs = prover_service
            .compute_transactions_proofs(
                signed_entity.artifact.block_number,
                transaction_hashes.as_slice(),
            )
            .await?;
        let message = ToCardanoTransactionsProofsMessageAdapter::try_adapt(
            signed_entity,
            transactions_set_proofs,
            transaction_hashes,
        )?;

        Ok(message)
    }

    async fn build_response_message_for_v2_cardano_transaction(
        prover_service: Arc<dyn ProverService>,
        signed_entity: SignedEntity<CardanoBlocksTransactionsSnapshot>,
        transaction_hashes: Vec<String>,
    ) -> StdResult<CardanoTransactionsProofsV2Message> {
        let (certified_transactions, non_certified_transactions) = match prover_service
            .compute_transactions_proofs(
                signed_entity.artifact.block_number_signed,
                &transaction_hashes,
            )
            .await?
        {
            Some(transactions_set_proof) => {
                let certified_transactions_hashes: Vec<_> =
                    transactions_set_proof.transactions_hashes().collect();
                let non_certified_transactions = transaction_hashes
                    .iter()
                    .filter(|hash| !certified_transactions_hashes.contains(hash))
                    .cloned()
                    .collect::<Vec<_>>();
                let certified_transactions = transactions_set_proof.try_into()?;

                (Some(certified_transactions), non_certified_transactions)
            }
            None => (None, transaction_hashes),
        };

        let security_parameter = BlockNumberOffset::from(
            signed_entity.artifact.block_number_tip - signed_entity.artifact.block_number_signed,
        );

        Ok(CardanoTransactionsProofsV2Message::new(
            &signed_entity.certificate_id,
            certified_transactions,
            non_certified_transactions,
            signed_entity.artifact.block_number_signed,
            security_parameter,
        ))
    }

    async fn build_response_message_for_v2_cardano_block(
        prover_service: Arc<dyn ProverService>,
        signed_entity: SignedEntity<CardanoBlocksTransactionsSnapshot>,
        block_hashes: Vec<String>,
    ) -> StdResult<CardanoBlocksProofsMessage> {
        let (certified_blocks, non_certified_blocks) = match prover_service
            .compute_blocks_proofs(signed_entity.artifact.block_number_signed, &block_hashes)
            .await?
        {
            Some(blocks_set_proofs) => {
                let certified_blocks_hashes: Vec<_> = blocks_set_proofs.blocks_hashes().collect();
                let non_certified_blocks = block_hashes
                    .iter()
                    .filter(|hash| !certified_blocks_hashes.contains(hash))
                    .cloned()
                    .collect::<Vec<_>>();
                let certified_blocks = blocks_set_proofs.try_into()?;

                (Some(certified_blocks), non_certified_blocks)
            }
            None => (None, block_hashes),
        };

        let security_parameter = BlockNumberOffset::from(
            signed_entity.artifact.block_number_tip - signed_entity.artifact.block_number_signed,
        );

        Ok(CardanoBlocksProofsMessage::new(
            &signed_entity.certificate_id,
            certified_blocks,
            non_certified_blocks,
            signed_entity.artifact.block_number_signed,
            security_parameter,
        ))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use serde_json::Value::Null;
    use std::sync::Arc;
    use std::vec;
    use warp::{
        http::{Method, StatusCode},
        test::request,
    };

    use mithril_api_spec::APISpec;
    use mithril_common::{
        MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER,
        entities::{
            BlockNumber, CardanoTransactionsSetProof, CardanoTransactionsSnapshot, MkSetProof,
        },
        signable_builder::SignedEntity,
        test::{
            assert_equivalent,
            double::{Dummy, fake_data},
        },
    };

    use crate::services::{MockLegacyProverService, MockProverService};
    use crate::{initialize_dependencies, services::MockSignedEntityService};

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
    async fn build_response_message_return_latest_block_number_from_artifact_beacon() {
        // Arrange
        let mut mock_prover_service = MockLegacyProverService::new();
        mock_prover_service
            .expect_compute_transactions_proofs()
            .returning(|_, _| Ok(vec![CardanoTransactionsSetProof::dummy()]));

        let cardano_transactions_snapshot =
            CardanoTransactionsSnapshot::new(String::new(), BlockNumber(2309));

        let signed_entity = SignedEntity::<CardanoTransactionsSnapshot> {
            artifact: cardano_transactions_snapshot,
            ..Dummy::dummy()
        };

        // Action
        let transaction_hashes = vec![];
        let message = handlers::build_response_message(
            Arc::new(mock_prover_service),
            signed_entity,
            transaction_hashes,
        )
        .await
        .unwrap();

        // Assert
        assert_eq!(message.latest_block_number, 2309)
    }

    #[tokio::test]
    async fn test_proof_cardano_transaction_increments_proofs_metrics() {
        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_proofs_counter_value = dependency_manager
            .metrics_service
            .get_proof_cardano_transaction_total_proofs_served_since_startup()
            .get(&["TEST", "CLI"]);
        let initial_transactions_counter_value = dependency_manager
            .metrics_service
            .get_proof_cardano_transaction_total_transactions_served_since_startup()
            .get(&["TEST", "CLI"]);

        request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1],
                fake_data::transaction_hashes()[2]
            ))
            .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
            .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
            .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                dependency_manager.clone(),
                &["TEST"],
            )))
            .await;

        assert_eq!(
            initial_proofs_counter_value + 1,
            dependency_manager
                .metrics_service
                .get_proof_cardano_transaction_total_proofs_served_since_startup()
                .get(&["TEST", "CLI"])
        );
        assert_eq!(
            initial_transactions_counter_value + 3,
            dependency_manager
                .metrics_service
                .get_proof_cardano_transaction_total_transactions_served_since_startup()
                .get(&["TEST", "CLI"])
        );
    }

    #[tokio::test]
    async fn test_proof_v2_cardano_transaction_increments_proofs_metrics() {
        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_proofs_counter_value = dependency_manager
            .metrics_service
            .get_proof_v2_cardano_transaction_total_proofs_served_since_startup()
            .get(&["TEST", "CLI"]);
        let initial_transactions_counter_value = dependency_manager
            .metrics_service
            .get_proof_v2_cardano_transaction_total_transactions_served_since_startup()
            .get(&["TEST", "CLI"]);

        request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1],
                fake_data::transaction_hashes()[2]
            ))
            .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
            .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
            .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                dependency_manager.clone(),
                &["TEST"],
            )))
            .await;

        assert_eq!(
            initial_proofs_counter_value + 1,
            dependency_manager
                .metrics_service
                .get_proof_v2_cardano_transaction_total_proofs_served_since_startup()
                .get(&["TEST", "CLI"])
        );
        assert_eq!(
            initial_transactions_counter_value + 3,
            dependency_manager
                .metrics_service
                .get_proof_v2_cardano_transaction_total_transactions_served_since_startup()
                .get(&["TEST", "CLI"])
        );
    }

    #[tokio::test]
    async fn test_proof_v2_cardano_block_increments_proofs_metrics() {
        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";
        let dependency_manager = Arc::new(initialize_dependencies!().await);
        let initial_proofs_counter_value = dependency_manager
            .metrics_service
            .get_proof_v2_cardano_block_total_proofs_served_since_startup()
            .get(&["TEST", "CLI"]);
        let initial_blocks_counter_value = dependency_manager
            .metrics_service
            .get_proof_v2_cardano_block_total_blocks_served_since_startup()
            .get(&["TEST", "CLI"]);
        let block_hash_1 = fake_data::block_hashes()[0];
        let block_hash_2 = fake_data::block_hashes()[1];
        let block_hash_3 = fake_data::block_hashes()[2];

        request()
            .method(method)
            .path(&format!(
                "{path}?block_hashes={},{},{}",
                block_hash_1, block_hash_2, block_hash_3
            ))
            .header(MITHRIL_ORIGIN_TAG_HEADER, "TEST")
            .header(MITHRIL_CLIENT_TYPE_HEADER, "CLI")
            .reply(&setup_router(RouterState::new_with_origin_tag_white_list(
                dependency_manager.clone(),
                &["TEST"],
            )))
            .await;

        assert_eq!(
            initial_proofs_counter_value + 1,
            dependency_manager
                .metrics_service
                .get_proof_v2_cardano_block_total_proofs_served_since_startup()
                .get(&["TEST", "CLI"])
        );
        assert_eq!(
            initial_blocks_counter_value + 3,
            dependency_manager
                .metrics_service
                .get_proof_v2_cardano_block_total_blocks_served_since_startup()
                .get(&["TEST", "CLI"])
        );
    }

    #[tokio::test]
    async fn proof_cardano_transaction_ok() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        mock_signed_entity_service
            .expect_get_last_cardano_transaction_snapshot()
            .returning(|| Ok(Some(SignedEntity::<CardanoTransactionsSnapshot>::dummy())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let mut mock_prover_service = MockLegacyProverService::new();
        mock_prover_service
            .expect_compute_transactions_proofs()
            .returning(|_, _| Ok(vec![CardanoTransactionsSetProof::dummy()]));
        dependency_manager.legacy_prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_v2_cardano_transaction_ok_some_proof() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        let signed_entity = SignedEntity::dummy();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(move || Ok(Some(signed_entity.clone())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let mut mock_prover_service = MockProverService::new();
        mock_prover_service
            .expect_compute_transactions_proofs()
            .returning(|_, _| Ok(Some(MkSetProof::dummy())));
        dependency_manager.prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_v2_cardano_transaction_ok_no_proof() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        let signed_entity = SignedEntity::dummy();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(move || Ok(Some(signed_entity.clone())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let mut mock_prover_service = MockProverService::new();
        mock_prover_service
            .expect_compute_transactions_proofs()
            .returning(|_, _| Ok(None));
        dependency_manager.prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={}",
                fake_data::transaction_hashes()[0],
            ))
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
    async fn proof_v2_cardano_block_ok_some_proof() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        let signed_entity = SignedEntity::dummy();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(move || Ok(Some(signed_entity.clone())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let block_hash = fake_data::block_hashes()[0].to_string();
        let mut mock_prover_service = MockProverService::new();
        mock_prover_service
            .expect_compute_blocks_proofs()
            .returning(|_, _| Ok(Some(MkSetProof::dummy())));
        dependency_manager.prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";

        let response = request()
            .method(method)
            .path(&format!("{path}?block_hashes={block_hash}"))
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
    async fn proof_v2_cardano_block_ok_no_proof() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        let signed_entity = SignedEntity::dummy();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(move || Ok(Some(signed_entity.clone())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let block_hash = fake_data::block_hashes()[0].to_string();
        let mut mock_prover_service = MockProverService::new();
        mock_prover_service
            .expect_compute_blocks_proofs()
            .returning(|_, _| Ok(None));
        dependency_manager.prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";

        let response = request()
            .method(method)
            .path(&format!("{path}?block_hashes={block_hash}"))
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
    async fn proof_v2_cardano_transaction_not_found() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_v2_cardano_transaction_ko() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(|| Err(anyhow!("Error")));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_v2_cardano_transaction_return_bad_request_with_invalid_hashes() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes=invalid%3A%2F%2Fid,,tx-456"
            ))
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
            &StatusCode::BAD_REQUEST,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn proof_v2_cardano_block_not_found() {
        let dependency_manager = initialize_dependencies!().await;
        let block_hash = fake_data::block_hashes()[0];

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";

        let response = request()
            .method(method)
            .path(&format!("{path}?block_hashes={block_hash}"))
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
    async fn proof_v2_cardano_block_ko() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        mock_signed_entity_service
            .expect_get_last_cardano_blocks_transactions_snapshot()
            .returning(|| Err(anyhow!("Error")));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);
        let block_hash = fake_data::block_hashes()[0];

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";

        let response = request()
            .method(method)
            .path(&format!("{path}?block_hashes={block_hash}"))
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
    async fn proof_v2_cardano_block_return_bad_request_with_invalid_hashes() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/proof/v2/cardano-block";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?block_hashes=invalid%3A%2F%2Fid,,block-456"
            ))
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
            &StatusCode::BAD_REQUEST,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn proof_cardano_transaction_not_found() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_cardano_transaction_ko() {
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        mock_signed_entity_service
            .expect_get_last_cardano_transaction_snapshot()
            .returning(|| Err(anyhow!("Error")));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes={},{}",
                fake_data::transaction_hashes()[0],
                fake_data::transaction_hashes()[1]
            ))
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
    async fn proof_cardano_transaction_return_bad_request_with_invalid_hashes() {
        let dependency_manager = initialize_dependencies!().await;

        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!(
                "{path}?transaction_hashes=invalid%3A%2F%2Fid,,tx-456"
            ))
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
            &StatusCode::BAD_REQUEST,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn proof_cardano_transaction_route_deduplicate_hashes() {
        let tx = fake_data::transaction_hashes()[0].to_string();
        let mut dependency_manager = initialize_dependencies!().await;
        let mut mock_signed_entity_service = MockSignedEntityService::new();
        mock_signed_entity_service
            .expect_get_last_cardano_transaction_snapshot()
            .returning(|| Ok(Some(SignedEntity::<CardanoTransactionsSnapshot>::dummy())));
        dependency_manager.signed_entity_service = Arc::new(mock_signed_entity_service);

        let mut mock_prover_service = MockLegacyProverService::new();
        let txs_expected = vec![tx.clone()];
        mock_prover_service
            .expect_compute_transactions_proofs()
            .withf(move |_, transaction_hashes| transaction_hashes == txs_expected)
            .returning(|_, _| Ok(vec![CardanoTransactionsSetProof::dummy()]));
        dependency_manager.legacy_prover_service = Arc::new(mock_prover_service);

        let method = Method::GET.as_str();
        let path = "/proof/cardano-transaction";

        let response = request()
            .method(method)
            .path(&format!("{path}?transaction_hashes={tx},{tx}",))
            .reply(&setup_router(RouterState::new_with_dummy_config(Arc::new(
                dependency_manager,
            ))))
            .await;

        assert_eq!(StatusCode::OK, response.status());
    }

    #[test]
    fn sanitize_cardano_transaction_proof_query_params_remove_duplicate() {
        let tx1 = fake_data::transaction_hashes()[0].to_string();
        let tx2 = fake_data::transaction_hashes()[1].to_string();

        // We are testing on an unordered list of transaction hashes
        // as some rust dedup methods only remove consecutive duplicates
        let params = CardanoTransactionProofQueryParams {
            transaction_hashes: format!("{tx1},{tx2},{tx2},{tx1},{tx2}",),
        };

        assert_equivalent!(params.sanitize(), vec![tx1, tx2]);
    }
}
