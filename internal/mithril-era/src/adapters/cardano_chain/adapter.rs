use async_trait::async_trait;
use slog::{Logger, info, warn};
use std::sync::Arc;
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::{ChainAddress, TxDatumFieldTypeName};
use mithril_common::StdResult;
use mithril_common::crypto_helper::EraMarkersVerifierVerificationKey;
use mithril_common::logging::LoggerExtensions;

use crate::{EraMarker, EraReaderAdapter};

use super::payload::EraMarkersPayload;

/// [CardanoChainAdapter] related errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CardanoChainAdapterError {
    /// Error raised when different era markers are signed with the same highest sequence number
    #[error(
        "different era markers share the highest sequence number '{0}': era markers with a higher sequence number must be stored"
    )]
    ConflictingEraMarkers(u64),
}

/// Cardano Chain adapter retrieves era markers on chain
///
/// Among the datums that hold an [EraMarkersPayload] with a valid signature, the era markers
/// with the highest sequence number are selected, whatever the order of the datums.
///
/// The legacy era markers (without sequence number) are ignored: they are only read by the
/// nodes that can not read the sequence number yet.
///
/// Different era markers that share the highest sequence number are not expected: the read then
/// fails until era markers with a higher sequence number are stored.
pub struct CardanoChainAdapter {
    address: ChainAddress,
    chain_observer: Arc<dyn ChainObserver>,
    verification_key: EraMarkersVerifierVerificationKey,
    logger: Logger,
}

impl CardanoChainAdapter {
    /// CardanoChainAdapter factory
    pub fn new(
        address: ChainAddress,
        chain_observer: Arc<dyn ChainObserver>,
        verification_key: EraMarkersVerifierVerificationKey,
        logger: Logger,
    ) -> Self {
        Self {
            address,
            chain_observer,
            verification_key,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Decode the encoded payload of a datum and keep it if its signature is valid
    fn verified_payload(&self, payload_json_hex: &str) -> Option<EraMarkersPayload> {
        EraMarkersPayload::from_json_hex(payload_json_hex)
            .ok()
            .filter(|payload| payload.verify_signature(self.verification_key).is_ok())
    }
}

#[async_trait]
impl EraReaderAdapter for CardanoChainAdapter {
    async fn read(&self) -> StdResult<Vec<EraMarker>> {
        let tx_datums = self.chain_observer.get_current_datums(&self.address).await?;
        let datums_count = tx_datums.len();
        let verified_payloads = tx_datums
            .into_iter()
            .filter_map(|datum| datum.get_fields_by_type(&TxDatumFieldTypeName::Bytes).ok())
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field_value| field_value.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
                    .join("")
            })
            .filter_map(|payload_json_hex| self.verified_payload(&payload_json_hex))
            .collect::<Vec<EraMarkersPayload>>();
        let valid_datums_count = verified_payloads.len();
        let selected_sequence_number =
            verified_payloads.iter().map(|payload| payload.sequence_number).max();
        let selected_payloads = verified_payloads
            .iter()
            .filter(|payload| Some(payload.sequence_number) == selected_sequence_number)
            .collect::<Vec<&EraMarkersPayload>>();
        let selected_markers = selected_payloads
            .first()
            .map(|payload| payload.markers.clone())
            .unwrap_or_default();
        if let Some(sequence_number) = selected_sequence_number
            && selected_payloads
                .iter()
                .any(|payload| payload.markers != selected_markers)
        {
            return Err(CardanoChainAdapterError::ConflictingEraMarkers(sequence_number).into());
        }
        if datums_count > 0 && valid_datums_count == 0 {
            warn!(
                self.logger, "No era markers datum with a sequence number and a valid signature is stored, no era markers are read";
                "address" => &self.address,
                "datums_count" => datums_count
            );
        }
        if valid_datums_count > 1 {
            warn!(
                self.logger, "Several era markers datums with a valid signature coexist, the era markers with the highest sequence number are selected";
                "address" => &self.address,
                "datums_count" => datums_count,
                "valid_datums_count" => valid_datums_count,
                "selected_sequence_number" => selected_sequence_number.unwrap_or_default(),
                "datums_with_selected_sequence_number_count" => selected_payloads.len(),
                "selected_markers" => ?selected_markers
            );
        }
        if let Some(sequence_number) = selected_sequence_number {
            info!(
                self.logger, "Era markers read with the highest sequence number";
                "address" => &self.address,
                "selected_sequence_number" => sequence_number,
                "selected_markers" => ?selected_markers
            );
        }

        Ok(selected_markers)
    }
}

#[cfg(test)]
mod test {
    use mithril_cardano_node_chain::entities::{TxDatum, TxDatumBuilder, TxDatumFieldValue};
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::crypto_helper::EraMarkersSigner;
    use mithril_common::test::logging::MemoryDrainForTestInspector;

    use crate::test_tools::TestLogger;

    use super::super::test_fixtures::{
        legacy_payload, pythagoras_markers, sequenced_payload, thales_markers,
    };
    use super::*;

    fn tx_datum(payload_json_hex: String) -> TxDatum {
        TxDatumBuilder::new()
            .add_field(TxDatumFieldValue::Bytes(payload_json_hex))
            .build()
            .unwrap()
    }

    fn sequenced_datum(markers: &[EraMarker], sequence_number: u64) -> TxDatum {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();

        tx_datum(
            sequenced_payload(markers, sequence_number, &era_markers_signer)
                .to_json_hex()
                .unwrap(),
        )
    }

    fn sequenced_datum_signed_with_another_key(
        markers: &[EraMarker],
        sequence_number: u64,
    ) -> TxDatum {
        let era_markers_signer = EraMarkersSigner::create_non_deterministic_signer();

        tx_datum(
            sequenced_payload(markers, sequence_number, &era_markers_signer)
                .to_json_hex()
                .unwrap(),
        )
    }

    fn unsigned_sequenced_datum(markers: &[EraMarker], sequence_number: u64) -> TxDatum {
        tx_datum(
            EraMarkersPayload {
                markers: markers.to_vec(),
                sequence_number,
                signature: None,
            }
            .to_json_hex()
            .unwrap(),
        )
    }

    fn legacy_datum(markers: &[EraMarker]) -> TxDatum {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();

        tx_datum(legacy_payload(markers, &era_markers_signer).to_json_hex().unwrap())
    }

    #[allow(deprecated)]
    fn legacy_datum_with_an_added_sequence_number(
        markers: &[EraMarker],
        sequence_number: u64,
    ) -> TxDatum {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let legacy_payload = legacy_payload(markers, &era_markers_signer);

        tx_datum(
            EraMarkersPayload {
                markers: legacy_payload.markers,
                sequence_number,
                signature: legacy_payload.signature,
            }
            .to_json_hex()
            .unwrap(),
        )
    }

    async fn try_read_markers(
        tx_datums: Vec<TxDatum>,
        logger: Logger,
    ) -> StdResult<Vec<EraMarker>> {
        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(tx_datums).await;
        let cardano_chain_adapter = CardanoChainAdapter::new(
            "addr_test_123456".to_string(),
            Arc::new(chain_observer),
            EraMarkersSigner::create_deterministic_signer()
                .create_verifier()
                .to_verification_key(),
            logger,
        );

        cardano_chain_adapter.read().await
    }

    async fn read_markers(tx_datums: Vec<TxDatum>, logger: Logger) -> Vec<EraMarker> {
        try_read_markers(tx_datums, logger)
            .await
            .expect("CardanoChainAdapter read should not fail")
    }

    async fn read_error(tx_datums: Vec<TxDatum>) -> CardanoChainAdapterError {
        try_read_markers(tx_datums, TestLogger::stdout())
            .await
            .expect_err("CardanoChainAdapter read should fail")
            .downcast::<CardanoChainAdapterError>()
            .expect("the error should be a CardanoChainAdapterError")
    }

    async fn read_markers_in_both_datum_orders(
        first_datum: TxDatum,
        second_datum: TxDatum,
    ) -> (Vec<EraMarker>, Vec<EraMarker>) {
        (
            read_markers(
                vec![first_datum.clone(), second_datum.clone()],
                TestLogger::stdout(),
            )
            .await,
            read_markers(vec![second_datum, first_datum], TestLogger::stdout()).await,
        )
    }

    #[tokio::test]
    async fn read_selects_the_markers_of_a_single_valid_datum() {
        let expected_markers = pythagoras_markers(Some(2));

        let markers = read_markers(
            vec![sequenced_datum(&expected_markers, 1)],
            TestLogger::stdout(),
        )
        .await;

        assert_eq!(expected_markers, markers);
    }

    #[tokio::test]
    async fn read_selects_the_highest_sequence_number_over_a_later_activation_epoch() {
        let superseded_markers = pythagoras_markers(Some(10));
        let rescheduled_markers = pythagoras_markers(Some(8));

        let (markers_with_superseded_datum_first, markers_with_rescheduled_datum_first) =
            read_markers_in_both_datum_orders(
                sequenced_datum(&superseded_markers, 1),
                sequenced_datum(&rescheduled_markers, 2),
            )
            .await;

        assert_eq!(rescheduled_markers, markers_with_superseded_datum_first);
        assert_eq!(rescheduled_markers, markers_with_rescheduled_datum_first);
    }

    #[tokio::test]
    async fn read_selects_a_cancellation_with_a_higher_sequence_number() {
        let superseded_markers = pythagoras_markers(Some(10));
        let cancellation_markers = pythagoras_markers(None);

        let (markers_with_superseded_datum_first, markers_with_cancellation_datum_first) =
            read_markers_in_both_datum_orders(
                sequenced_datum(&superseded_markers, 1),
                sequenced_datum(&cancellation_markers, 2),
            )
            .await;

        assert_eq!(cancellation_markers, markers_with_superseded_datum_first);
        assert_eq!(cancellation_markers, markers_with_cancellation_datum_first);
    }

    #[tokio::test]
    async fn read_selects_the_highest_sequence_number_among_more_than_two_valid_datums() {
        let most_recent_markers = pythagoras_markers(Some(3));

        let markers = read_markers(
            vec![
                sequenced_datum(&thales_markers(), 1),
                sequenced_datum(&most_recent_markers, 3),
                sequenced_datum(&pythagoras_markers(Some(5)), 2),
            ],
            TestLogger::stdout(),
        )
        .await;

        assert_eq!(most_recent_markers, markers);
    }

    #[tokio::test]
    async fn read_selects_the_highest_supported_sequence_number() {
        let most_recent_markers = pythagoras_markers(Some(2));

        let (markers_with_lowest_datum_first, markers_with_highest_datum_first) =
            read_markers_in_both_datum_orders(
                sequenced_datum(&thales_markers(), 0),
                sequenced_datum(&most_recent_markers, u64::MAX),
            )
            .await;

        assert_eq!(most_recent_markers, markers_with_lowest_datum_first);
        assert_eq!(most_recent_markers, markers_with_highest_datum_first);
    }

    #[tokio::test]
    async fn read_fails_when_different_markers_share_the_highest_sequence_number() {
        let thales_datum = sequenced_datum(&thales_markers(), 2);
        let pythagoras_datum = sequenced_datum(&pythagoras_markers(Some(2)), 2);

        let error_with_thales_datum_first =
            read_error(vec![thales_datum.clone(), pythagoras_datum.clone()]).await;
        let error_with_pythagoras_datum_first =
            read_error(vec![pythagoras_datum, thales_datum]).await;

        assert_eq!(
            CardanoChainAdapterError::ConflictingEraMarkers(2),
            error_with_thales_datum_first
        );
        assert_eq!(
            CardanoChainAdapterError::ConflictingEraMarkers(2),
            error_with_pythagoras_datum_first
        );
    }

    #[tokio::test]
    async fn read_selects_the_markers_stored_twice_with_the_highest_sequence_number() {
        let expected_markers = pythagoras_markers(Some(2));

        let markers = read_markers(
            vec![
                sequenced_datum(&expected_markers, 2),
                sequenced_datum(&expected_markers, 2),
            ],
            TestLogger::stdout(),
        )
        .await;

        assert_eq!(expected_markers, markers);
    }

    #[tokio::test]
    async fn read_selects_the_highest_sequence_number_when_different_markers_share_a_lower_one() {
        let expected_markers = pythagoras_markers(Some(2));

        let markers = read_markers(
            vec![
                sequenced_datum(&thales_markers(), 1),
                sequenced_datum(&pythagoras_markers(None), 1),
                sequenced_datum(&expected_markers, 2),
            ],
            TestLogger::stdout(),
        )
        .await;

        assert_eq!(expected_markers, markers);
    }

    #[tokio::test]
    async fn read_ignores_legacy_markers_next_to_markers_with_a_sequence_number() {
        let sequenced_markers = thales_markers();

        let (markers_with_legacy_datum_first, markers_with_sequenced_datum_first) =
            read_markers_in_both_datum_orders(
                legacy_datum(&pythagoras_markers(Some(10))),
                sequenced_datum(&sequenced_markers, 0),
            )
            .await;

        assert_eq!(sequenced_markers, markers_with_legacy_datum_first);
        assert_eq!(sequenced_markers, markers_with_sequenced_datum_first);
    }

    #[tokio::test]
    async fn read_returns_no_markers_when_only_legacy_markers_exist() {
        let markers =
            read_markers(vec![legacy_datum(&thales_markers())], TestLogger::stdout()).await;

        assert_eq!(Vec::<EraMarker>::new(), markers);
    }

    #[tokio::test]
    async fn read_ignores_legacy_markers_with_an_added_sequence_number() {
        let sequenced_markers = thales_markers();

        let (markers_with_tampered_datum_first, markers_with_sequenced_datum_first) =
            read_markers_in_both_datum_orders(
                legacy_datum_with_an_added_sequence_number(&pythagoras_markers(Some(10)), 99),
                sequenced_datum(&sequenced_markers, 1),
            )
            .await;

        assert_eq!(sequenced_markers, markers_with_tampered_datum_first);
        assert_eq!(sequenced_markers, markers_with_sequenced_datum_first);
    }

    #[tokio::test]
    async fn read_discards_a_higher_sequence_number_signed_with_another_key() {
        let genuine_markers = thales_markers();

        let (markers_with_genuine_datum_first, markers_with_forged_datum_first) =
            read_markers_in_both_datum_orders(
                sequenced_datum(&genuine_markers, 1),
                sequenced_datum_signed_with_another_key(&pythagoras_markers(Some(2)), 2),
            )
            .await;

        assert_eq!(genuine_markers, markers_with_genuine_datum_first);
        assert_eq!(genuine_markers, markers_with_forged_datum_first);
    }

    #[tokio::test]
    async fn read_discards_a_higher_sequence_number_without_signature() {
        let genuine_markers = thales_markers();

        let (markers_with_genuine_datum_first, markers_with_unsigned_datum_first) =
            read_markers_in_both_datum_orders(
                sequenced_datum(&genuine_markers, 1),
                unsigned_sequenced_datum(&pythagoras_markers(Some(2)), 2),
            )
            .await;

        assert_eq!(genuine_markers, markers_with_genuine_datum_first);
        assert_eq!(genuine_markers, markers_with_unsigned_datum_first);
    }

    #[tokio::test]
    async fn read_ignores_a_datum_that_is_not_an_era_markers_payload() {
        let expected_markers = pythagoras_markers(Some(2));
        let tx_datums = vec![
            sequenced_datum(&expected_markers, 1),
            TxDatum("not_valid_datum".to_string()),
        ];

        let markers = read_markers(tx_datums, TestLogger::stdout()).await;

        assert_eq!(expected_markers, markers);
    }

    mod logs {
        use super::*;

        const ERA_MARKERS_READ_LOG: &str = "Era markers read with the highest sequence number";
        const NO_VALID_DATUM_WARNING: &str =
            "No era markers datum with a sequence number and a valid signature is stored";
        const SEVERAL_VALID_DATUMS_WARNING: &str =
            "Several era markers datums with a valid signature coexist";

        async fn read_markers_and_inspect_logs(
            tx_datums: Vec<TxDatum>,
        ) -> (Vec<EraMarker>, MemoryDrainForTestInspector) {
            let (logger, log_inspector) = TestLogger::memory();
            let markers = read_markers(tx_datums, logger).await;

            (markers, log_inspector)
        }

        #[tokio::test]
        async fn read_warns_with_the_datums_counts_and_the_selection_when_several_valid_datums_coexist()
         {
            let (_, log_inspector) = read_markers_and_inspect_logs(vec![
                sequenced_datum(&thales_markers(), 1),
                sequenced_datum(&pythagoras_markers(Some(2)), 2),
                sequenced_datum_signed_with_another_key(&thales_markers(), 3),
            ])
            .await;

            let warnings = log_inspector.search_logs(SEVERAL_VALID_DATUMS_WARNING);
            assert_eq!(1, warnings.len(), "logs: {log_inspector}");
            assert!(warnings[0].starts_with("WARN"), "logs: {log_inspector}");
            assert!(
                warnings[0].contains(" datums_count=3")
                    && warnings[0].contains(" valid_datums_count=2"),
                "logs: {log_inspector}"
            );
            assert!(
                warnings[0].contains("selected_sequence_number=2")
                    && warnings[0].contains("selected_markers=")
                    && warnings[0].contains("pythagoras"),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_warns_with_the_count_of_datums_sharing_the_selected_sequence_number() {
            let (_, log_inspector) = read_markers_and_inspect_logs(vec![
                sequenced_datum(&thales_markers(), 1),
                sequenced_datum(&pythagoras_markers(Some(2)), 2),
                sequenced_datum(&pythagoras_markers(Some(2)), 2),
            ])
            .await;

            let warnings = log_inspector.search_logs(SEVERAL_VALID_DATUMS_WARNING);
            assert_eq!(1, warnings.len(), "logs: {log_inspector}");
            assert!(
                warnings[0].contains(" datums_with_selected_sequence_number_count=2"),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_logs_the_selected_sequence_number_and_markers() {
            let (_, log_inspector) = read_markers_and_inspect_logs(vec![sequenced_datum(
                &pythagoras_markers(Some(2)),
                3,
            )])
            .await;

            let logs = log_inspector.search_logs(ERA_MARKERS_READ_LOG);
            assert_eq!(1, logs.len(), "logs: {log_inspector}");
            assert!(logs[0].starts_with("INFO"), "logs: {log_inspector}");
            assert!(
                logs[0].contains("selected_sequence_number=3")
                    && logs[0].contains("selected_markers=")
                    && logs[0].contains("pythagoras"),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_does_not_log_a_selection_when_no_datum_is_valid() {
            let (_, log_inspector) =
                read_markers_and_inspect_logs(vec![legacy_datum(&thales_markers())]).await;

            assert!(
                !log_inspector.contains_log(ERA_MARKERS_READ_LOG),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_warns_with_the_datums_count_when_no_stored_datum_is_valid() {
            let (markers, log_inspector) = read_markers_and_inspect_logs(vec![
                legacy_datum(&thales_markers()),
                sequenced_datum_signed_with_another_key(&thales_markers(), 1),
            ])
            .await;

            assert_eq!(Vec::<EraMarker>::new(), markers);
            let warnings = log_inspector.search_logs(NO_VALID_DATUM_WARNING);
            assert_eq!(1, warnings.len(), "logs: {log_inspector}");
            assert!(warnings[0].starts_with("WARN"), "logs: {log_inspector}");
            assert!(
                warnings[0].contains(" datums_count=2"),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_does_not_warn_when_no_datum_is_stored() {
            let (markers, log_inspector) = read_markers_and_inspect_logs(vec![]).await;

            assert_eq!(Vec::<EraMarker>::new(), markers);
            assert!(
                !log_inspector.contains_log(NO_VALID_DATUM_WARNING),
                "logs: {log_inspector}"
            );
        }

        #[tokio::test]
        async fn read_does_not_warn_when_a_single_datum_is_valid_among_several() {
            let (_, log_inspector) = read_markers_and_inspect_logs(vec![
                sequenced_datum(&thales_markers(), 1),
                sequenced_datum_signed_with_another_key(&thales_markers(), 2),
                legacy_datum(&thales_markers()),
            ])
            .await;

            assert!(
                !log_inspector.contains_log(SEVERAL_VALID_DATUMS_WARNING),
                "logs: {log_inspector}"
            );
        }
    }
}
