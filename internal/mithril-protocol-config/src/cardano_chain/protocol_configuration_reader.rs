//! Cardano Chain implementation to read protocol configuration markers

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug, info, warn};
use std::collections::BTreeMap;
use std::sync::Arc;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::{ChainAddress, TxDatum, TxDatumFieldTypeName};
use mithril_common::StdResult;
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;
use mithril_common::entities::Epoch;
use mithril_common::logging::LoggerExtensions;

use crate::cardano_chain::message::{
    ProtocolConfigurationForEpochMessage, ProtocolConfigurationMarker,
};
use crate::cardano_chain::payload::SignedProtocolConfigurationMarkersPayload;
use crate::interface::ProtocolConfigurationMarkersReader;
use crate::model::{ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch};

/// Cardano Chain reader retrieves protocol configuration markers on chain
pub struct CardanoChainProtocolConfigurationMarkersReader {
    address: ChainAddress,
    chain_observer: Arc<dyn ChainObserver>,
    verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
    logger: Logger,
}

impl CardanoChainProtocolConfigurationMarkersReader {
    /// CardanoChainAdapter factory
    pub fn new(
        address: ChainAddress,
        chain_observer: Arc<dyn ChainObserver>,
        verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
        logger: Logger,
    ) -> Self {
        Self {
            address,
            chain_observer,
            verification_key,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Decode the signed markers payload held by the bytes fields of a datum.
    fn decode_signed_payload(
        tx_datum: &TxDatum,
    ) -> StdResult<SignedProtocolConfigurationMarkersPayload> {
        let payload = tx_datum
            .get_fields_by_type(&TxDatumFieldTypeName::Bytes)?
            .iter()
            .filter_map(|field_value| field_value.as_str().map(|s| s.to_string()))
            .collect::<Vec<String>>()
            .join("");

        SignedProtocolConfigurationMarkersPayload::from_json_hex(&payload)
    }
}

#[async_trait]
impl ProtocolConfigurationMarkersReader for CardanoChainProtocolConfigurationMarkersReader {
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers> {
        let tx_datums = self.chain_observer.get_current_datums(&self.address).await?;
        info!(
            self.logger, "Read protocol configuration markers datums";
            "address" => &self.address, "datums_count" => tx_datums.len()
        );

        let mut verified_markers = Vec::new();
        let mut invalid_signature_datums_count = 0;
        let mut undecodable_datums_count = 0;
        for tx_datum in tx_datums {
            match Self::decode_signed_payload(&tx_datum) {
                Ok(signed_payload) => {
                    match signed_payload.verify_signature(self.verification_key) {
                        Ok(()) => verified_markers.push(signed_payload.markers_payload.markers),
                        Err(error) => {
                            debug!(
                                self.logger, "Discarded protocol configuration markers datum with an invalid signature";
                                "error" => ?error
                            );
                            invalid_signature_datums_count += 1;
                        }
                    }
                }
                Err(error) => {
                    debug!(
                        self.logger, "Discarded undecodable protocol configuration markers datum";
                        "error" => ?error
                    );
                    undecodable_datums_count += 1;
                }
            }
        }
        if invalid_signature_datums_count > 0 || undecodable_datums_count > 0 {
            warn!(
                self.logger, "Discarded protocol configuration markers datums with an invalid signature or an undecodable payload";
                "address" => &self.address,
                "invalid_signature_datums_count" => invalid_signature_datums_count,
                "undecodable_datums_count" => undecodable_datums_count
            );
        }
        let last_markers: Vec<ProtocolConfigurationMarker> =
            verified_markers.into_iter().next().unwrap_or_default();

        let mut markers_map: BTreeMap<Epoch, ProtocolConfigurationForEpoch> = BTreeMap::new();
        for marker in last_markers {
            markers_map.insert(
                marker.epoch,
                ProtocolConfigurationForEpochMessage::from_cbor_hex(&marker.configuration)
                    .with_context(|| {
                        format!(
                            "ProtocolConfigurationForEpochMessage for Epoch({}) could not be decoded from cbor hex",
                            marker.epoch,
                        )
                    })?
                    .into(),
            );
        }

        Ok(ConfigurationResolverFromMarkers::new(markers_map))
    }
}
#[cfg(test)]
mod test {
    use mithril_cardano_node_chain::{
        entities::{TxDatum, TxDatumBuilder, TxDatumFieldValue},
        test::double::FakeChainObserver,
    };
    use mithril_common::test::logging::MemoryDrainForTestInspector;
    use mithril_common::{crypto_helper::ProtocolConfigurationMarkersSigner, entities::Epoch};

    use crate::cardano_chain::{
        ProtocolConfigurationMarkersPayloadCardanoChain,
        SignedProtocolConfigurationMarkersPayloadCardanoChain,
        message::ProtocolConfigurationMarker,
    };

    use crate::test::helper::{generate_configuration, generate_configuration_message};
    use crate::test::test_tools::TestLogger;

    use super::*;

    fn dummy_tx_datums_from_markers_payload(
        payloads: Vec<SignedProtocolConfigurationMarkersPayloadCardanoChain>,
    ) -> Vec<TxDatum> {
        payloads
            .into_iter()
            .map(|payload| {
                TxDatumBuilder::new()
                    .add_field(TxDatumFieldValue::Bytes(payload.to_json_hex().unwrap()))
                    .build()
                    .unwrap()
            })
            .collect()
    }

    fn signed_markers_payload(
        signer: &ProtocolConfigurationMarkersSigner,
    ) -> SignedProtocolConfigurationMarkersPayloadCardanoChain {
        ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![ProtocolConfigurationMarker::new(
                Epoch(41),
                generate_configuration_message('A').to_cbor_hex().unwrap(),
            )],
        }
        .sign(signer)
        .unwrap()
    }

    async fn read_markers_and_inspect_logs(tx_datums: Vec<TxDatum>) -> MemoryDrainForTestInspector {
        let markers_signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(tx_datums).await;
        let (logger, log_inspector) = TestLogger::memory();
        let cardano_chain_reader = CardanoChainProtocolConfigurationMarkersReader::new(
            "addr_test_123456".to_string(),
            Arc::new(chain_observer),
            markers_signer.create_verifier().to_verification_key(),
            logger,
        );

        cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect("read_configuration_markers should not fail");

        log_inspector
    }

    #[tokio::test]
    async fn markers_with_invalid_signature_are_rejected() {
        let conf_a = generate_configuration_message('A');
        let conf_b = generate_configuration_message('B');
        let conf_c = generate_configuration_message('C');
        let conf_d = generate_configuration_message('D');

        let markers_signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let bad_markers_signer =
            ProtocolConfigurationMarkersSigner::create_non_deterministic_signer();

        let fake_address = "addr_test_123456".to_string();
        let payload_1 = ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![
                ProtocolConfigurationMarker::new(Epoch(41), conf_a.to_cbor_hex().unwrap()),
                ProtocolConfigurationMarker::new(Epoch(42), conf_b.to_cbor_hex().unwrap()),
            ],
        }
        .sign(&bad_markers_signer)
        .unwrap();

        let payload_2 = ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![
                ProtocolConfigurationMarker::new(Epoch(43), conf_c.to_cbor_hex().unwrap()),
                ProtocolConfigurationMarker::new(Epoch(44), conf_d.to_cbor_hex().unwrap()),
            ],
        }
        .sign(&markers_signer)
        .unwrap();

        let mut fake_datums = dummy_tx_datums_from_markers_payload(vec![payload_2, payload_1]);

        fake_datums.push(TxDatum("not_valid_datum".to_string()));

        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(fake_datums.clone()).await;

        let cardano_chain_reader = CardanoChainProtocolConfigurationMarkersReader::new(
            fake_address,
            Arc::new(chain_observer),
            markers_signer.create_verifier().to_verification_key(),
            TestLogger::stdout(),
        );
        let configurations = cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect("read_configuration_markers should not fail");

        assert_eq!(2, configurations.markers.len());
        assert_eq!(
            Some(&generate_configuration('C')),
            configurations.markers.get(&Epoch(43))
        );
        assert_eq!(
            Some(&generate_configuration('D')),
            configurations.markers.get(&Epoch(44))
        );
    }

    #[tokio::test]
    async fn markers_with_invalid_signature_are_logged() {
        let markers_signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let bad_markers_signer =
            ProtocolConfigurationMarkersSigner::create_non_deterministic_signer();
        let payload = ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![ProtocolConfigurationMarker::new(
                Epoch(41),
                generate_configuration_message('A').to_cbor_hex().unwrap(),
            )],
        }
        .sign(&bad_markers_signer)
        .unwrap();

        let chain_observer = FakeChainObserver::default();
        chain_observer
            .set_datums(dummy_tx_datums_from_markers_payload(vec![payload]))
            .await;

        let (logger, log_inspector) = TestLogger::memory();
        let cardano_chain_reader = CardanoChainProtocolConfigurationMarkersReader::new(
            "addr_test_123456".to_string(),
            Arc::new(chain_observer),
            markers_signer.create_verifier().to_verification_key(),
            logger,
        );
        cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect("read_configuration_markers should not fail");

        assert!(
            log_inspector
                .search_logs("WARN")
                .iter()
                .any(|log| log.contains("signature")),
            "Expected a warning about the invalid signature, logs:\n{log_inspector}"
        );
    }

    #[tokio::test]
    async fn invalid_signature_datum_after_a_valid_one_is_logged() {
        let valid_payload = signed_markers_payload(
            &ProtocolConfigurationMarkersSigner::create_deterministic_signer(),
        );
        let invalid_payload = signed_markers_payload(
            &ProtocolConfigurationMarkersSigner::create_non_deterministic_signer(),
        );

        let log_inspector =
            read_markers_and_inspect_logs(dummy_tx_datums_from_markers_payload(vec![
                valid_payload,
                invalid_payload,
            ]))
            .await;

        let warnings = log_inspector.search_logs("WARN");
        assert_eq!(
            1,
            warnings.len(),
            "Expected a single warning, logs:\n{log_inspector}"
        );
        assert!(
            warnings[0].contains("invalid_signature_datums_count=1")
                && warnings[0].contains("undecodable_datums_count=0"),
            "Expected one datum discarded for an invalid signature, logs:\n{log_inspector}"
        );
    }

    #[tokio::test]
    async fn discarded_datums_are_logged_once_per_read() {
        let bad_markers_signer =
            ProtocolConfigurationMarkersSigner::create_non_deterministic_signer();
        let invalid_payloads: Vec<_> =
            (0..3).map(|_| signed_markers_payload(&bad_markers_signer)).collect();

        let log_inspector =
            read_markers_and_inspect_logs(dummy_tx_datums_from_markers_payload(invalid_payloads))
                .await;

        let warnings = log_inspector.search_logs("WARN");
        assert_eq!(
            1,
            warnings.len(),
            "Expected a single warning for the discarded datums, logs:\n{log_inspector}"
        );
        assert!(
            warnings[0].contains("invalid_signature_datums_count=3"),
            "Expected three datums discarded for an invalid signature, logs:\n{log_inspector}"
        );
    }

    #[tokio::test]
    async fn undecodable_datum_is_logged() {
        let undecodable_datum = TxDatumBuilder::new()
            .add_field(TxDatumFieldValue::Bytes("not-a-signed-payload".to_string()))
            .build()
            .unwrap();

        let log_inspector = read_markers_and_inspect_logs(vec![undecodable_datum]).await;

        let warnings = log_inspector.search_logs("WARN");
        assert_eq!(
            1,
            warnings.len(),
            "Expected a single warning, logs:\n{log_inspector}"
        );
        assert!(
            warnings[0].contains("undecodable_datums_count=1")
                && warnings[0].contains("invalid_signature_datums_count=0"),
            "Expected one undecodable datum discarded, logs:\n{log_inspector}"
        );
    }

    #[tokio::test]
    async fn undecodable_datum_is_logged_with_its_decoding_error() {
        let undecodable_datum = TxDatumBuilder::new()
            .add_field(TxDatumFieldValue::Bytes("not-a-signed-payload".to_string()))
            .build()
            .unwrap();

        let log_inspector = read_markers_and_inspect_logs(vec![undecodable_datum]).await;

        let discarded_logs =
            log_inspector.search_logs("Discarded undecodable protocol configuration markers datum");
        assert_eq!(
            1,
            discarded_logs.len(),
            "Expected a single discarded datum log, logs:\n{log_inspector}"
        );
        assert!(
            discarded_logs[0].contains("error="),
            "Expected the decoding error in the discarded datum log, logs:\n{log_inspector}"
        );
    }

    #[tokio::test]
    async fn discarded_datums_before_the_valid_one_do_not_prevent_its_selection() {
        let markers_signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let invalid_payload = signed_markers_payload(
            &ProtocolConfigurationMarkersSigner::create_non_deterministic_signer(),
        );
        let valid_payload = ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![ProtocolConfigurationMarker::new(
                Epoch(42),
                generate_configuration_message('B').to_cbor_hex().unwrap(),
            )],
        }
        .sign(&markers_signer)
        .unwrap();
        let mut tx_datums = vec![TxDatum("not_valid_datum".to_string())];
        tx_datums.extend(dummy_tx_datums_from_markers_payload(vec![
            invalid_payload,
            valid_payload,
        ]));
        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(tx_datums).await;
        let cardano_chain_reader = CardanoChainProtocolConfigurationMarkersReader::new(
            "addr_test_123456".to_string(),
            Arc::new(chain_observer),
            markers_signer.create_verifier().to_verification_key(),
            TestLogger::stdout(),
        );

        let configurations = cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect("read_configuration_markers should not fail");

        assert_eq!(1, configurations.markers.len());
        assert_eq!(
            Some(&generate_configuration('B')),
            configurations.markers.get(&Epoch(42))
        );
    }

    #[tokio::test]
    async fn throw_error_on_invalid_cbor() {
        let markers_signer = ProtocolConfigurationMarkersSigner::create_deterministic_signer();
        let fake_address = "addr_test_123456".to_string();
        let payload_1 = ProtocolConfigurationMarkersPayloadCardanoChain {
            markers: vec![
                ProtocolConfigurationMarker::new(
                    Epoch(41),
                    generate_configuration_message('A').to_cbor_hex().unwrap(),
                ),
                ProtocolConfigurationMarker::new(Epoch(42), "unvalid_cbor_hex".to_string()),
            ],
        }
        .sign(&markers_signer)
        .unwrap();

        let fake_datums = dummy_tx_datums_from_markers_payload(vec![payload_1]);

        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(fake_datums.clone()).await;

        let cardano_chain_reader = CardanoChainProtocolConfigurationMarkersReader::new(
            fake_address,
            Arc::new(chain_observer),
            markers_signer.create_verifier().to_verification_key(),
            TestLogger::stdout(),
        );
        cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect_err("should throw error");
    }
}
