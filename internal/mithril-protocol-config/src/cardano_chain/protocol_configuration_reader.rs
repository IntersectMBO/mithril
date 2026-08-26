//! Cardano Chain implementation to read protocol configuration markers

use anyhow::Context;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::{ChainAddress, TxDatumFieldTypeName};
use mithril_common::StdResult;
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;
use mithril_common::entities::Epoch;

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
}

impl CardanoChainProtocolConfigurationMarkersReader {
    /// CardanoChainAdapter factory
    pub fn new(
        address: ChainAddress,
        chain_observer: Arc<dyn ChainObserver>,
        verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
    ) -> Self {
        Self {
            address,
            chain_observer,
            verification_key,
        }
    }
}

#[async_trait]
impl ProtocolConfigurationMarkersReader for CardanoChainProtocolConfigurationMarkersReader {
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers> {
        let tx_datums = self.chain_observer.get_current_datums(&self.address).await?;

        let last_markers: Vec<ProtocolConfigurationMarker> = tx_datums
            .into_iter()
            .filter_map(|datum| datum.get_fields_by_type(&TxDatumFieldTypeName::Bytes).ok())
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field_value| field_value.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
                    .join("")
            })
            .filter_map(|field_value_str| {
                SignedProtocolConfigurationMarkersPayload::from_json_hex(&field_value_str).ok()
            })
            .filter_map(|signed_payload| {
                signed_payload
                    .verify_signature(self.verification_key)
                    .ok()
                    .map(|_| signed_payload.markers_payload.markers)
            })
            .next()
            .unwrap_or_default();

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
    use mithril_common::{crypto_helper::ProtocolConfigurationMarkersSigner, entities::Epoch};

    use crate::cardano_chain::{
        ProtocolConfigurationMarkersPayloadCardanoChain,
        SignedProtocolConfigurationMarkersPayloadCardanoChain,
        message::ProtocolConfigurationMarker,
    };

    use crate::test::helper::{generate_configuration, generate_configuration_message};

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
        );
        cardano_chain_reader
            .read_configuration_markers()
            .await
            .expect_err("should throw error");
    }
}
