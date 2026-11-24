use async_trait::async_trait;
use std::sync::Arc;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::{ChainAddress, TxDatumFieldTypeName};
use mithril_common::StdResult;
use mithril_common::crypto_helper::EraMarkersVerifierVerificationKey;

use crate::{EraMarker, EraReaderAdapter};

use super::payload::EraMarkersPayload;

/// Cardano Chain adapter retrieves era markers on chain
pub struct CardanoChainAdapter {
    address: ChainAddress,
    chain_observer: Arc<dyn ChainObserver>,
    verification_key: EraMarkersVerifierVerificationKey,
}

impl CardanoChainAdapter {
    /// CardanoChainAdapter factory
    pub fn new(
        address: ChainAddress,
        chain_observer: Arc<dyn ChainObserver>,
        verification_key: EraMarkersVerifierVerificationKey,
    ) -> Self {
        Self {
            address,
            chain_observer,
            verification_key,
        }
    }
}

#[async_trait]
impl EraReaderAdapter for CardanoChainAdapter {
    async fn read(&self) -> StdResult<Vec<EraMarker>> {
        let tx_datums = self.chain_observer.get_current_datums(&self.address).await?;
        let markers_list = tx_datums
            .into_iter()
            .filter_map(|datum| datum.get_fields_by_type(&TxDatumFieldTypeName::Bytes).ok())
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field_value| field_value.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
                    .join("")
            })
            .filter_map(|field_value_str| EraMarkersPayload::from_json_hex(&field_value_str).ok())
            .filter_map(|era_markers_payload| {
                era_markers_payload
                    .verify_signature(self.verification_key)
                    .ok()
                    .map(|_| era_markers_payload.markers)
            })
            .collect::<Vec<Vec<EraMarker>>>();

        Ok(markers_list.first().unwrap_or(&Vec::new()).to_owned())
    }
}

#[cfg(test)]
mod test {
    use mithril_cardano_node_chain::entities::{TxDatum, TxDatumBuilder, TxDatumFieldValue};
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::crypto_helper::EraMarkersSigner;
    use mithril_common::entities::Epoch;

    use super::*;

    fn dummy_tx_datums_from_markers_payload(payloads: Vec<EraMarkersPayload>) -> Vec<TxDatum> {
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
    async fn test_cardano_chain_adapter() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let fake_address = "addr_test_123456".to_string();
        let era_marker_payload_1 = EraMarkersPayload {
            markers: vec![
                EraMarker::new("thales", Some(Epoch(1))),
                EraMarker::new("pythagoras", None),
            ],
            signature: None,
        };
        let era_marker_payload_2 = EraMarkersPayload {
            markers: vec![
                EraMarker::new("thales", Some(Epoch(1))),
                EraMarker::new("pythagoras", Some(Epoch(2))),
            ],
            signature: None,
        };
        let mut fake_datums = dummy_tx_datums_from_markers_payload(vec![
            era_marker_payload_1,
            era_marker_payload_2.clone().sign(&era_markers_signer).unwrap(),
        ]);
        fake_datums.push(TxDatum("not_valid_datum".to_string()));
        let chain_observer = FakeChainObserver::default();
        chain_observer.set_datums(fake_datums.clone()).await;
        let cardano_chain_adapter = CardanoChainAdapter::new(
            fake_address,
            Arc::new(chain_observer),
            era_markers_signer.create_verifier().to_verification_key(),
        );
        let markers = cardano_chain_adapter
            .read()
            .await
            .expect("CardanoChainAdapter read should not fail");
        let expected_markers = era_marker_payload_2.markers.to_owned();
        assert_eq!(expected_markers, markers);
    }
}
