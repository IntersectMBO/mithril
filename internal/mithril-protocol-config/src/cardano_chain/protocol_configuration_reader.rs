//! Cardano Chain implementation to read protocol configuration markers

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::cardano_chain::message::{
    ProtocolConfigurationForEpochMessage, ProtocolConfigurationMarker,
};
use crate::cardano_chain::payload::SignedProtocolConfigurationMarkersPayload;
use crate::interface::ProtocolConfigurationMarkersReader;
use crate::model::{ConfigurationComputerFromMarkers, ProtocolConfigurationForEpoch};
use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::{ChainAddress, TxDatumFieldTypeName};
use mithril_common::StdResult;
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;

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
    async fn read(&self) -> StdResult<ConfigurationComputerFromMarkers> {
        //read payload
        // to ProtocolConfigurationForEpochMessage
        // to ProtocolConfigurationForEpoch
        // build ConfigurationComputerFromMarkers with ProtocolConfigurationForEpoch
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
            .filter_map(|field_value_str| {
                SignedProtocolConfigurationMarkersPayload::from_json_hex(&field_value_str).ok()
            })
            .filter_map(|era_markers_payload| {
                era_markers_payload
                    .verify_signature(self.verification_key)
                    .ok()
                    .map(|_| era_markers_payload.markers)
            })
            .collect::<Vec<Vec<ProtocolConfigurationMarker>>>();

        let last_markers = markers_list.first().unwrap_or(&Vec::new()).to_owned();

        // BTreeMap<Epoch, ProtocolConfigurationForEpoch> filled from markers
        let mut markers_map: BTreeMap<Epoch, ProtocolConfigurationForEpoch> = BTreeMap::new();
        for marker in last_markers {
            markers_map.insert(
                marker.epoch,
                ProtocolConfigurationForEpochMessage::from_cbor_hex(&marker.protocol_configuration_for_epoch_cbor_hex)
                    .map_err(|e| {
                        StdError::generic_err(format!(
                            "ProtocolConfigurationForEpochMessage could not be decoded from cbor hex: {}",
                            e
                        ))
                    })?
                    .into(),
            );
        }
    }
}
