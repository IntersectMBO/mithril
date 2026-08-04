//! Cardano Chain implementation to read protocol configuration markers

use async_trait::async_trait;
use std::sync::Arc;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::ChainAddress;
use mithril_common::StdResult;
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;

use crate::interface::ProtocolConfigurationMarkersReader;
use crate::model::ConfigurationResolverFromMarkers;

/// Cardano Chain reader retrieves protocol configuration markers on chain
pub struct CardanoChainProtocolConfigurationMarkersReader {
    _address: ChainAddress,
    _chain_observer: Arc<dyn ChainObserver>,
    _verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
}

impl CardanoChainProtocolConfigurationMarkersReader {
    /// CardanoChainAdapter factory
    pub fn new(
        _address: ChainAddress,
        _chain_observer: Arc<dyn ChainObserver>,
        _verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
    ) -> Self {
        Self {
            _address,
            _chain_observer,
            _verification_key,
        }
    }
}

#[async_trait]
impl ProtocolConfigurationMarkersReader for CardanoChainProtocolConfigurationMarkersReader {
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers> {
        //read payload
        // to ProtocolConfigurationForEpochMessage
        // to ProtocolConfigurationForEpoch
        // build ConfigurationComputerFromMarkers with ProtocolConfigurationForEpoch
        Err(anyhow::anyhow!(
            "CardanoChainProtocolConfigurationMarkersReader::read is not implemented yet"
        ))
    }
}
