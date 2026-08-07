//! Builder helping creating a ProtocolConfigurationMarkersReader base on AdapterConfig.

use serde::Deserialize;
use std::{str::FromStr, sync::Arc};

use mithril_cardano_node_chain::{chain_observer::ChainObserver, entities::ChainAddress};
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;

use crate::{
    cardano_chain::protocol_configuration_reader::CardanoChainProtocolConfigurationMarkersReader,
    interface::ProtocolConfigurationMarkersReader,
};

/// Configuration of Protocol Configuration Adapter
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum AdapterConfig {
    /// Cardano chain protocol configuration adapter
    CardanoChain {
        /// Cardano chain address
        address: ChainAddress,

        /// Verification key
        verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
    },
}

impl FromStr for AdapterConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// Build a ProtocolConfigurationMarkersReader from configuration settings.
pub fn build_protocol_configuration_adapter(
    adapter_config: AdapterConfig,
    chain_observer: Arc<dyn ChainObserver>,
) -> Arc<dyn ProtocolConfigurationMarkersReader> {
    match adapter_config {
        AdapterConfig::CardanoChain {
            address,
            verification_key,
        } => Arc::new(CardanoChainProtocolConfigurationMarkersReader::new(
            address,
            chain_observer,
            verification_key,
        )),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    static VERIFICATION_KEY: &str = "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d";

    #[test]
    fn deserialize_adapter_config_from_json() {
        let serialized_json = serde_json::json!({
            "type": "cardano-chain",
            "address": "my_address",
            "verification_key": VERIFICATION_KEY,
        });

        let payload = serde_json::to_string(&serialized_json).unwrap();
        let deserialized: AdapterConfig = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            deserialized,
            AdapterConfig::CardanoChain {
                address: "my_address".to_string(),
                verification_key: VERIFICATION_KEY.try_into().expect("should not fail")
            }
        );
    }

    #[test]
    fn rejects_adapter_config_with_invalid_verification_key() {
        let invalid_verification_key = "invalid_verification_key";

        let serialized_json = serde_json::json!({
            "type": "cardano-chain",
            "address": "my_address",
            "verification_key": invalid_verification_key,
        });

        let payload = serde_json::to_string(&serialized_json).unwrap();
        let result = serde_json::from_str::<AdapterConfig>(&payload);
        assert!(result.is_err())
    }

    #[test]
    fn rejects_adapter_config_with_unknown_type() {
        let serialized_json = serde_json::json!({
            "type": "invalid-type",
            "address": "A",
            "verification_key": "B",
        });

        let payload = serde_json::to_string(&serialized_json).unwrap();
        let result = serde_json::from_str::<AdapterConfig>(&payload);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown variant `invalid-type`")
        );
    }
}
