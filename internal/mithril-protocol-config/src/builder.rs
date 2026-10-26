//! Builder for creating a ProtocolConfigurationMarkersReader based on AdapterConfig.

use std::{str::FromStr, sync::Arc};

use serde::Deserialize;
use slog::Logger;

use mithril_cardano_node_chain::{chain_observer::ChainObserver, entities::ChainAddress};
use mithril_common::{
    StdResult, crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey,
};

use crate::{
    cardano_chain::protocol_configuration_reader::CardanoChainProtocolConfigurationMarkersReader,
    interface::ProtocolConfigurationMarkersReader,
    test::double::FakeProtocolConfigurationMarkersReader,
};

/// Configuration of Protocol Configuration Adapter
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum AdapterConfig {
    /// Cardano chain protocol configuration adapter
    CardanoChain {
        /// Cardano chain address
        address: ChainAddress,

        /// Verification key
        verification_key: Box<ProtocolConfigurationMarkersVerifierVerificationKey>,
    },

    /// Fake protocol configuration adapter with a single configuration at epoch 0 (for test usage)
    Fake {
        /// JSON hex encoded protocol configuration (same format as the configuration of a protocol configuration marker)
        protocol_parameters: String,
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
    logger: Logger,
) -> StdResult<Arc<dyn ProtocolConfigurationMarkersReader>> {
    let adapter: Arc<dyn ProtocolConfigurationMarkersReader> = match adapter_config {
        AdapterConfig::CardanoChain {
            address,
            verification_key,
        } => Arc::new(CardanoChainProtocolConfigurationMarkersReader::new(
            address,
            chain_observer,
            *verification_key,
            logger,
        )),
        AdapterConfig::Fake {
            protocol_parameters,
        } => Arc::new(
            FakeProtocolConfigurationMarkersReader::from_json_hex_marker_configuration(
                &protocol_parameters,
            )?,
        ),
    };

    Ok(adapter)
}

#[cfg(test)]
mod test {
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::{crypto_helper::key_encode_hex, test::double::Dummy};

    use crate::{
        cardano_chain::message::ProtocolConfigurationForEpochMessage, test::test_tools::TestLogger,
    };

    use super::*;

    static VERIFICATION_KEY: &str = "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d";

    #[test]
    fn deserialize_cardano_chain_adapter_config_from_json() {
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
                verification_key: Box::new(VERIFICATION_KEY.try_into().expect("should not fail"))
            }
        );
    }

    #[test]
    fn deserialize_fake_adapter_config_from_json() {
        let serialized_json = serde_json::json!({
            "type": "fake",
            "protocol_parameters": "7b7d",
        });

        let payload = serde_json::to_string(&serialized_json).unwrap();
        let deserialized: AdapterConfig = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            deserialized,
            AdapterConfig::Fake {
                protocol_parameters: "7b7d".to_string()
            }
        );
    }

    #[test]
    fn build_fake_adapter_from_json_hex_configuration() {
        let adapter_config = AdapterConfig::Fake {
            protocol_parameters: key_encode_hex(ProtocolConfigurationForEpochMessage::dummy())
                .unwrap(),
        };

        build_protocol_configuration_adapter(
            adapter_config,
            Arc::new(FakeChainObserver::default()),
            TestLogger::stdout(),
        )
        .expect("building a fake adapter with a valid configuration should not fail");
    }

    #[test]
    fn build_fake_adapter_fails_with_invalid_configuration() {
        let adapter_config = AdapterConfig::Fake {
            protocol_parameters: "invalid_configuration".to_string(),
        };

        let result = build_protocol_configuration_adapter(
            adapter_config,
            Arc::new(FakeChainObserver::default()),
            TestLogger::stdout(),
        );

        assert!(result.is_err());
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
