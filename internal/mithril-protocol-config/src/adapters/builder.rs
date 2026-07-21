use serde::{Deserialize, Serialize};
use std::{fmt::Display, sync::Arc};
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_cardano_node_chain::entities::ChainAddress;
use mithril_common::StdError;
use mithril_common::crypto_helper::ProtocolConfigurationMarkersVerifierVerificationKey;

use crate::ProtocolConfigurationReaderAdapter;
use crate::adapters::ProtocolConfigurationReaderCardanoChainAdapter;

/// Type of protocol configuration reader adapters available
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdapterType {
    /// Cardano chain adapter.
    #[serde(rename = "cardano-chain")]
    CardanoChain,
    // /// File adapter.
    // File,
    // /// Dummy adapter.
    // Dummy,
    // /// Bootstrap adapter.
    // Bootstrap,
    // /// Bootstrap latest adapter.
    // #[serde(rename = "bootstrap-latest")]
    // BootstrapLatest,
}

impl Display for AdapterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CardanoChain => write!(f, "cardano chain"),
            // Self::Bootstrap => write!(f, "bootstrap"),
            // Self::Dummy => write!(f, "dummy"),
            // Self::File => write!(f, "file"),
            // Self::BootstrapLatest => write!(f, "bootstrap latest"),
        }
    }
}

/// Error type for protocol configuration reader adapter builder service.
#[derive(Error, Debug)]
pub enum AdapterBuilderError {
    /// Missing parameters error.
    #[error("protocol configuration reader adapter parameters are missing")]
    MissingParameters(),

    /// Parameters parse error.
    #[error("protocol configuration reader adapter parameters parse error")]
    ParseParameters(#[source] serde_json::Error),

    /// Parameters decode error.
    #[error("protocol configuration reader adapter parameters decode error")]
    Decode(#[source] StdError),
}

/// Protocol configuration adapter builder
pub struct AdapterBuilder {
    adapter_type: AdapterType,
    adapter_params: Option<String>,
}

impl AdapterBuilder {
    /// Protocol configuration reader adapter builder factory
    pub fn new(adapter_type: &AdapterType, adapter_params: &Option<String>) -> Self {
        Self {
            adapter_type: adapter_type.to_owned(),
            adapter_params: adapter_params.to_owned(),
        }
    }

    /// Create protocol configuration reader adapter from configuration settings.
    pub fn build(
        &self,
        chain_observer: Arc<dyn ChainObserver>,
    ) -> Result<Arc<dyn ProtocolConfigurationReaderAdapter>, AdapterBuilderError> {
        match self.adapter_type {
            AdapterType::CardanoChain => {
                #[derive(Deserialize)]
                struct CardanoChainAdapterConfig {
                    address: ChainAddress,
                    verification_key: ProtocolConfigurationMarkersVerifierVerificationKey,
                }

                let adapter_config: CardanoChainAdapterConfig = serde_json::from_str(
                    self.adapter_params
                        .as_ref()
                        .ok_or_else(AdapterBuilderError::MissingParameters)?,
                )
                .map_err(AdapterBuilderError::ParseParameters)?;

                Ok(Arc::new(
                    ProtocolConfigurationReaderCardanoChainAdapter::new(
                        adapter_config.address,
                        chain_observer,
                        adapter_config.verification_key,
                    ),
                ))
            } // AdapterType::File => {
              //     #[derive(Deserialize)]
              //     struct EraReaderFileAdapterConfig {
              //         markers_file: PathBuf,
              //     }

              //     let adapter_config: EraReaderFileAdapterConfig = serde_json::from_str(
              //         self.adapter_params
              //             .as_ref()
              //             .ok_or_else(AdapterBuilderError::MissingParameters)?,
              //     )
              //     .map_err(AdapterBuilderError::ParseParameters)?;
              //     let file_adapter = EraReaderFileAdapter::new(adapter_config.markers_file);

              //     Ok(Arc::new(file_adapter))
              // }
              // AdapterType::Dummy => {
              //     #[derive(Deserialize)]
              //     struct EraReaderDummyAdapterConfig {
              //         markers: Vec<EraMarker>,
              //     }

              //     let adapter_config: EraReaderDummyAdapterConfig = serde_json::from_str(
              //         self.adapter_params
              //             .as_ref()
              //             .ok_or_else(AdapterBuilderError::MissingParameters)?,
              //     )
              //     .map_err(AdapterBuilderError::ParseParameters)?;
              //     let dummy_adapter = EraReaderDummyAdapter::default();
              //     dummy_adapter.set_markers(adapter_config.markers);

              //     Ok(Arc::new(dummy_adapter))
              // }
              // AdapterType::Bootstrap => Ok(Arc::new(EraReaderBootstrapAdapter)),
              // AdapterType::BootstrapLatest => Ok(Arc::new(EraReaderBootstrapLatestAdapter)),
        }
    }
}

#[cfg(test)]
mod test {
    use mithril_cardano_node_chain::test::double::FakeChainObserver;

    use super::*;

    const GOLDEN_ADAPTER_PARAMS: &str = r#"{
        "address":"addr_test1qrv5xfwh043mlc3vk5d97s4nmhxu7cmleyssvhx37gkfyejfe8d38v3vsfgetjafgrsdc49krug8wf04h5rmtengtejqlxrksk",
        "verification_key":"5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d"
    }"#;

    #[test]
    fn golden_test_for_cardano_chain() {
        AdapterBuilder::new(
            &AdapterType::CardanoChain,
            &Some(GOLDEN_ADAPTER_PARAMS.to_owned()),
        )
        .build(Arc::new(FakeChainObserver::new(None)))
        .expect("building an cardano chain era reader with golden params should not fail");
    }
}
