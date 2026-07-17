use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use thiserror::Error;

use mithril_common::crypto_helper::{CodecParseError, SerDeShelleyFileFormat};
use mithril_common::entities::{
    CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
    ProtocolParameters, SignedEntityTypeDiscriminants,
};
use mithril_common::{StdError, StdResult};

/// The cbor representation of a MithrilNetworkConfigurationForEpoch
pub type CborProtocolConfigurationForEpoch = String;

/// Value object that represents a tag of Protocol Configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolConfigurationMarker {
    /// Epoch
    pub epoch: Epoch,

    /// Protocol parameters
    pub configuration: CborProtocolConfigurationForEpoch,
}

impl ProtocolConfigurationMarker {
    /// instantiate a new [ProtocolConfigurationMarker].
    pub fn new(epoch: Epoch, protocol_configuration: CborProtocolConfigurationForEpoch) -> Self {
        ProtocolConfigurationMarker {
            epoch,
            configuration: protocol_configuration,
        }
    }
}

//A epoch configuration used by the reader and for the CBOR representation in the ProtocolConfigurationMarker
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
/// A network configuration available for an epoch
pub struct ProtocolConfigurationForEpoch {
    /// Cryptographic protocol parameters (`k`, `m` and `phi_f`)
    pub protocol_parameters: ProtocolParameters,

    /// List of available types of certifications
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,

    //TODO do we want a sub struct like signed_entity_types_config in model ?
    /// Signing configuration for Cardano transactions
    pub cardano_transactions: Option<CardanoTransactionsSigningConfig>,

    /// Signing configuration for Cardano blocks and transactions
    pub cardano_blocks_transactions: Option<CardanoBlocksTransactionsSigningConfig>,
}

impl ProtocolConfigurationForEpoch {
    /// Serialize the ProtocolConfigurationForEpoch to a CBOR hex representation
    pub fn to_cbor(&self) -> Result<CborProtocolConfigurationForEpoch, CodecParseError> {
        self.to_cbor_hex()
    }

    /// Deserialize the ProtocolConfigurationForEpoch from a CBOR hex representation
    pub fn from_cbor(cbor: CborProtocolConfigurationForEpoch) -> Result<Self, CodecParseError> {
        Self::from_cbor_hex(&cbor)
    }
}

impl SerDeShelleyFileFormat for ProtocolConfigurationForEpoch {
    const TYPE: &'static str = "ProtocolConfigurationForEpoch";
    const DESCRIPTION: &'static str = "";
}

/// Adapters are responsible of technically reading the information of
/// [ProtocolConfigurationMarker]s from a backend.
#[async_trait]
pub trait ProtocolConfigurationReaderAdapter: Sync + Send {
    /// Read protocol configuration markers from the underlying adapter.
    async fn read(&self) -> StdResult<Vec<ProtocolConfigurationMarker>>;
}

/// The ProtocolConfigurationReader is responsible of giving the current Protocol Configurations
/// It uses an [ProtocolConfigurationReaderAdapter] to read data from a backend.
pub struct ProtocolConfigurationReader {
    adapter: Arc<dyn ProtocolConfigurationReaderAdapter>,
}

/// Error type when [ProtocolConfigurationReader] fails to return a [todo].
#[derive(Debug, Error)]
pub enum ProtocolConfigurationReaderError {
    /// Underlying adapter fails to return data.
    #[error("Adapter Error message: «{message}»")]
    AdapterFailure {
        /// context message
        message: String,

        /// nested underlying adapter error
        #[source]
        error: StdError,
    },
}

impl ProtocolConfigurationReader {
    /// Instantiate a new [ProtocolConfigurationReader] with an [ProtocolConfigurationReaderAdapter].
    pub fn new(adapter: Arc<dyn ProtocolConfigurationReaderAdapter>) -> Self {
        Self { adapter }
    }

    /// Read protocol configuration markers from the underlying adapter.
    pub async fn read_mithril_network_configurations(
        &self,
    ) -> Result<HashMap<Epoch, ProtocolConfigurationForEpoch>, ProtocolConfigurationReaderError>
    {
        let markers = self.adapter.read().await.map_err(|e| {
            ProtocolConfigurationReaderError::AdapterFailure {
                message: "Failed to read protocol configuration markers from adapter".to_string(),
                error: e,
            }
        })?;

        let mut mithril_network_configurations = HashMap::new();
        for marker in markers {
            let configuration = ProtocolConfigurationForEpoch::from_cbor(marker.configuration)
                .map_err(|e| ProtocolConfigurationReaderError::AdapterFailure {
                    message: format!(
                        "Failed to parse protocol configuration for epoch {}",
                        marker.epoch
                    ),
                    error: e.into(),
                })?;
            mithril_network_configurations.insert(marker.epoch, configuration);
        }
        Ok(mithril_network_configurations)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{
        entities::{BlockNumber, BlockNumberOffset},
        test::double::Dummy,
    };

    use super::*;

    #[test]
    fn to_cbor_from_cbor_conversion() {
        let mithril_network_configuration_for_epoch = ProtocolConfigurationForEpoch::dummy();
        let cbor = mithril_network_configuration_for_epoch.to_cbor().unwrap();
        let mithril_network_configuration_for_epoch_from_cbor =
            ProtocolConfigurationForEpoch::from_cbor(cbor.clone()).unwrap();
        assert_eq!(
            mithril_network_configuration_for_epoch,
            mithril_network_configuration_for_epoch_from_cbor
        );
    }

    #[test]
    fn cbor_golden_test() {
        let expected_cbor = "a47370726f746f636f6c5f706172616d6574657273a3616b01616d02657068695f66fb4002666666666666781b656e61626c65645f7369676e65645f656e746974795f747970657384781843617264616e6f5374616b65446973747269627574696f6e6f43617264616e6f44617461626173657343617264616e6f5472616e73616374696f6e73781943617264616e6f426c6f636b735472616e73616374696f6e737463617264616e6f5f7472616e73616374696f6e73a27273656375726974795f706172616d657465720a647374657014781b63617264616e6f5f626c6f636b735f7472616e73616374696f6e73a27273656375726974795f706172616d65746572181e64737465701828";
        let mithril_network_configuration_for_epoch = ProtocolConfigurationForEpoch {
            protocol_parameters: ProtocolParameters {
                k: 1,
                m: 2,
                phi_f: 2.3,
            },
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
                SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            ]),
            cardano_transactions: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(10),
                step: BlockNumber(20),
            }),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(30),
                step: BlockNumber(40),
            }),
        };
        let cbor = mithril_network_configuration_for_epoch.to_cbor().unwrap();
        assert_eq!(&cbor, expected_cbor);
    }
}
