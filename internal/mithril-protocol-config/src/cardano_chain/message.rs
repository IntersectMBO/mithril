//! Messages representing Protocol Configurations converted into CBOR format, for Cardano chain datum

use anyhow::Context;
use fixed::types::U8F24;
use hex::FromHex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

use mithril_common::{
    StdError,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, ProtocolParameters,
    },
    messages::SignedEntityTypeDiscriminantsMessage,
};

/// The cbor representation of a [ProtocolConfigurationForEpochMessage]
pub type CborProtocolConfigurationForEpochMessage = String;

/// Value object that represents a tag of Protocol Configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolConfigurationMarker {
    /// Epoch
    pub epoch: Epoch,

    /// Protocol parameters
    pub configuration: CborProtocolConfigurationForEpochMessage,
}

impl ProtocolConfigurationMarker {
    /// instantiate a new [ProtocolConfigurationMarker].
    pub fn new(
        epoch: Epoch,
        protocol_configuration: CborProtocolConfigurationForEpochMessage,
    ) -> Self {
        ProtocolConfigurationMarker {
            epoch,
            configuration: protocol_configuration,
        }
    }
}

/// Parse error
#[derive(Error, Debug)]
#[error("Codec parse error")]
pub struct ProtocolConfigurationForEpochMessageParseError(#[source] StdError);

/// Protocol cryptographic parameters Message
///
/// used for the CBOR representation of [ProtocolConfigurationForEpochMessage]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolParametersMessage {
    /// Quorum parameter
    pub k: u64,

    /// Security parameter (number of lotteries)
    pub m: u64,

    /// f in phi(w) = 1 - (1 - f)^w, where w is the stake of a participant
    pub phi_f: f64,
}

impl ProtocolParametersMessage {
    /// phi_f_fixed is a fixed decimal representation of phi_f
    /// used for PartialEq and Hash implementation
    pub fn phi_f_fixed(&self) -> U8F24 {
        U8F24::from_num(self.phi_f)
    }
}

impl PartialEq<ProtocolParametersMessage> for ProtocolParametersMessage {
    fn eq(&self, other: &ProtocolParametersMessage) -> bool {
        self.k == other.k && self.m == other.m && self.phi_f_fixed() == other.phi_f_fixed()
    }
}

impl From<ProtocolParameters> for ProtocolParametersMessage {
    fn from(params: ProtocolParameters) -> Self {
        ProtocolParametersMessage {
            k: params.k,
            m: params.m,
            phi_f: params.phi_f,
        }
    }
}

/// Configuration for the signing of Cardano transactions
///
/// used for the CBOR representation of [ProtocolConfigurationForEpochMessage]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoTransactionsSigningConfigMessage {
    /// Number of blocks to discard from the tip of the chain when importing transactions.
    pub security_parameter: BlockNumberOffset,

    /// The number of blocks between signature of the transactions.
    pub step: BlockNumber,
}

impl From<CardanoTransactionsSigningConfig> for CardanoTransactionsSigningConfigMessage {
    fn from(config: CardanoTransactionsSigningConfig) -> Self {
        CardanoTransactionsSigningConfigMessage {
            security_parameter: config.security_parameter,
            step: config.step,
        }
    }
}

/// Configuration for the signing of Cardano blocks and transactions
///
/// used for the CBOR representation of [ProtocolConfigurationForEpochMessage]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoBlocksTransactionsSigningConfigMessage {
    /// Number of blocks to discard from the tip of the chain when importing blocks and transactions.
    pub security_parameter: BlockNumberOffset,

    /// The number of blocks between signature of the blocks and transactions.
    pub step: BlockNumber,
}

impl From<CardanoBlocksTransactionsSigningConfig>
    for CardanoBlocksTransactionsSigningConfigMessage
{
    fn from(config: CardanoBlocksTransactionsSigningConfig) -> Self {
        CardanoBlocksTransactionsSigningConfigMessage {
            security_parameter: config.security_parameter,
            step: config.step,
        }
    }
}

//A epoch configuration used for the CBOR representation in the [ProtocolConfigurationMarker]
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
/// A network configuration available for an epoch
pub struct ProtocolConfigurationForEpochMessage {
    /// Cryptographic protocol parameters (`k`, `m` and `phi_f`)
    pub protocol_parameters: ProtocolParametersMessage,

    /// List of available types of certifications
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,

    /// Signing configuration for Cardano transactions
    pub cardano_transactions: Option<CardanoTransactionsSigningConfigMessage>,

    /// Signing configuration for Cardano blocks and transactions
    pub cardano_blocks_transactions: Option<CardanoBlocksTransactionsSigningConfigMessage>,
}

impl ProtocolConfigurationForEpochMessage {
    /// Serialize the structure to a CBOR bytes representation.
    fn to_cbor_bytes(&self) -> Result<Vec<u8>, ProtocolConfigurationForEpochMessageParseError> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        ciborium::ser::into_writer(&self, &mut cursor)
            .with_context(|| "ProtocolConfigurationForEpoch can not serialize data to cbor")
            .map_err(ProtocolConfigurationForEpochMessageParseError)?;

        Ok(cursor.into_inner())
    }

    /// Serialize the structure to a CBOR hex representation.
    pub fn to_cbor_hex(&self) -> Result<String, ProtocolConfigurationForEpochMessageParseError> {
        Ok(hex::encode(self.to_cbor_bytes()?))
    }

    /// Deserialize a type `T: Serialize + DeserializeOwned` from CBOR bytes representation.
    fn from_cbor_bytes(
        bytes: &[u8],
    ) -> Result<Self, ProtocolConfigurationForEpochMessageParseError> {
        let mut cursor = std::io::Cursor::new(&bytes);
        let a: Self = ciborium::de::from_reader(&mut cursor)
            .with_context(|| "ProtocolConfigurationForEpoch can not unserialize cbor data")
            .map_err(ProtocolConfigurationForEpochMessageParseError)?;

        Ok(a)
    }

    /// Deserialize a type `T: Serialize + DeserializeOwned` from CBOR hex representation.
    pub fn from_cbor_hex(
        hex: &str,
    ) -> Result<Self, ProtocolConfigurationForEpochMessageParseError> {
        let hex_vector = Vec::from_hex(hex)
            .with_context(|| "ProtocolConfigurationForEpochMessage can not unserialize hex data")
            .map_err(ProtocolConfigurationForEpochMessageParseError)?;

        Self::from_cbor_bytes(&hex_vector)
            .with_context(|| "ProtocolConfigurationForEpochMessage can not unserialize cbor data")
            .map_err(ProtocolConfigurationForEpochMessageParseError)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::Dummy;

    use super::*;

    #[test]
    fn to_cbor_from_cbor_conversion() {
        let mithril_network_configuration_for_epoch = ProtocolConfigurationForEpochMessage::dummy();
        let cbor = mithril_network_configuration_for_epoch.to_cbor_hex().unwrap();
        let mithril_network_configuration_for_epoch_from_cbor =
            ProtocolConfigurationForEpochMessage::from_cbor_hex(&cbor).unwrap();
        assert_eq!(
            mithril_network_configuration_for_epoch,
            mithril_network_configuration_for_epoch_from_cbor
        );
    }
}
