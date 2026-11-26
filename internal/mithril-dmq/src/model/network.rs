use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

use mithril_common::MagicId;

#[derive(Error, Debug)]
pub enum DmqNetworkError {
    #[error("parse from code error: '{0}'")]
    ParseFromCode(String),
}

/// The Dmq Network that is being targeted
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize, Hash, Eq, PartialOrd)]
pub enum DmqNetwork {
    /// The Dmq mainnet network
    MainNet,

    /// A Dmq test network (preview, preprod, dijkstranet or private testnet)
    TestNet(MagicId),
}

impl DmqNetwork {
    /// Mainnet magic ID
    pub const MAINNET_MAGIC_ID: MagicId = 2912307721;
    /// Preprod magic ID
    pub const PREPROD_MAGIC_ID: MagicId = 2147483649;
    /// Preview magic ID
    pub const PREVIEW_MAGIC_ID: MagicId = 2147483650;
    /// Devnet magic ID
    pub(crate) const DEVNET_MAGIC_ID: MagicId = 2147483690;
    /// Dijkstranet magic ID
    pub const DIJKSTRANET_MAGIC_ID: MagicId = 2147483654;

    /// Instantiates a DmqNetwork from its code and magic id
    pub fn from_code(
        network_code: String,
        network_magic: Option<u64>,
    ) -> Result<DmqNetwork, DmqNetworkError> {
        match network_code.to_lowercase().as_str() {
            "mainnet" => Ok(DmqNetwork::MainNet),
            "preview" => Ok(DmqNetwork::TestNet(Self::PREVIEW_MAGIC_ID)),
            "preprod" => Ok(DmqNetwork::TestNet(Self::PREPROD_MAGIC_ID)),
            "devnet" => Ok(DmqNetwork::TestNet(Self::DEVNET_MAGIC_ID)),
            "dijkstranet" => Ok(DmqNetwork::TestNet(Self::DIJKSTRANET_MAGIC_ID)),
            "private" => {
                if let Some(magic) = network_magic {
                    Ok(DmqNetwork::TestNet(magic))
                } else {
                    Err(DmqNetworkError::ParseFromCode(
                        "no NETWORK MAGIC number given for test network".to_string(),
                    ))
                }
            }
            what => Err(DmqNetworkError::ParseFromCode(format!(
                "could not parse network '{what}', the only recognized networks are: mainnet, devnet, testnet, preview, preprod, dijkstranet and private"
            ))),
        }
    }

    /// Returns the magic ID of the network
    pub fn magic_id(&self) -> MagicId {
        match *self {
            DmqNetwork::MainNet => Self::MAINNET_MAGIC_ID,
            DmqNetwork::TestNet(magic_id) => magic_id,
        }
    }
}

impl Display for DmqNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            DmqNetwork::MainNet => write!(f, "mainnet"),
            DmqNetwork::TestNet(magic_id) => match magic_id {
                Self::PREVIEW_MAGIC_ID => write!(f, "preview"),
                Self::PREPROD_MAGIC_ID => write!(f, "preprod"),
                Self::DEVNET_MAGIC_ID => write!(f, "devnet"),
                Self::DIJKSTRANET_MAGIC_ID => write!(f, "dijkstranet"),
                _ => write!(f, "private"),
            },
        }
    }
}

impl From<DmqNetwork> for String {
    fn from(network: DmqNetwork) -> Self {
        network.to_string()
    }
}

impl From<&DmqNetwork> for String {
    fn from(network: &DmqNetwork) -> Self {
        network.to_string()
    }
}

impl From<MagicId> for DmqNetwork {
    fn from(magic_id: MagicId) -> Self {
        match magic_id {
            Self::MAINNET_MAGIC_ID => Self::MainNet,
            _ => Self::TestNet(magic_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmq_network_from_code() {
        assert_eq!(
            DmqNetwork::from_code("mainnet".to_string(), None).unwrap(),
            DmqNetwork::MainNet
        );
        assert_eq!(
            DmqNetwork::from_code("mainnet".to_string(), Some(123)).unwrap(),
            DmqNetwork::MainNet
        );
        assert_eq!(
            DmqNetwork::from_code("preview".to_string(), None).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::PREVIEW_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("preview".to_string(), Some(123)).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::PREVIEW_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("preprod".to_string(), None).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::PREPROD_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("preprod".to_string(), Some(123)).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::PREPROD_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("devnet".to_string(), None).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::DEVNET_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("devnet".to_string(), Some(123)).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::DEVNET_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("dijkstranet".to_string(), None).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::DIJKSTRANET_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("dijkstranet".to_string(), Some(123)).unwrap(),
            DmqNetwork::TestNet(DmqNetwork::DIJKSTRANET_MAGIC_ID)
        );
        assert_eq!(
            DmqNetwork::from_code("private".to_string(), Some(123)).unwrap(),
            DmqNetwork::TestNet(123)
        );
        assert!(DmqNetwork::from_code("private".to_string(), None).is_err());
    }

    #[test]
    fn network_to_string() {
        fn assert_all_conversions_eq(network: DmqNetwork, expected: &str) {
            assert_eq!(network.to_string(), expected);
            assert_eq!(String::from(network), expected);
            assert_eq!(String::from(&network), expected);
        }

        assert_all_conversions_eq(DmqNetwork::MainNet, "mainnet");
        assert_all_conversions_eq(DmqNetwork::TestNet(DmqNetwork::DEVNET_MAGIC_ID), "devnet");
        assert_all_conversions_eq(DmqNetwork::TestNet(DmqNetwork::PREVIEW_MAGIC_ID), "preview");
        assert_all_conversions_eq(DmqNetwork::TestNet(DmqNetwork::PREPROD_MAGIC_ID), "preprod");
        assert_all_conversions_eq(
            DmqNetwork::TestNet(DmqNetwork::DIJKSTRANET_MAGIC_ID),
            "dijkstranet",
        );
        assert_all_conversions_eq(DmqNetwork::TestNet(123456), "private");
    }

    #[test]
    fn dmq_network_from_magic_id_roundtrip() {
        fn assert_magic_id_conversion_roundtrip(magic_id: MagicId, expected: DmqNetwork) {
            let network = DmqNetwork::from(magic_id);
            assert_eq!(network, expected);
            assert_eq!(network.magic_id(), magic_id);
        }

        assert_magic_id_conversion_roundtrip(DmqNetwork::MAINNET_MAGIC_ID, DmqNetwork::MainNet);
        assert_magic_id_conversion_roundtrip(
            DmqNetwork::PREVIEW_MAGIC_ID,
            DmqNetwork::TestNet(DmqNetwork::PREVIEW_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            DmqNetwork::PREPROD_MAGIC_ID,
            DmqNetwork::TestNet(DmqNetwork::PREPROD_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            DmqNetwork::DEVNET_MAGIC_ID,
            DmqNetwork::TestNet(DmqNetwork::DEVNET_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            DmqNetwork::DIJKSTRANET_MAGIC_ID,
            DmqNetwork::TestNet(DmqNetwork::DIJKSTRANET_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(123456, DmqNetwork::TestNet(123456));
    }
}
