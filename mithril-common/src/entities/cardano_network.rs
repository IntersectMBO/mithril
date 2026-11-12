use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

use crate::{MagicId, StdResult};

#[derive(Error, Debug)]
pub enum CardanoNetworkError {
    #[error("parse from code error: '{0}'")]
    ParseFromCode(String),
}

/// The Cardano Network that is being targeted
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize, Hash, Eq, PartialOrd)]
pub enum CardanoNetwork {
    /// The Cardano mainnet network
    MainNet,

    /// A Cardano test network (preview, preprod, dijkstranet or private testnet)
    TestNet(MagicId),
}

impl CardanoNetwork {
    /// Mainnet magic ID
    pub const MAINNET_MAGIC_ID: MagicId = 764824073;
    /// Preprod magic ID
    pub const PREPROD_MAGIC_ID: MagicId = 1;
    /// Preview magic ID
    pub const PREVIEW_MAGIC_ID: MagicId = 2;
    /// Devnet magic ID
    pub const DEVNET_MAGIC_ID: MagicId = 42;
    /// Dijkstranet magic ID
    pub const DIJKSTRANET_MAGIC_ID: MagicId = 6;

    /// Instantiates a CardanoNetwork from its code and magic id
    pub fn from_code(
        network_code: String,
        network_magic: Option<u64>,
    ) -> Result<CardanoNetwork, CardanoNetworkError> {
        match network_code.to_lowercase().as_str() {
            "mainnet" => Ok(CardanoNetwork::MainNet),
            "preview" => Ok(CardanoNetwork::TestNet(Self::PREVIEW_MAGIC_ID)),
            "preprod" => Ok(CardanoNetwork::TestNet(Self::PREPROD_MAGIC_ID)),
            "devnet" => Ok(CardanoNetwork::TestNet(Self::DEVNET_MAGIC_ID)),
            "dijkstranet" => Ok(CardanoNetwork::TestNet(Self::DIJKSTRANET_MAGIC_ID)),
            "private" => {
                if let Some(magic) = network_magic {
                    Ok(CardanoNetwork::TestNet(magic))
                } else {
                    Err(CardanoNetworkError::ParseFromCode(
                        "no NETWORK MAGIC number given for test network".to_string(),
                    ))
                }
            }
            what => Err(CardanoNetworkError::ParseFromCode(format!(
                "could not parse network '{what}', the only recognized networks are: mainnet, devnet, testnet, preview, preprod, dijkstranet and private"
            ))),
        }
    }

    /// Returns the magic ID of the network
    pub fn magic_id(&self) -> MagicId {
        match *self {
            CardanoNetwork::MainNet => Self::MAINNET_MAGIC_ID,
            CardanoNetwork::TestNet(magic_id) => magic_id,
        }
    }

    /// Determines whether unparsable blocks should be allowed based on the specific Cardano network.
    pub fn compute_allow_unparsable_block(&self, allow_unparsable_block: bool) -> StdResult<bool> {
        let allow_unparsable_block = match self {
            CardanoNetwork::MainNet => false,
            CardanoNetwork::TestNet(id) if *id == Self::PREPROD_MAGIC_ID => false,
            _ => allow_unparsable_block,
        };

        Ok(allow_unparsable_block)
    }
}

impl Display for CardanoNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            CardanoNetwork::MainNet => write!(f, "mainnet"),
            CardanoNetwork::TestNet(magic_id) => match magic_id {
                Self::PREVIEW_MAGIC_ID => write!(f, "preview"),
                Self::PREPROD_MAGIC_ID => write!(f, "preprod"),
                Self::DEVNET_MAGIC_ID => write!(f, "devnet"),
                Self::DIJKSTRANET_MAGIC_ID => write!(f, "dijkstranet"),
                _ => write!(f, "private"),
            },
        }
    }
}

impl From<CardanoNetwork> for String {
    fn from(network: CardanoNetwork) -> Self {
        network.to_string()
    }
}

impl From<&CardanoNetwork> for String {
    fn from(network: &CardanoNetwork) -> Self {
        network.to_string()
    }
}

impl From<MagicId> for CardanoNetwork {
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
    fn test_cardano_network_from_code() {
        assert_eq!(
            CardanoNetwork::from_code("mainnet".to_string(), None).unwrap(),
            CardanoNetwork::MainNet
        );
        assert_eq!(
            CardanoNetwork::from_code("mainnet".to_string(), Some(123)).unwrap(),
            CardanoNetwork::MainNet
        );
        assert_eq!(
            CardanoNetwork::from_code("preview".to_string(), None).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("preview".to_string(), Some(123)).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("preprod".to_string(), None).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("preprod".to_string(), Some(123)).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("devnet".to_string(), None).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("devnet".to_string(), Some(123)).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("dijkstranet".to_string(), None).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::DIJKSTRANET_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("dijkstranet".to_string(), Some(123)).unwrap(),
            CardanoNetwork::TestNet(CardanoNetwork::DIJKSTRANET_MAGIC_ID)
        );
        assert_eq!(
            CardanoNetwork::from_code("private".to_string(), Some(123)).unwrap(),
            CardanoNetwork::TestNet(123)
        );
        assert!(CardanoNetwork::from_code("private".to_string(), None).is_err());
    }

    #[test]
    fn compute_allow_unparsable_block_should_always_return_false_on_mainnet_and_preprod() {
        let allow_unparsable_block =
            CardanoNetwork::MainNet.compute_allow_unparsable_block(false).unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block =
            CardanoNetwork::MainNet.compute_allow_unparsable_block(true).unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID)
            .compute_allow_unparsable_block(false)
            .unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID)
            .compute_allow_unparsable_block(true)
            .unwrap();
        assert!(!allow_unparsable_block);
    }

    #[test]
    fn compute_allow_unparsable_block_should_return_value_passed_in_parameter_on_all_networks_other_than_mainnet_and_preprod()
     {
        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID)
            .compute_allow_unparsable_block(false)
            .unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID)
            .compute_allow_unparsable_block(true)
            .unwrap();
        assert!(allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID)
            .compute_allow_unparsable_block(false)
            .unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID)
            .compute_allow_unparsable_block(true)
            .unwrap();
        assert!(allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(123)
            .compute_allow_unparsable_block(false)
            .unwrap();
        assert!(!allow_unparsable_block);

        let allow_unparsable_block = CardanoNetwork::TestNet(123)
            .compute_allow_unparsable_block(true)
            .unwrap();
        assert!(allow_unparsable_block);
    }

    #[test]
    fn network_to_string() {
        fn assert_all_conversions_eq(network: CardanoNetwork, expected: &str) {
            assert_eq!(network.to_string(), expected);
            assert_eq!(String::from(network), expected);
            assert_eq!(String::from(&network), expected);
        }

        assert_all_conversions_eq(CardanoNetwork::MainNet, "mainnet");
        assert_all_conversions_eq(
            CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID),
            "devnet",
        );
        assert_all_conversions_eq(
            CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID),
            "preview",
        );
        assert_all_conversions_eq(
            CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID),
            "preprod",
        );
        assert_all_conversions_eq(
            CardanoNetwork::TestNet(CardanoNetwork::DIJKSTRANET_MAGIC_ID),
            "dijkstranet",
        );
        assert_all_conversions_eq(CardanoNetwork::TestNet(123456), "private");
    }

    #[test]
    fn cardano_network_from_magic_id_roundtrip() {
        fn assert_magic_id_conversion_roundtrip(magic_id: MagicId, expected: CardanoNetwork) {
            let network = CardanoNetwork::from(magic_id);
            assert_eq!(network, expected);
            assert_eq!(network.magic_id(), magic_id);
        }

        assert_magic_id_conversion_roundtrip(
            CardanoNetwork::MAINNET_MAGIC_ID,
            CardanoNetwork::MainNet,
        );
        assert_magic_id_conversion_roundtrip(
            CardanoNetwork::PREVIEW_MAGIC_ID,
            CardanoNetwork::TestNet(CardanoNetwork::PREVIEW_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            CardanoNetwork::PREPROD_MAGIC_ID,
            CardanoNetwork::TestNet(CardanoNetwork::PREPROD_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            CardanoNetwork::DEVNET_MAGIC_ID,
            CardanoNetwork::TestNet(CardanoNetwork::DEVNET_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(
            CardanoNetwork::DIJKSTRANET_MAGIC_ID,
            CardanoNetwork::TestNet(CardanoNetwork::DIJKSTRANET_MAGIC_ID),
        );
        assert_magic_id_conversion_roundtrip(123456, CardanoNetwork::TestNet(123456));
    }
}
