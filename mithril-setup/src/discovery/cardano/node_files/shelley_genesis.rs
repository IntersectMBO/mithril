use anyhow::Context;
use serde::Deserialize;

/// Shelley genesis file (ie: `shelley/genesis.json`), only the keys used by the discovery
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShelleyGenesisConfiguration {
    /// Magic number of the network
    pub network_magic: u32,
}

impl ShelleyGenesisConfiguration {
    /// Parse the content of a Shelley genesis file
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        serde_json::from_str(content).context("The Shelley genesis is not a valid JSON")
    }

    /// Network the genesis belongs to
    pub fn network(&self) -> CardanoNetwork {
        CardanoNetwork::from_magic(self.network_magic)
    }
}

/// A Cardano network, named like the Mithril signer expects it (see `CardanoNetwork` in
/// `mithril-common`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardanoNetwork {
    /// The Cardano mainnet
    Mainnet,

    /// The Cardano preprod test network
    Preprod,

    /// The Cardano preview test network
    Preview,

    /// A local development network
    Devnet,

    /// Any other test network, identified by its magic number
    Private(u32),
}

impl CardanoNetwork {
    const MAINNET_MAGIC: u32 = 764824073;
    const PREPROD_MAGIC: u32 = 1;
    const PREVIEW_MAGIC: u32 = 2;
    const DEVNET_MAGIC: u32 = 42;

    /// Network identified by the given magic number
    pub fn from_magic(magic: u32) -> Self {
        match magic {
            Self::MAINNET_MAGIC => Self::Mainnet,
            Self::PREPROD_MAGIC => Self::Preprod,
            Self::PREVIEW_MAGIC => Self::Preview,
            Self::DEVNET_MAGIC => Self::Devnet,
            _ => Self::Private(magic),
        }
    }

    /// Magic number of the network
    pub fn magic(&self) -> u32 {
        match self {
            Self::Mainnet => Self::MAINNET_MAGIC,
            Self::Preprod => Self::PREPROD_MAGIC,
            Self::Preview => Self::PREVIEW_MAGIC,
            Self::Devnet => Self::DEVNET_MAGIC,
            Self::Private(magic) => *magic,
        }
    }

    /// Name of the network, ie: `preview`
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Preprod => "preprod",
            Self::Preview => "preview",
            Self::Devnet => "devnet",
            Self::Private(_) => "private",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod shelley_genesis_configuration {
        use super::*;

        const PREVIEW_GENESIS: &str = r#"{
            "networkMagic": 2
        }"#;

        #[test]
        fn parses_a_shelley_genesis() {
            let genesis = ShelleyGenesisConfiguration::parse(PREVIEW_GENESIS).unwrap();

            assert_eq!(ShelleyGenesisConfiguration { network_magic: 2 }, genesis);
        }

        #[test]
        fn fails_when_the_network_magic_is_missing() {
            let result = ShelleyGenesisConfiguration::parse(r#"{ "networkId": "Testnet" }"#);

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[test]
        fn fails_on_an_invalid_json() {
            let result = ShelleyGenesisConfiguration::parse("{ not json");

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[test]
        fn gives_the_network_of_the_genesis() {
            let genesis = ShelleyGenesisConfiguration::parse(PREVIEW_GENESIS).unwrap();

            assert_eq!(CardanoNetwork::Preview, genesis.network());
        }
    }

    mod cardano_network {
        use super::*;

        #[test]
        fn identifies_the_known_networks_by_their_magic() {
            assert_eq!(
                CardanoNetwork::Mainnet,
                CardanoNetwork::from_magic(764824073)
            );
            assert_eq!(CardanoNetwork::Preprod, CardanoNetwork::from_magic(1));
            assert_eq!(CardanoNetwork::Preview, CardanoNetwork::from_magic(2));
            assert_eq!(CardanoNetwork::Devnet, CardanoNetwork::from_magic(42));
        }

        #[test]
        fn identifies_any_other_magic_as_a_private_network() {
            assert_eq!(CardanoNetwork::Private(4), CardanoNetwork::from_magic(4));
        }

        #[test]
        fn gives_back_the_magic_of_the_network() {
            for magic in [764824073, 1, 2, 42, 4] {
                assert_eq!(magic, CardanoNetwork::from_magic(magic).magic());
            }
        }

        #[test]
        fn names_the_networks_like_the_mithril_signer_expects() {
            assert_eq!("mainnet", CardanoNetwork::Mainnet.name());
            assert_eq!("preprod", CardanoNetwork::Preprod.name());
            assert_eq!("preview", CardanoNetwork::Preview.name());
            assert_eq!("devnet", CardanoNetwork::Devnet.name());
            assert_eq!("private", CardanoNetwork::Private(4).name());
        }
    }
}
