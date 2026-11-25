use anyhow::Context;
use serde::Deserialize;

use crate::guessing::CardanoNetwork;

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
}
