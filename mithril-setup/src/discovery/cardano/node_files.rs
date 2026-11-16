//! Parsing of the files the Cardano node reads at startup, found through its command line

use std::path::{Path, PathBuf};

use anyhow::Context;
use config::{Config, File, FileFormat};
use serde::Deserialize;

/// Node configuration file (ie: `configuration.yml`), only the keys used by the discovery
///
/// The file is either in JSON or in YAML, whatever its name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct CardanoConfiguration {
    /// Path of the Shelley genesis file, relative to the directory of the configuration file
    #[serde(rename = "ShelleyGenesisFile")]
    pub shelley_genesis_file: Option<String>,
}

impl CardanoConfiguration {
    /// Parse the content of a node configuration file, in JSON or in YAML
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        if let Ok(configuration) = serde_json::from_str(content) {
            return Ok(configuration);
        }

        Config::builder()
            .add_source(File::from_str(content, FileFormat::Yaml))
            .build()
            .and_then(Config::try_deserialize)
            .context("The node configuration is neither a valid JSON nor a valid YAML")
    }

    /// Path of the Shelley genesis file, resolved like the node does: against the directory of
    /// the configuration file
    pub fn shelley_genesis_path(&self, config_file: &Path) -> Option<PathBuf> {
        let genesis_file = Path::new(self.shelley_genesis_file.as_deref()?);

        Some(match config_file.parent() {
            Some(config_dir) => config_dir.join(genesis_file),
            None => genesis_file.to_path_buf(),
        })
    }
}

/// Shelley genesis file (ie: `shelley/genesis.json`), only the keys used by the discovery
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShelleyGenesisConfiguration {
    /// Magic number of the network
    pub network_magic: u32,

    /// Kind of the network
    pub network_id: NetworkId,
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

/// Kind of a Cardano network, as written in the Shelley genesis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum NetworkId {
    /// The Cardano mainnet
    Mainnet,

    /// Any Cardano test network
    Testnet,
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

    mod cardano_configuration {
        use super::*;

        const YAML_CONFIGURATION: &str = r#"
            AlonzoGenesisFile: alonzo/genesis.json
            ByronGenesisFile: byron/genesis.json
            ShelleyGenesisFile: shelley/genesis.json
        "#;

        //TODO: can configuration.yml be in JSON format or only in YAML ?
        const JSON_CONFIGURATION: &str = r#"{
            "AlonzoGenesisFile": "alonzo/genesis.json",
            "ByronGenesisFile": "byron/genesis.json",
            "ShelleyGenesisFile": "shelley/genesis.json",
        }"#;

        #[test]
        fn parses_a_yaml_configuration() {
            let configuration = CardanoConfiguration::parse(YAML_CONFIGURATION).unwrap();

            assert_eq!(
                Some("shelley/genesis.json".to_string()),
                configuration.shelley_genesis_file
            );
        }

        #[test]
        fn parses_a_json_configuration() {
            let configuration = CardanoConfiguration::parse(JSON_CONFIGURATION).unwrap();

            assert_eq!(
                Some("shelley/genesis.json".to_string()),
                configuration.shelley_genesis_file
            );
        }

        #[test]
        fn leaves_the_shelley_genesis_file_unknown_when_absent() {
            let configuration = CardanoConfiguration::parse("Protocol: Cardano").unwrap();

            assert_eq!(CardanoConfiguration::default(), configuration);
        }

        #[test]
        fn fails_on_a_content_that_is_neither_json_nor_yaml() {
            let result = CardanoConfiguration::parse("{ not: [valid");

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[test]
        fn fails_on_a_content_that_is_not_a_map() {
            let result = CardanoConfiguration::parse("- a\n- list");

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        fn with_genesis(path: &str) -> CardanoConfiguration {
            CardanoConfiguration {
                shelley_genesis_file: Some(path.to_string()),
            }
        }

        #[test]
        fn resolves_a_relative_genesis_path_against_the_configuration_directory() {
            let path = with_genesis("shelley/genesis.json")
                .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

            assert_eq!(
                Some(PathBuf::from("/opt/cardano/shelley/genesis.json")),
                path
            );
        }

        #[test]
        fn keeps_an_absolute_genesis_path() {
            let path = with_genesis("/etc/cardano/shelley-genesis.json")
                .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

            assert_eq!(
                Some(PathBuf::from("/etc/cardano/shelley-genesis.json")),
                path
            );
        }

        #[test]
        fn keeps_a_relative_genesis_path_when_the_configuration_path_has_no_directory() {
            let path = with_genesis("shelley/genesis.json")
                .shelley_genesis_path(Path::new("configuration.yml"));

            assert_eq!(Some(PathBuf::from("shelley/genesis.json")), path);
        }

        #[test]
        fn has_no_genesis_path_when_the_genesis_file_is_unknown() {
            let path = CardanoConfiguration::default()
                .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

            assert_eq!(None, path);
        }
    }

    mod shelley_genesis_configuration {
        use super::*;

        const PREVIEW_GENESIS: &str = r#"{
            "networkId": "Testnet",
            "networkMagic": 2
        }"#;

        #[test]
        fn parses_a_shelley_genesis() {
            let genesis = ShelleyGenesisConfiguration::parse(PREVIEW_GENESIS).unwrap();

            assert_eq!(
                ShelleyGenesisConfiguration {
                    network_magic: 2,
                    network_id: NetworkId::Testnet,
                },
                genesis
            );
        }

        #[test]
        fn parses_a_mainnet_network_id() {
            let genesis = ShelleyGenesisConfiguration::parse(
                r#"{ "networkId": "Mainnet", "networkMagic": 764824073 }"#,
            )
            .unwrap();

            assert_eq!(NetworkId::Mainnet, genesis.network_id);
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
