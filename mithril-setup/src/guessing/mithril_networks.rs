//! Mithril networks, read from the `networks.json` file of the Mithril repository
//!
//! `networks.json` declares the reader adapters of each Mithril network, but does not hold their
//! configuration (address and verification key). That configuration is given alongside it,
//! keyed by the name of the Mithril network, so that parsing them does no I/O.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, anyhow};
use serde::Deserialize;

use crate::guessing::CardanoNetwork;

/// `networks.json` and the readers configuration, embedded by the build script
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_mithril_networks.rs"));
}

/// The Mithril networks, grouped by the Cardano network they run on
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MithrilNetworks {
    networks: BTreeMap<String, Vec<MithrilNetwork>>,
}

/// A Mithril network, ie: `release-mainnet`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MithrilNetwork {
    /// Name of the network, ie: `release-mainnet`
    pub name: String,

    /// Endpoint of the first aggregator of the network
    pub aggregator_endpoint: Option<String>,

    /// Adapter reading the eras from the Cardano chain
    pub era_reader: Option<ReaderAdapter>,

    /// Adapter reading the protocol configuration from the Cardano chain
    pub protocol_configuration_reader: Option<ReaderAdapter>,
}

/// An adapter reading data written on the Cardano chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderAdapter {
    /// Type of the adapter, ie: `cardano-chain`
    pub adapter_type: String,

    /// Address holding the data on chain
    pub address: String,

    /// Verification key of the data written on chain
    pub verification_key: String,
}

/// Configuration of the reader adapters of a Mithril network
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadersConfiguration {
    /// Configuration of the era reader
    pub era_reader: Option<ReaderConfiguration>,

    /// Configuration of the protocol configuration reader
    pub protocol_configuration_reader: Option<ReaderConfiguration>,
}

/// Configuration of a reader adapter, ie: the content of its `.addr` and `.vkey` files
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderConfiguration {
    /// Address holding the data on chain
    pub address: String,

    /// Verification key of the data written on chain
    pub verification_key: String,
}

impl MithrilNetworks {
    /// Mithril networks embedded at build time, from `networks.json` and the readers
    /// configuration of `mithril-infra/configuration`
    pub fn embedded() -> Self {
        let readers_configuration = embedded::READERS_CONFIGURATION
            .iter()
            .map(|(name, era_reader, protocol_configuration_reader)| {
                let configuration = ReadersConfiguration {
                    era_reader: era_reader.map(ReaderConfiguration::from),
                    protocol_configuration_reader: protocol_configuration_reader
                        .map(ReaderConfiguration::from),
                };
                (name.to_string(), configuration)
            })
            .collect();

        // The build script embeds the configuration of every reader declared by `networks.json`
        Self::parse(embedded::NETWORKS_JSON, &readers_configuration)
            .expect("The embedded Mithril networks should be valid")
    }

    /// Parse the content of `networks.json`, with the readers configuration of its Mithril
    /// networks keyed by their name
    ///
    /// Fails when the configuration of a reader declared by `networks.json` is not given, the
    /// Mithril networks would be incomplete otherwise. A configuration of a reader not declared
    /// by `networks.json` is ignored.
    pub fn parse(
        networks_json: &str,
        readers_configuration: &HashMap<String, ReadersConfiguration>,
    ) -> anyhow::Result<Self> {
        let entries: BTreeMap<String, CardanoNetworkEntry> = serde_json::from_str(networks_json)
            .context("The Mithril networks file is not a valid JSON")?;

        let mut networks = BTreeMap::new();
        for (cardano_network, entry) in entries {
            let mithril_networks = entry
                .mithril_networks
                .into_iter()
                .flatten()
                .map(|(name, entry)| {
                    let configuration = readers_configuration.get(&name);
                    entry.resolve(name, configuration)
                })
                .collect::<anyhow::Result<Vec<_>>>()
                .with_context(|| {
                    format!("Invalid Mithril networks for the '{cardano_network}' Cardano network")
                })?;
            networks.insert(cardano_network, mithril_networks);
        }

        Ok(Self { networks })
    }

    /// Mithril networks running on the given Cardano network, in the order of `networks.json`
    pub fn running_on(&self, network: CardanoNetwork) -> &[MithrilNetwork] {
        self.networks
            .get(network.name())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Mithril network with the given name running on the given Cardano network, or its first
    /// one when no name is given
    pub fn select(&self, network: CardanoNetwork, name: Option<&str>) -> Option<&MithrilNetwork> {
        let mut networks = self.running_on(network).iter();
        match name {
            Some(name) => networks.find(|network| network.name == name),
            None => networks.next(),
        }
    }
}

impl From<(&str, &str)> for ReaderConfiguration {
    fn from((address, verification_key): (&str, &str)) -> Self {
        Self {
            address: address.to_string(),
            verification_key: verification_key.to_string(),
        }
    }
}

/// A Cardano network of `networks.json`, only the keys used by the guessing
#[derive(Debug, Deserialize)]
struct CardanoNetworkEntry {
    #[serde(rename = "mithril-networks", default)]
    mithril_networks: Vec<BTreeMap<String, MithrilNetworkEntry>>,
}

/// A Mithril network of `networks.json`, only the keys used by the guessing
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MithrilNetworkEntry {
    #[serde(default)]
    aggregators: Vec<AggregatorEntry>,
    era_reader: Option<ReaderAdapterEntry>,
    protocol_configuration_reader: Option<ReaderAdapterEntry>,
}

impl MithrilNetworkEntry {
    fn resolve(
        self,
        name: String,
        readers_configuration: Option<&ReadersConfiguration>,
    ) -> anyhow::Result<MithrilNetwork> {
        let era_reader = self
            .era_reader
            .map(|reader| {
                reader.resolve(
                    readers_configuration
                        .and_then(|configuration| configuration.era_reader.as_ref()),
                )
            })
            .transpose()
            .with_context(|| format!("Invalid era reader of '{name}'"))?;
        let protocol_configuration_reader =
            self.protocol_configuration_reader
                .map(|reader| {
                    reader.resolve(readers_configuration.and_then(|configuration| {
                        configuration.protocol_configuration_reader.as_ref()
                    }))
                })
                .transpose()
                .with_context(|| format!("Invalid protocol configuration reader of '{name}'"))?;

        Ok(MithrilNetwork {
            aggregator_endpoint: self
                .aggregators
                .into_iter()
                .next()
                .map(|aggregator| aggregator.url),
            era_reader,
            protocol_configuration_reader,
            name,
        })
    }
}

/// A reader adapter of `networks.json`, only its type: its configuration is given apart
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ReaderAdapterEntry {
    adapter_type: String,
}

impl ReaderAdapterEntry {
    fn resolve(self, configuration: Option<&ReaderConfiguration>) -> anyhow::Result<ReaderAdapter> {
        let configuration = configuration.ok_or_else(|| anyhow!("No configuration given"))?;

        Ok(ReaderAdapter {
            adapter_type: self.adapter_type,
            address: configuration.address.trim().to_string(),
            verification_key: configuration.verification_key.trim().to_string(),
        })
    }
}

/// An aggregator of `networks.json`
#[derive(Debug, Deserialize)]
struct AggregatorEntry {
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERA_ADDRESS: &str = "addr_test_era";
    const ERA_VERIFICATION_KEY: &str = "5b_era_vkey";
    const PROTOCOL_CONFIGURATION_ADDRESS: &str = "addr_test_protocol_config";
    const PROTOCOL_CONFIGURATION_VERIFICATION_KEY: &str = "5b_protocol_config_vkey";

    const NETWORKS_JSON: &str = r#"{
        "preview": {
            "cardano-minimum-version": { "mithril-signer": "10.7.1" },
            "mithril-networks": [
                {
                    "pre-release-preview": {
                        "aggregators": [
                            { "url": "https://aggregator.pre-release-preview.example.com/aggregator" },
                            { "url": "https://second-aggregator.example.com/aggregator" }
                        ],
                        "era-reader": {
                            "adapter-type": "cardano-chain",
                            "address": { "url": "https://example.com/pre-release-preview/era.addr" },
                            "verification-key": { "url": "https://example.com/pre-release-preview/era.vkey" }
                        },
                        "protocol-configuration-reader": {
                            "adapter-type": "cardano-chain",
                            "address": { "url": "https://example.com/pre-release-preview/protocol-config.addr" },
                            "verification-key": { "url": "https://example.com/pre-release-preview/protocol-config.vkey" }
                        }
                    }
                },
                {
                    "ivc-snark-preview": {
                        "aggregators": [
                            { "url": "https://aggregator.ivc-snark-preview.example.com/aggregator" }
                        ]
                    }
                }
            ]
        }
    }"#;

    /// Readers configuration of the Mithril networks of [NETWORKS_JSON], the era reader one
    /// ending with a new line like the embedded `.addr` and `.vkey` files may
    fn readers_configuration() -> HashMap<String, ReadersConfiguration> {
        HashMap::from([(
            "pre-release-preview".to_string(),
            ReadersConfiguration {
                era_reader: Some(ReaderConfiguration {
                    address: ERA_ADDRESS.to_string(),
                    verification_key: ERA_VERIFICATION_KEY.to_string(),
                }),
                protocol_configuration_reader: Some(ReaderConfiguration {
                    address: PROTOCOL_CONFIGURATION_ADDRESS.to_string(),
                    verification_key: PROTOCOL_CONFIGURATION_VERIFICATION_KEY.to_string(),
                }),
            },
        )])
    }

    fn mithril_networks() -> MithrilNetworks {
        MithrilNetworks::parse(NETWORKS_JSON, &readers_configuration()).unwrap()
    }

    fn names(networks: &[MithrilNetwork]) -> Vec<&str> {
        networks.iter().map(|network| network.name.as_str()).collect()
    }

    mod parse {
        use super::*;

        #[test]
        fn lists_the_mithril_networks_of_a_cardano_network_in_their_order() {
            let mithril_networks = mithril_networks();

            assert_eq!(
                vec!["pre-release-preview", "ivc-snark-preview"],
                names(mithril_networks.running_on(CardanoNetwork::Preview))
            );
        }

        #[test]
        fn reads_the_endpoint_of_the_first_aggregator() {
            let mithril_networks = mithril_networks();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[0];

            assert_eq!(
                Some("https://aggregator.pre-release-preview.example.com/aggregator".to_string()),
                network.aggregator_endpoint
            );
        }

        #[test]
        fn reads_the_era_reader_with_its_configuration() {
            let mithril_networks = mithril_networks();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[0];

            assert_eq!(
                Some(ReaderAdapter {
                    adapter_type: "cardano-chain".to_string(),
                    address: ERA_ADDRESS.to_string(),
                    verification_key: ERA_VERIFICATION_KEY.to_string(),
                }),
                network.era_reader
            );
        }

        #[test]
        fn reads_the_protocol_configuration_reader_with_its_configuration() {
            let mithril_networks = mithril_networks();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[0];

            assert_eq!(
                Some(ReaderAdapter {
                    adapter_type: "cardano-chain".to_string(),
                    address: PROTOCOL_CONFIGURATION_ADDRESS.to_string(),
                    verification_key: PROTOCOL_CONFIGURATION_VERIFICATION_KEY.to_string(),
                }),
                network.protocol_configuration_reader
            );
        }

        #[test]
        fn leaves_the_readers_absent_from_networks_json_unknown() {
            let mithril_networks = mithril_networks();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[1];

            assert_eq!(
                MithrilNetwork {
                    name: "ivc-snark-preview".to_string(),
                    aggregator_endpoint: Some(
                        "https://aggregator.ivc-snark-preview.example.com/aggregator".to_string()
                    ),
                    era_reader: None,
                    protocol_configuration_reader: None,
                },
                *network
            );
        }

        #[test]
        fn ignores_the_configuration_of_a_reader_not_declared_by_networks_json() {
            let mut readers_configuration = readers_configuration();
            readers_configuration.insert(
                "ivc-snark-preview".to_string(),
                ReadersConfiguration {
                    era_reader: Some(ReaderConfiguration {
                        address: ERA_ADDRESS.to_string(),
                        verification_key: ERA_VERIFICATION_KEY.to_string(),
                    }),
                    protocol_configuration_reader: None,
                },
            );

            let mithril_networks =
                MithrilNetworks::parse(NETWORKS_JSON, &readers_configuration).unwrap();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[1];
            assert_eq!(None, network.era_reader);
        }

        #[test]
        fn leaves_the_aggregator_endpoint_unknown_without_aggregator() {
            let mithril_networks = MithrilNetworks::parse(
                r#"{ "preview": { "mithril-networks": [ { "testing-preview": {} } ] } }"#,
                &HashMap::new(),
            )
            .unwrap();

            let network = &mithril_networks.running_on(CardanoNetwork::Preview)[0];

            assert_eq!(None, network.aggregator_endpoint);
        }

        #[test]
        fn lists_no_mithril_network_for_a_cardano_network_absent_from_networks_json() {
            let mithril_networks = mithril_networks();

            assert_eq!(
                Vec::<&str>::new(),
                names(mithril_networks.running_on(CardanoNetwork::Mainnet))
            );
            assert_eq!(
                Vec::<&str>::new(),
                names(mithril_networks.running_on(CardanoNetwork::Private(4)))
            );
        }

        #[test]
        fn fails_when_the_configuration_of_a_reader_declared_by_networks_json_is_not_given() {
            let mut readers_configuration = readers_configuration();
            readers_configuration
                .get_mut("pre-release-preview")
                .unwrap()
                .era_reader = None;

            let result = MithrilNetworks::parse(NETWORKS_JSON, &readers_configuration);

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[test]
        fn fails_when_no_readers_configuration_is_given_for_a_network_declaring_readers() {
            let result = MithrilNetworks::parse(NETWORKS_JSON, &HashMap::new());

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[test]
        fn fails_on_an_invalid_json() {
            let result = MithrilNetworks::parse("{ not json", &readers_configuration());

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }
    }

    mod select {
        use super::*;

        #[test]
        fn selects_the_first_mithril_network_by_default() {
            let mithril_networks = mithril_networks();

            let network = mithril_networks.select(CardanoNetwork::Preview, None);

            assert_eq!(
                Some("pre-release-preview"),
                network.map(|network| network.name.as_str())
            );
        }

        #[test]
        fn selects_the_mithril_network_with_the_given_name() {
            let mithril_networks = mithril_networks();

            let network =
                mithril_networks.select(CardanoNetwork::Preview, Some("ivc-snark-preview"));

            assert_eq!(
                Some("ivc-snark-preview"),
                network.map(|network| network.name.as_str())
            );
        }

        #[test]
        fn selects_nothing_for_a_name_not_running_on_the_cardano_network() {
            let mithril_networks = mithril_networks();

            let network = mithril_networks.select(CardanoNetwork::Preview, Some("release-mainnet"));

            assert_eq!(None, network);
        }

        #[test]
        fn selects_nothing_for_a_cardano_network_absent_from_networks_json() {
            let mithril_networks = mithril_networks();

            let network = mithril_networks.select(CardanoNetwork::Devnet, None);

            assert_eq!(None, network);
        }
    }

    mod embedded {
        use std::path::PathBuf;

        use super::*;

        /// Content of a file of the Mithril repository, trimmed
        fn repository_file(path: &str) -> String {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(path);

            std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("Could not read '{}': {error}", path.display()))
                .trim()
                .to_string()
        }

        #[test]
        fn embeds_the_mithril_networks_of_networks_json() {
            let mithril_networks = MithrilNetworks::embedded();

            for cardano_network in [
                CardanoNetwork::Mainnet,
                CardanoNetwork::Preprod,
                CardanoNetwork::Preview,
            ] {
                assert!(
                    !mithril_networks.running_on(cardano_network).is_empty(),
                    "Expected Mithril networks running on {}",
                    cardano_network.name()
                );
            }
        }

        #[test]
        fn embeds_the_readers_configuration_of_mithril_infra() {
            let mithril_networks = MithrilNetworks::embedded();

            let network = mithril_networks
                .select(CardanoNetwork::Mainnet, Some("release-mainnet"))
                .unwrap();

            assert_eq!(
                Some(ReaderAdapter {
                    adapter_type: "cardano-chain".to_string(),
                    address: repository_file(
                        "mithril-infra/configuration/release-mainnet/era.addr"
                    ),
                    verification_key: repository_file(
                        "mithril-infra/configuration/release-mainnet/era.vkey"
                    ),
                }),
                network.era_reader
            );
            assert_eq!(
                Some(ReaderAdapter {
                    adapter_type: "cardano-chain".to_string(),
                    address: repository_file(
                        "mithril-infra/configuration/release-mainnet/protocol-config.addr"
                    ),
                    verification_key: repository_file(
                        "mithril-infra/configuration/release-mainnet/protocol-config.vkey"
                    ),
                }),
                network.protocol_configuration_reader
            );
        }
    }
}
