//! Facts of the Cardano node read from its files: configuration, Shelley genesis and topology

use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use crate::discovery::cardano::CardanoDiscoverer;
use crate::discovery::cardano::node_files::{
    CardanoConfiguration, Peer, ShelleyGenesisConfiguration, TopologyConfiguration,
};
use crate::guessing::CardanoNetwork;

impl CardanoDiscoverer {
    /// Path of the Shelley genesis file, read from the node configuration file
    pub(super) async fn shelley_genesis_file(&self, config_file: Option<&Path>) -> Option<PathBuf> {
        let Some(config_file) = config_file else {
            debug!(
                "No configuration file on the node command line, the Shelley genesis file is unknown"
            );
            return None;
        };

        let content = self
            .files
            .read_to_string(config_file)
            .await
            .inspect_err(|error| {
                warn!(
                    path = %config_file.display(),
                    error = %format_args!("{error:#}"),
                    "Could not read the node configuration file, the Shelley genesis file is unknown"
                )
            })
            .ok()?;
        let configuration = CardanoConfiguration::parse(&content)
            .inspect_err(|error| {
                warn!(
                    path = %config_file.display(),
                    error = %format_args!("{error:#}"),
                    "Invalid node configuration file, the Shelley genesis file is unknown"
                )
            })
            .ok()?;

        let shelley_genesis_file = configuration.shelley_genesis_path(config_file);
        if shelley_genesis_file.is_none() {
            debug!(
                path = %config_file.display(),
                "No Shelley genesis file in the node configuration"
            );
        }
        shelley_genesis_file
    }

    /// Network identified by the magic of the Shelley genesis
    pub(super) async fn network(
        &self,
        shelley_genesis_file: Option<&Path>,
    ) -> Option<CardanoNetwork> {
        // An unknown genesis file was already logged while looking for it
        let shelley_genesis_file = shelley_genesis_file?;

        let content = self
            .files
            .read_to_string(shelley_genesis_file)
            .await
            .inspect_err(|error| {
                warn!(
                    path = %shelley_genesis_file.display(),
                    error = %format_args!("{error:#}"),
                    "Could not read the Shelley genesis file, the network is unknown"
                )
            })
            .ok()?;
        let network = ShelleyGenesisConfiguration::parse(&content)
            .inspect_err(|error| {
                warn!(
                    path = %shelley_genesis_file.display(),
                    error = %format_args!("{error:#}"),
                    "Invalid Shelley genesis file, the network is unknown"
                )
            })
            .ok()?
            .network();

        debug!(network = ?network, "Cardano network identified");
        Some(network)
    }

    /// Peers of the pool read from the node topology file, none when it can't be read
    pub(super) async fn pool_peers(&self, topology_file: Option<&Path>) -> Vec<Peer> {
        let Some(topology_file) = topology_file else {
            debug!("No topology file on the node command line, the pool peers are unknown");
            return Vec::new();
        };

        let content = match self.files.read_to_string(topology_file).await {
            Ok(content) => content,
            Err(error) => {
                warn!(
                    path = %topology_file.display(),
                    error = %format_args!("{error:#}"),
                    "Could not read the topology file, the pool peers are unknown"
                );
                return Vec::new();
            }
        };

        match TopologyConfiguration::parse(&content) {
            Ok(topology) => {
                let pool_peers = topology.pool_peers();
                debug!(
                    count = pool_peers.len(),
                    "Pool peers read from the topology"
                );
                pool_peers
            }
            Err(error) => {
                warn!(
                    path = %topology_file.display(),
                    error = %format_args!("{error:#}"),
                    "Invalid topology file, the pool peers are unknown"
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::discovery::cardano::{CardanoDiscovery, NodeProcess, Peer};
    use crate::guessing::CardanoNetwork;
    use crate::test_tools::logs::capture_logs;

    use super::super::test_doubles::*;

    fn process_with_node_files() -> NodeProcess {
        block_producer_process(&[
            "--config",
            "/opt/cardano/config.json",
            "--topology",
            "/opt/cardano/topology.json",
        ])
    }
    async fn discover_with_files(files: &[(&str, &str)]) -> CardanoDiscovery {
        discover(
            process_with_node_files(),
            FakeProbes {
                files: node_files(files),
                ..Default::default()
            },
        )
        .await
    }

    #[tokio::test]
    async fn resolves_the_shelley_genesis_file_from_a_relative_configuration_path() {
        let process = NodeProcess {
            working_dir: Some(PathBuf::from("/home/cardano")),
            ..block_producer_process(&["--config", "config/config.yml"])
        };
        let files = node_files(&[
            ("/home/cardano/config/config.yml", CONFIGURATION),
            ("/home/cardano/config/shelley/genesis.json", PREVIEW_GENESIS),
        ]);

        let discovery = discover(
            process,
            FakeProbes {
                files,
                ..Default::default()
            },
        )
        .await;

        assert_eq!(
            Some(PathBuf::from("/home/cardano/config/shelley/genesis.json")),
            discovery.shelley_genesis_file
        );
        assert_eq!(Some(CardanoNetwork::Preview), discovery.network);
    }

    #[tokio::test]
    async fn leaves_the_network_undiscovered_when_the_configuration_can_not_be_read() {
        let logs = capture_logs();
        let discovery =
            discover_with_files(&[("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS)]).await;

        assert_eq!(None, discovery.shelley_genesis_file);
        assert_eq!(None, discovery.network);
        assert!(
            logs.contains_log("Could not read the node configuration file"),
            "{:?}",
            logs.search_logs("")
        );
    }

    #[tokio::test]
    async fn leaves_the_network_undiscovered_when_the_configuration_is_invalid() {
        let discovery = discover_with_files(&[
            ("/opt/cardano/config.json", "{ not: [valid"),
            ("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS),
        ])
        .await;

        assert_eq!(None, discovery.shelley_genesis_file);
        assert_eq!(None, discovery.network);
    }

    #[tokio::test]
    async fn leaves_the_network_undiscovered_when_the_configuration_has_no_shelley_genesis() {
        let discovery = discover_with_files(&[
            ("/opt/cardano/config.json", "Protocol: Cardano"),
            ("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS),
        ])
        .await;

        assert_eq!(None, discovery.shelley_genesis_file);
        assert_eq!(None, discovery.network);
    }

    #[tokio::test]
    async fn keeps_the_shelley_genesis_file_when_the_genesis_can_not_be_read() {
        let discovery = discover_with_files(&[("/opt/cardano/config.json", CONFIGURATION)]).await;

        assert_eq!(
            Some(PathBuf::from("/opt/cardano/shelley/genesis.json")),
            discovery.shelley_genesis_file
        );
        assert_eq!(None, discovery.network);
    }

    #[tokio::test]
    async fn keeps_the_shelley_genesis_file_when_the_genesis_is_invalid() {
        let discovery = discover_with_files(&[
            ("/opt/cardano/config.json", CONFIGURATION),
            ("/opt/cardano/shelley/genesis.json", "{ not json"),
        ])
        .await;

        assert_eq!(
            Some(PathBuf::from("/opt/cardano/shelley/genesis.json")),
            discovery.shelley_genesis_file
        );
        assert_eq!(None, discovery.network);
    }

    #[tokio::test]
    async fn has_no_pool_peers_when_the_topology_can_not_be_read() {
        let discovery = discover_with_files(&[]).await;

        assert_eq!(Vec::<Peer>::new(), discovery.pool_peers);
    }

    #[tokio::test]
    async fn has_no_pool_peers_when_the_topology_is_invalid() {
        let logs = capture_logs();
        let discovery = discover_with_files(&[("/opt/cardano/topology.json", "{ not json")]).await;

        assert_eq!(Vec::<Peer>::new(), discovery.pool_peers);
        assert!(
            logs.contains_log("Invalid topology file"),
            "{:?}",
            logs.search_logs("")
        );
    }
}
