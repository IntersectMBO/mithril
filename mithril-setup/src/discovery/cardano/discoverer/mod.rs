//! Discoverer of the Cardano node running on the machine

mod error;
mod node_files_facts;
mod node_selection;
#[cfg(test)]
mod test_doubles;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{debug, info};

use crate::discovery::cardano::command_line::NodeCommandLine;
use crate::discovery::cardano::host::{HostFileProbe, ProcfsProcessProbe};
use crate::discovery::cardano::{
    CardanoDiscovery, FileProbe, NodeInstance, NodeProcess, ProcessProbe,
};

pub use error::*;
use node_selection::select_node;

/// Discovers the facts of the Cardano block producer node through the given probes
pub struct CardanoDiscoverer {
    processes: Arc<dyn ProcessProbe>,
    files: Arc<dyn FileProbe>,
}

impl CardanoDiscoverer {
    /// Create a discoverer observing the runtime through the given probes
    pub fn new(processes: Arc<dyn ProcessProbe>, files: Arc<dyn FileProbe>) -> Self {
        Self { processes, files }
    }

    /// Create a discoverer observing the Linux host the setup runs on
    pub fn host() -> Self {
        Self::new(
            Arc::new(ProcfsProcessProbe::default()),
            Arc::new(HostFileProbe),
        )
    }

    /// Detect the Cardano node instances running as host processes
    pub async fn detect_nodes(&self) -> anyhow::Result<Vec<NodeInstance>> {
        let nodes = self.detect().await?;

        Ok(nodes.into_iter().map(|node| node.instance).collect())
    }

    /// Discover the facts of the Cardano node running on the machine
    ///
    /// The block producer is selected, or the only node running when it is not a block producer.
    pub async fn discover(&self) -> Result<CardanoDiscovery, CardanoDiscoveryError> {
        let (
            DetectedNode {
                instance,
                process,
                command_line,
            },
            role,
        ) = select_node(self.detect().await?)?;
        info!(
            pid = instance.pid,
            role = ?role,
            "Cardano node selected"
        );

        let resolve = |path: &str| resolve_path(process.working_dir.as_deref(), path);
        let config_file = command_line.config.as_deref().map(resolve);
        let topology_file = command_line.topology.as_deref().map(resolve);
        let shelley_genesis_file = self.shelley_genesis_file(config_file.as_deref()).await;
        let network = self.network(shelley_genesis_file.as_deref()).await;
        let pool_peers = self.pool_peers(topology_file.as_deref()).await;
        info!(
            network = ?network,
            pool_peers = pool_peers.len(),
            "Cardano node discovered"
        );

        Ok(CardanoDiscovery {
            node: instance,
            role,
            socket_path: command_line.socket_path.as_deref().map(resolve),
            database_dir: command_line.database_path.as_deref().map(resolve),
            config_file,
            topology_file,
            shelley_genesis_file,
            network,
            pool_peers,
            kes_key_path: command_line.kes_key.as_deref().map(resolve),
            operational_certificate_path: command_line
                .operational_certificate
                .as_deref()
                .map(resolve),
            kes_agent_socket: command_line.kes_agent_socket.as_deref().map(resolve),
            bulk_credentials_file: command_line.bulk_credentials_file.as_deref().map(resolve),
            service_user: process.user,
        })
    }

    async fn detect(&self) -> anyhow::Result<Vec<DetectedNode>> {
        let processes = self.processes.cardano_node_processes().await?;
        debug!(count = processes.len(), "Cardano node processes detected");

        let mut nodes = Vec::with_capacity(processes.len());
        for process in processes {
            let instance = NodeInstance { pid: process.pid };
            let command_line = NodeCommandLine::parse(&process.args);
            debug!(
                pid = instance.pid,
                block_producer = command_line.is_block_producer(),
                "Cardano node detected"
            );

            nodes.push(DetectedNode {
                instance,
                command_line,
                process,
            });
        }

        Ok(nodes)
    }
}

/// A running node with what is known about it
struct DetectedNode {
    instance: NodeInstance,
    process: NodeProcess,
    command_line: NodeCommandLine,
}

/// Resolve a path given on the node command line against the node working directory
fn resolve_path(working_dir: Option<&Path>, path: &str) -> PathBuf {
    match working_dir {
        Some(working_dir) => working_dir.join(path),
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::discovery::cardano::{CardanoNetwork, NodeRole, Peer};

    use super::test_doubles::*;
    use super::*;

    // The host discoverer reads the `/proc` filesystem, only available on Linux
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn host_discoverer_detects_the_nodes_running_on_the_machine() {
        let result = CardanoDiscoverer::host().detect_nodes().await;

        assert!(result.is_ok(), "Expected Ok, got {result:?}");
    }

    mod detect_nodes {
        use super::*;

        #[tokio::test]
        async fn returns_no_instance_when_no_node_is_running() {
            let discoverer = FakeProbes::default().discoverer();

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(Vec::<NodeInstance>::new(), nodes);
        }

        #[tokio::test]
        async fn detects_a_node_running_as_a_host_process() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &["run"])],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(vec![NodeInstance { pid: 42 }], nodes);
        }

        #[tokio::test]
        async fn detects_several_nodes() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &["run"]), node_process(43, &["run"])],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(
                vec![NodeInstance { pid: 42 }, NodeInstance { pid: 43 }],
                nodes
            );
        }

        #[tokio::test]
        async fn fails_when_the_processes_can_not_be_listed() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    fails: true,
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let result = discoverer.detect_nodes().await;

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }
    }

    mod collect_facts {
        use super::*;

        #[tokio::test]
        async fn collects_all_the_facts_of_the_block_producer() {
            let process = NodeProcess {
                user: Some("cardano".to_string()),
                ..block_producer_process(&[
                    "--socket-path",
                    "/opt/cardano/node.socket",
                    "--database-path",
                    "/opt/cardano/db",
                    "--config",
                    "/opt/cardano/config.json",
                    "--topology",
                    "/opt/cardano/topology.json",
                ])
            };

            let files = node_files(&[
                ("/opt/cardano/config.json", CONFIGURATION),
                ("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS),
                ("/opt/cardano/topology.json", TOPOLOGY),
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
                CardanoDiscovery {
                    node: NodeInstance { pid: 42 },
                    role: NodeRole::BlockProducer,
                    socket_path: Some(PathBuf::from("/opt/cardano/node.socket")),
                    database_dir: Some(PathBuf::from("/opt/cardano/db")),
                    config_file: Some(PathBuf::from("/opt/cardano/config.json")),
                    topology_file: Some(PathBuf::from("/opt/cardano/topology.json")),
                    shelley_genesis_file: Some(PathBuf::from("/opt/cardano/shelley/genesis.json")),
                    network: Some(CardanoNetwork::Preview),
                    pool_peers: vec![Peer {
                        address: "relay1.example.com".to_string(),
                        port: 3001,
                        advertised: None,
                        trustable: None,
                    }],
                    kes_key_path: Some(PathBuf::from("/opt/cardano/kes.skey")),
                    operational_certificate_path: Some(PathBuf::from("/opt/cardano/node.cert")),
                    kes_agent_socket: None,
                    bulk_credentials_file: None,
                    service_user: Some("cardano".to_string()),
                },
                discovery
            );
        }

        #[tokio::test]
        async fn leaves_the_facts_absent_from_the_command_line_undiscovered() {
            let discovery = discover(block_producer_process(&[]), FakeProbes::default()).await;

            assert_eq!(None, discovery.socket_path);
            assert_eq!(None, discovery.database_dir);
            assert_eq!(None, discovery.config_file);
            assert_eq!(None, discovery.topology_file);
            assert_eq!(None, discovery.service_user);
            assert_eq!(None, discovery.shelley_genesis_file);
            assert_eq!(None, discovery.network);
            assert_eq!(Vec::<Peer>::new(), discovery.pool_peers);
        }

        #[tokio::test]
        async fn resolves_relative_paths_against_the_working_directory() {
            let process = NodeProcess {
                working_dir: Some(PathBuf::from("/home/cardano")),
                ..node_process(
                    42,
                    &[
                        "run",
                        "--shelley-kes-key",
                        "keys/kes.skey",
                        "--shelley-operational-certificate",
                        "keys/node.cert",
                        "--socket-path",
                        "db/node.socket",
                        "--database-path",
                        "db",
                        "--config",
                        "./config.json",
                        "--topology",
                        "/etc/cardano/topology.json",
                    ],
                )
            };

            let discovery = discover(process, FakeProbes::default()).await;

            assert_eq!(
                Some(PathBuf::from("/home/cardano/keys/kes.skey")),
                discovery.kes_key_path
            );
            assert_eq!(
                Some(PathBuf::from("/home/cardano/keys/node.cert")),
                discovery.operational_certificate_path
            );
            assert_eq!(
                Some(PathBuf::from("/home/cardano/db/node.socket")),
                discovery.socket_path
            );
            assert_eq!(
                Some(PathBuf::from("/home/cardano/db")),
                discovery.database_dir
            );
            assert_eq!(
                Some(PathBuf::from("/home/cardano/./config.json")),
                discovery.config_file
            );
            assert_eq!(
                Some(PathBuf::from("/etc/cardano/topology.json")),
                discovery.topology_file
            );
        }

        #[tokio::test]
        async fn keeps_relative_paths_when_the_working_directory_is_unknown() {
            let process = node_process(
                42,
                &[
                    "run",
                    "--shelley-kes-key",
                    "keys/kes.skey",
                    "--shelley-operational-certificate",
                    "keys/node.cert",
                ],
            );

            let discovery = discover(process, FakeProbes::default()).await;

            assert_eq!(Some(PathBuf::from("keys/kes.skey")), discovery.kes_key_path);
            assert_eq!(
                Some(PathBuf::from("keys/node.cert")),
                discovery.operational_certificate_path
            );
        }
    }
}
