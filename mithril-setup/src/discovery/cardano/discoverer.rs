//! Discoverer of the Cardano node running on the machine

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::discovery::cardano::command_line::NodeCommandLine;
use crate::discovery::cardano::host::{CgroupServiceProbe, HostFileProbe, ProcfsProcessProbe};
use crate::discovery::cardano::node_files::{
    CardanoConfiguration, CardanoNetwork, Peer, ShelleyGenesisConfiguration, TopologyConfiguration,
};
use crate::discovery::cardano::{
    CardanoDiscovery, FileProbe, NodeInstance, NodeProcess, NodeRole, ProcessProbe, ServiceProbe,
};

/// Reasons why the Cardano block producer node could not be discovered
#[derive(Debug, thiserror::Error)]
pub enum CardanoDiscoveryError {
    /// No Cardano node is running on the machine
    #[error("No running Cardano node found")]
    NoCardanoNode,

    /// Several Cardano nodes are running, but none of them is a block producer
    #[error("No running Cardano block producer node found among the running nodes: {nodes:?}")]
    NoBlockProducer {
        /// The running nodes
        nodes: Vec<NodeInstance>,
    },

    /// Several Cardano block producer nodes are running, the one to use can't be chosen
    #[error("Several running Cardano block producer nodes found: {nodes:?}")]
    SeveralBlockProducers {
        /// The running block producer nodes
        nodes: Vec<NodeInstance>,
    },

    /// The running block producer node is not handled by Mithril
    #[error("The running Cardano block producer is not handled by Mithril: {node:?} {reason}")]
    BlockProducerNotHandled {
        /// The running block producer node
        node: NodeInstance,

        /// Reason
        reason: String,
    },

    /// A probe failed to observe the machine
    #[error("Cardano node discovery failed")]
    Probe(#[from] anyhow::Error),
}

/// Discovers the facts of the Cardano block producer node through the given probes
pub struct CardanoDiscoverer {
    processes: Arc<dyn ProcessProbe>,
    services: Arc<dyn ServiceProbe>,
    files: Arc<dyn FileProbe>,
}

impl CardanoDiscoverer {
    /// Create a discoverer observing the runtime through the given probes
    pub fn new(
        processes: Arc<dyn ProcessProbe>,
        services: Arc<dyn ServiceProbe>,
        files: Arc<dyn FileProbe>,
    ) -> Self {
        Self {
            processes,
            services,
            files,
        }
    }

    /// Create a discoverer observing the Linux host the setup runs on
    pub fn host() -> Self {
        Self::new(
            Arc::new(ProcfsProcessProbe::default()),
            Arc::new(CgroupServiceProbe::default()),
            Arc::new(HostFileProbe),
        )
    }

    /// Detect the Cardano node instances running as host processes or systemd services
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
            systemd_unit = ?instance.systemd_unit,
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

    /// Path of the Shelley genesis file, read from the node configuration file
    async fn shelley_genesis_file(&self, config_file: Option<&Path>) -> Option<PathBuf> {
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
    async fn network(&self, shelley_genesis_file: Option<&Path>) -> Option<CardanoNetwork> {
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
    async fn pool_peers(&self, topology_file: Option<&Path>) -> Vec<Peer> {
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

    async fn detect(&self) -> anyhow::Result<Vec<DetectedNode>> {
        let processes = self.processes.cardano_node_processes().await?;
        debug!(count = processes.len(), "Cardano node processes detected");

        let mut nodes = Vec::with_capacity(processes.len());
        for process in processes {
            let instance = NodeInstance {
                pid: process.pid,
                systemd_unit: self.services.systemd_unit_of(process.pid).await?,
            };
            let command_line = NodeCommandLine::parse(&process.args);
            debug!(
                pid = instance.pid,
                systemd_unit = ?instance.systemd_unit,
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

/// Select the block producer, or the only node running when it is not a block producer
fn select_node(
    nodes: Vec<DetectedNode>,
) -> Result<(DetectedNode, NodeRole), CardanoDiscoveryError> {
    if nodes.is_empty() {
        return Err(CardanoDiscoveryError::NoCardanoNode);
    }

    let (mut block_producers, other_nodes): (Vec<_>, Vec<_>) = nodes
        .into_iter()
        .partition(|node| node.command_line.is_block_producer());
    let (mut non_producing_nodes, mut relays): (Vec<_>, Vec<_>) = other_nodes
        .into_iter()
        .partition(|node| node.command_line.is_a_non_producing_node());

    match block_producers.len() {
        // No block producer, one relay
        0 if non_producing_nodes.is_empty() && relays.len() == 1 => {
            Ok((relays.remove(0), NodeRole::Relay))
        },
        // No block producer, and non producing node(s)
        0 if !non_producing_nodes.is_empty() => Err(CardanoDiscoveryError::BlockProducerNotHandled {
            node: non_producing_nodes.remove(0).instance,
            reason: "The node is started as a non-producing node, run the setup beside the active block producer"
                .to_string(),
        }),
        // No block producer
        0 => Err(CardanoDiscoveryError::NoBlockProducer {
            nodes: non_producing_nodes
                .into_iter()
                .chain(relays)
                .map(|node| node.instance)
                .collect(),
        }),
        // One block producer
        1 => {
            let node = block_producers.remove(0);
            if node.command_line.is_using_kes_agent()
                && !node.command_line.has_kes_key_and_operational_certificate()
            {
                return Err(CardanoDiscoveryError::BlockProducerNotHandled {
                    node: node.instance,
                    reason: "The node is using a KES agent, use KES keys instead".to_string(),
                });
            }
            if node.command_line.is_using_bulk_credentials() {
                return Err(CardanoDiscoveryError::BlockProducerNotHandled {
                    node: node.instance,
                    reason: "The node is using a bulk credentials file, use KES keys instead"
                        .to_string(),
                });
            }
            Ok((node, NodeRole::BlockProducer))
        }
        // Several block producers
        _ => Err(CardanoDiscoveryError::SeveralBlockProducers {
            nodes: block_producers.into_iter().map(|node| node.instance).collect(),
        }),
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use anyhow::anyhow;
    use async_trait::async_trait;

    use crate::discovery::cardano::{NodeProcess, ProcessOwner};
    use crate::test_tools::logs::capture_logs;

    use super::*;

    #[derive(Default)]
    pub struct FakeProcessProbe {
        processes: Vec<NodeProcess>,
        fails: bool,
    }

    #[async_trait]
    impl ProcessProbe for FakeProcessProbe {
        async fn cardano_node_processes(&self) -> anyhow::Result<Vec<NodeProcess>> {
            if self.fails {
                return Err(anyhow!("process listing failed"));
            }
            Ok(self.processes.clone())
        }
    }

    #[derive(Default)]
    pub struct FakeServiceProbe {
        units: HashMap<u32, String>,
    }

    #[async_trait]
    impl ServiceProbe for FakeServiceProbe {
        async fn systemd_unit_of(&self, pid: u32) -> anyhow::Result<Option<String>> {
            Ok(self.units.get(&pid).cloned())
        }
    }

    #[derive(Default)]
    pub struct FakeFileProbe {
        files: HashMap<PathBuf, String>,
    }

    #[async_trait]
    impl FileProbe for FakeFileProbe {
        async fn read_to_string(&self, path: &Path) -> anyhow::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow!("file not found: {}", path.display()))
        }
    }

    fn node_process(pid: u32, args: &[&str]) -> NodeProcess {
        NodeProcess {
            pid,
            executable: Some(PathBuf::from("/usr/local/bin/cardano-node")),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            working_dir: None,
            user: None,
            owner: Some(NODE_OWNER),
        }
    }

    const NODE_OWNER: ProcessOwner = ProcessOwner {
        uid: 1001,
        gid: 1001,
    };

    /// Fake probes of a discoverer under test, each test only sets the probes it needs
    #[derive(Default)]
    struct FakeProbes {
        processes: FakeProcessProbe,
        services: FakeServiceProbe,
        files: FakeFileProbe,
    }

    impl FakeProbes {
        fn discoverer(self) -> CardanoDiscoverer {
            CardanoDiscoverer::new(
                Arc::new(self.processes),
                Arc::new(self.services),
                Arc::new(self.files),
            )
        }
    }

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

            assert_eq!(
                vec![NodeInstance {
                    pid: 42,
                    systemd_unit: None
                }],
                nodes
            );
        }

        #[tokio::test]
        async fn detects_a_node_running_as_a_systemd_service() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &["run"])],
                    ..Default::default()
                },
                services: FakeServiceProbe {
                    units: HashMap::from([(42, "cardano-node.service".to_string())]),
                },
                ..Default::default()
            }
            .discoverer();

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(
                vec![NodeInstance {
                    pid: 42,
                    systemd_unit: Some("cardano-node.service".to_string())
                }],
                nodes
            );
        }

        #[tokio::test]
        async fn detects_several_nodes() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &["run"]), node_process(43, &["run"])],
                    ..Default::default()
                },
                services: FakeServiceProbe {
                    units: HashMap::from([(43, "relay.service".to_string())]),
                },
                ..Default::default()
            }
            .discoverer();

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(
                vec![
                    NodeInstance {
                        pid: 42,
                        systemd_unit: None
                    },
                    NodeInstance {
                        pid: 43,
                        systemd_unit: Some("relay.service".to_string())
                    }
                ],
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

    const BLOCK_PRODUCER_ARGS: [&str; 5] = [
        "run",
        "--shelley-kes-key",
        "/opt/cardano/kes.skey",
        "--shelley-operational-certificate",
        "/opt/cardano/node.cert",
    ];

    mod select_node {
        use super::*;

        #[tokio::test]
        async fn fails_when_no_node_is_running() {
            let discoverer = FakeProbes::default().discoverer();

            let result = discoverer.discover().await;

            assert!(
                matches!(result, Err(CardanoDiscoveryError::NoCardanoNode)),
                "Expected NoCardanoNode, got {result:?}"
            );
        }

        #[tokio::test]
        async fn fails_when_several_relays_are_running_without_block_producer() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![
                        node_process(42, &["run", "--port", "3001"]),
                        node_process(43, &["run", "--port", "3002"]),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let result = discoverer.discover().await;

            match result {
                Err(CardanoDiscoveryError::NoBlockProducer { nodes }) => {
                    let pids: Vec<u32> = nodes.iter().map(|node| node.pid).collect();
                    assert_eq!(vec![42, 43], pids);
                }
                _ => panic!("Expected NoBlockProducer, got {result:?}"),
            }
        }

        #[tokio::test]
        async fn selects_the_only_running_node_as_a_relay_when_it_is_not_a_block_producer() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &["run", "--port", "3001"])],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(42, discovery.node.pid);
            assert_eq!(NodeRole::Relay, discovery.role);
        }

        #[tokio::test]
        async fn fails_when_several_block_producers_are_running() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![
                        node_process(42, &BLOCK_PRODUCER_ARGS),
                        node_process(43, &["run"]),
                        node_process(44, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let result = discoverer.discover().await;

            match result {
                Err(CardanoDiscoveryError::SeveralBlockProducers { nodes }) => {
                    let pids: Vec<u32> = nodes.iter().map(|node| node.pid).collect();
                    assert_eq!(vec![42, 44], pids);
                }
                _ => panic!("Expected SeveralBlockProducers, got {result:?}"),
            }
        }

        #[tokio::test]
        async fn fails_when_block_producer_is_using_kes_agent() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(
                        42,
                        &["run", "--shelley-kes-agent-socket", "/opt/cardano/kes-agent.socket"],
                    )],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();
            let result = discoverer.discover().await;
            match result {
                Err(CardanoDiscoveryError::BlockProducerNotHandled { node, reason }) => {
                    assert_eq!(42, node.pid);
                    assert_eq!(
                        "The node is using a KES agent, use KES keys instead",
                        reason
                    );
                }
                _ => panic!("Expected BlockProducerNotHandled, got {result:?}"),
            }
        }

        #[tokio::test]
        async fn selects_a_block_producer_given_kes_keys_besides_a_kes_agent() {
            let args: Vec<&str> = BLOCK_PRODUCER_ARGS
                .iter()
                .copied()
                .chain(["--shelley-kes-agent-socket", "/opt/cardano/kes-agent.socket"])
                .collect();
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &args)],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(NodeRole::BlockProducer, discovery.role);
            assert_eq!(
                Some(PathBuf::from("/opt/cardano/kes-agent.socket")),
                discovery.kes_agent_socket
            );
        }

        #[tokio::test]
        async fn fails_when_block_producer_is_using_a_bulk_credentials_file() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(
                        42,
                        &["run", "--bulk-credentials-file", "/opt/cardano/bulk.creds"],
                    )],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let result = discoverer.discover().await;

            match result {
                Err(CardanoDiscoveryError::BlockProducerNotHandled { node, reason }) => {
                    assert_eq!(42, node.pid);
                    assert_eq!(
                        "The node is using a bulk credentials file, use KES keys instead",
                        reason
                    );
                }
                _ => panic!("Expected BlockProducerNotHandled, got {result:?}"),
            }
        }

        #[tokio::test]
        async fn selects_a_block_producer_given_kes_keys_besides_a_bulk_credentials_file() {
            let args: Vec<&str> = BLOCK_PRODUCER_ARGS
                .iter()
                .copied()
                .chain(["--bulk-credentials-file", "/opt/cardano/bulk.creds"])
                .collect();
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![node_process(42, &args)],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(NodeRole::BlockProducer, discovery.role);
            assert_eq!(
                Some(PathBuf::from("/opt/cardano/bulk.creds")),
                discovery.bulk_credentials_file
            );
        }

        #[tokio::test]
        async fn selects_the_block_producer_among_relays() {
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![
                        node_process(42, &["run"]),
                        node_process(43, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                services: FakeServiceProbe {
                    units: HashMap::from([(43, "cardano-bp.service".to_string())]),
                },
                ..Default::default()
            }
            .discoverer();

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(
                NodeInstance {
                    pid: 43,
                    systemd_unit: Some("cardano-bp.service".to_string())
                },
                discovery.node
            );
            assert_eq!(NodeRole::BlockProducer, discovery.role);
            assert_eq!(
                Some(PathBuf::from("/opt/cardano/kes.skey")),
                discovery.kes_key_path
            );
            assert_eq!(
                Some(PathBuf::from("/opt/cardano/node.cert")),
                discovery.operational_certificate_path
            );
        }

        #[tokio::test]
        async fn ignores_a_node_started_as_non_producing() {
            let standby_args: Vec<&str> = BLOCK_PRODUCER_ARGS
                .iter()
                .copied()
                .chain(["--start-as-non-producing-node"])
                .collect();
            let discoverer = FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![
                        node_process(42, &standby_args),
                        node_process(43, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer();

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(43, discovery.node.pid);
        }

        async fn discover_among(
            processes: Vec<NodeProcess>,
        ) -> Result<CardanoDiscovery, CardanoDiscoveryError> {
            FakeProbes {
                processes: FakeProcessProbe {
                    processes,
                    ..Default::default()
                },
                ..Default::default()
            }
            .discoverer()
            .discover()
            .await
        }

        fn assert_non_producing_node_not_handled(
            result: Result<CardanoDiscovery, CardanoDiscoveryError>,
            expected_pid: u32,
        ) {
            match result {
                Err(CardanoDiscoveryError::BlockProducerNotHandled { node, reason }) => {
                    assert_eq!(expected_pid, node.pid);
                    assert_eq!(
                        "The node is started as a non-producing node, run the setup beside the active block producer",
                        reason
                    );
                }
                _ => panic!("Expected BlockProducerNotHandled, got {result:?}"),
            }
        }

        #[tokio::test]
        async fn fails_when_the_only_running_node_is_started_as_non_producing_with_credentials() {
            let standby_args: Vec<&str> = BLOCK_PRODUCER_ARGS
                .iter()
                .copied()
                .chain(["--start-as-non-producing-node"])
                .collect();

            let result = discover_among(vec![node_process(42, &standby_args)]).await;

            assert_non_producing_node_not_handled(result, 42);
        }

        #[tokio::test]
        async fn fails_when_the_only_running_node_is_started_as_non_producing_without_credentials()
        {
            let result = discover_among(vec![node_process(
                42,
                &["run", "--start-as-non-producing-node"],
            )])
            .await;

            assert_non_producing_node_not_handled(result, 42);
        }

        #[tokio::test]
        async fn fails_on_the_non_producing_node_when_it_runs_beside_a_relay_without_block_producer()
         {
            let result = discover_among(vec![
                node_process(42, &["run"]),
                node_process(43, &["run", "--start-as-non-producing-node"]),
            ])
            .await;

            assert_non_producing_node_not_handled(result, 43);
        }

        #[tokio::test]
        async fn fails_on_the_first_non_producing_node_when_several_run_without_block_producer() {
            let result = discover_among(vec![
                node_process(42, &["run", "--start-as-non-producing-node"]),
                node_process(43, &["run", "--non-producing-node"]),
            ])
            .await;

            assert_non_producing_node_not_handled(result, 42);
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

            let result = discoverer.discover().await;

            assert!(
                matches!(result, Err(CardanoDiscoveryError::Probe(_))),
                "Expected Probe error, got {result:?}"
            );
        }
    }

    mod collect_facts {
        use crate::discovery::cardano::{CardanoNetwork, Peer};

        use super::*;

        fn block_producer_process(extra_args: &[&str]) -> NodeProcess {
            let args: Vec<&str> = BLOCK_PRODUCER_ARGS.iter().chain(extra_args).copied().collect();
            node_process(42, &args)
        }

        const CONFIGURATION: &str = "ShelleyGenesisFile: shelley/genesis.json\n";

        const PREVIEW_GENESIS: &str = r#"{ "networkId": "Testnet", "networkMagic": 2 }"#;

        const TOPOLOGY: &str = r#"{
            "localRoots": [{ "accessPoints": [{ "address": "relay1.example.com", "port": 3001 }] }],
            "publicRoots": [{ "accessPoints": [{ "address": "backbone.cardano.iog.io", "port": 3001 }] }]
        }"#;

        fn node_files(files: &[(&str, &str)]) -> FakeFileProbe {
            FakeFileProbe {
                files: files
                    .iter()
                    .map(|(path, content)| (PathBuf::from(path), content.to_string()))
                    .collect(),
            }
        }

        /// Discover the given block producer process, observed through the other given probes
        async fn discover(process: NodeProcess, probes: FakeProbes) -> CardanoDiscovery {
            FakeProbes {
                processes: FakeProcessProbe {
                    processes: vec![process],
                    ..Default::default()
                },
                services: FakeServiceProbe {
                    units: HashMap::from([(42, "cardano-node.service".to_string())]),
                },
                ..probes
            }
            .discoverer()
            .discover()
            .await
            .unwrap()
        }

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
                    node: NodeInstance {
                        pid: 42,
                        systemd_unit: Some("cardano-node.service".to_string())
                    },
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
                discover_with_files(&[("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS)])
                    .await;

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
            let discovery =
                discover_with_files(&[("/opt/cardano/config.json", CONFIGURATION)]).await;

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
            let discovery =
                discover_with_files(&[("/opt/cardano/topology.json", "{ not json")]).await;

            assert_eq!(Vec::<Peer>::new(), discovery.pool_peers);
            assert!(
                logs.contains_log("Invalid topology file"),
                "{:?}",
                logs.search_logs("")
            );
        }
    }
}
