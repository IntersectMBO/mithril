//! Discoverer of the Cardano node running on the machine

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::discovery::cardano::command_line::NodeCommandLine;
use crate::discovery::cardano::host::{
    CgroupServiceProbe, HostFileProbe, HostToolProbe, ProcfsProcessProbe,
};
use crate::discovery::cardano::node_files::{
    CardanoConfiguration, CardanoNetwork, Peer, ShelleyGenesisConfiguration, TopologyConfiguration,
};
use crate::discovery::cardano::{
    CardanoDiscovery, FileProbe, ListeningAddress, NodeInstance, NodeProcess, NodeRole,
    ProcessProbe, ServiceProbe, ToolProbe,
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
    tools: Arc<dyn ToolProbe>,
    files: Arc<dyn FileProbe>,
}

impl CardanoDiscoverer {
    /// Create a discoverer observing the runtime through the given probes
    pub fn new(
        processes: Arc<dyn ProcessProbe>,
        services: Arc<dyn ServiceProbe>,
        tools: Arc<dyn ToolProbe>,
        files: Arc<dyn FileProbe>,
    ) -> Self {
        Self {
            processes,
            services,
            tools,
            files,
        }
    }

    /// Create a discoverer observing the Linux host the setup runs on
    pub fn host() -> Self {
        Self::new(
            Arc::new(ProcfsProcessProbe::default()),
            Arc::new(CgroupServiceProbe::default()),
            Arc::new(HostToolProbe::from_env()),
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
        let resolve = |path: &str| resolve_path(process.working_dir.as_deref(), path);
        let config_file = command_line.config.as_deref().map(resolve);
        let topology_file = command_line.topology.as_deref().map(resolve);
        let shelley_genesis_file = self.shelley_genesis_file(config_file.as_deref()).await;
        let network = self.network(shelley_genesis_file.as_deref()).await;
        let pool_peers = self.pool_peers(topology_file.as_deref()).await;

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
            listening_address: ListeningAddress {
                ipv4: command_line.host_addr.as_deref().and_then(|addr| addr.parse().ok()),
                ipv6: command_line
                    .host_ipv6_addr
                    .as_deref()
                    .and_then(|addr| addr.parse().ok()),
                port: command_line.port.as_deref().and_then(|port| port.parse().ok()),
            },
            node_version: self.node_version(&process).await,
            cardano_cli_path: self
                .tools
                .find_cardano_cli(process.executable.as_deref())
                .await
                .ok()
                .flatten(),
            service_user: process.user,
        })
    }

    /// The node binary is only run with the identity of the node process, it is not run at all
    /// when that identity is unknown
    async fn node_version(&self, process: &NodeProcess) -> Option<String> {
        let output = self
            .tools
            .node_version_output(process.executable.as_deref()?, process.owner?)
            .await
            .ok()?;

        parse_node_version(&output)
    }

    /// Path of the Shelley genesis file, read from the node configuration file
    async fn shelley_genesis_file(&self, config_file: Option<&Path>) -> Option<PathBuf> {
        let config_file = config_file?;
        let content = self.files.read_to_string(config_file).await.ok()?;

        CardanoConfiguration::parse(&content)
            .ok()?
            .shelley_genesis_path(config_file)
    }

    /// Network identified by the magic of the Shelley genesis
    async fn network(&self, shelley_genesis_file: Option<&Path>) -> Option<CardanoNetwork> {
        let content = self.files.read_to_string(shelley_genesis_file?).await.ok()?;

        Some(ShelleyGenesisConfiguration::parse(&content).ok()?.network())
    }

    /// Peers of the pool read from the node topology file, none when it can't be read
    async fn pool_peers(&self, topology_file: Option<&Path>) -> Vec<Peer> {
        let Some(topology_file) = topology_file else {
            return Vec::new();
        };

        match self.files.read_to_string(topology_file).await {
            Ok(content) => TopologyConfiguration::parse(&content)
                .map(|topology| topology.pool_peers())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    async fn detect(&self) -> anyhow::Result<Vec<DetectedNode>> {
        let processes = self.processes.cardano_node_processes().await?;

        let mut nodes = Vec::with_capacity(processes.len());
        for process in processes {
            nodes.push(DetectedNode {
                instance: NodeInstance {
                    pid: process.pid,
                    systemd_unit: self.services.systemd_unit_of(process.pid).await?,
                },
                command_line: NodeCommandLine::parse(&process.args),
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

/// Extract the version from a `cardano-node --version` output,
/// ie: `cardano-node 10.1.4 - linux-x86_64 - ghc-9.6`
fn parse_node_version(output: &str) -> Option<String> {
    let mut words = output.lines().next()?.split_whitespace();

    match (words.next(), words.next()) {
        (Some("cardano-node"), Some(version)) => Some(version.to_string()),
        _ => None,
    }
}

/// Select the block producer, or the only node running when it is not a block producer
fn select_node(
    nodes: Vec<DetectedNode>,
) -> Result<(DetectedNode, NodeRole), CardanoDiscoveryError> {
    if nodes.is_empty() {
        return Err(CardanoDiscoveryError::NoCardanoNode);
    }

    let (mut block_producers, mut relays): (Vec<_>, Vec<_>) = nodes
        .into_iter()
        .partition(|node| node.command_line.is_block_producer());

    match block_producers.len() {
        // No block producer, One relay
        0 if relays.len() == 1 => Ok((relays.remove(0), NodeRole::Relay)),
        // No block producer
        0 => Err(CardanoDiscoveryError::NoBlockProducer {
            nodes: relays.into_iter().map(|node| node.instance).collect(),
        }),
        // One block producer
        1 => {
            let node = block_producers.remove(0);
            if node.command_line.is_using_kes_agent() {
                return Err(CardanoDiscoveryError::BlockProducerNotHandled {
                    node: node.instance,
                    reason: "The node is using a KES agent, use KES keys instead".to_string(),
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
    use std::sync::Mutex;

    use anyhow::anyhow;
    use async_trait::async_trait;

    use crate::discovery::cardano::{NodeProcess, ProcessOwner};

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
    pub struct FakeToolProbe {
        version_output: Option<String>,
        cardano_cli: Option<PathBuf>,
        /// Identities the version command was run with
        version_run_as: Arc<Mutex<Vec<ProcessOwner>>>,
    }

    #[async_trait]
    impl ToolProbe for FakeToolProbe {
        async fn node_version_output(
            &self,
            _node_executable: &Path,
            run_as: ProcessOwner,
        ) -> anyhow::Result<String> {
            self.version_run_as.lock().unwrap().push(run_as);
            self.version_output
                .clone()
                .ok_or_else(|| anyhow!("version command failed"))
        }

        async fn find_cardano_cli(
            &self,
            _node_executable: Option<&Path>,
        ) -> anyhow::Result<Option<PathBuf>> {
            Ok(self.cardano_cli.clone())
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
        tools: FakeToolProbe,
        files: FakeFileProbe,
    }

    impl FakeProbes {
        fn discoverer(self) -> CardanoDiscoverer {
            CardanoDiscoverer::new(
                Arc::new(self.processes),
                Arc::new(self.services),
                Arc::new(self.tools),
                Arc::new(self.files),
            )
        }
    }

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
        use std::net::{Ipv4Addr, Ipv6Addr};

        use crate::discovery::cardano::{CardanoNetwork, ListeningAddress, Peer};

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
                    "--host-addr",
                    "0.0.0.0",
                    "--host-ipv6-addr",
                    "::",
                    "--port",
                    "3001",
                ])
            };
            let tools = FakeToolProbe {
                version_output: Some(
                    "cardano-node 10.1.4 - linux-x86_64 - ghc-9.6\ngit rev 1f63dbf2ab39e0b32bf6901dc203866d3e37de08\n"
                        .to_string(),
                ),
                cardano_cli: Some(PathBuf::from("/usr/local/bin/cardano-cli")),
                ..Default::default()
            };

            let files = node_files(&[
                ("/opt/cardano/config.json", CONFIGURATION),
                ("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS),
                ("/opt/cardano/topology.json", TOPOLOGY),
            ]);

            let discovery = discover(
                process,
                FakeProbes {
                    tools,
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
                    }],
                    kes_key_path: Some(PathBuf::from("/opt/cardano/kes.skey")),
                    operational_certificate_path: Some(PathBuf::from("/opt/cardano/node.cert")),
                    kes_agent_socket: None,
                    bulk_credentials_file: None,
                    listening_address: ListeningAddress {
                        ipv4: Some(Ipv4Addr::UNSPECIFIED),
                        ipv6: Some(Ipv6Addr::UNSPECIFIED),
                        port: Some(3001),
                    },
                    service_user: Some("cardano".to_string()),
                    node_version: Some("10.1.4".to_string()),
                    cardano_cli_path: Some(PathBuf::from("/usr/local/bin/cardano-cli")),
                },
                discovery
            );
        }

        #[tokio::test]
        async fn runs_the_version_command_with_the_identity_of_the_node() {
            let tools = FakeToolProbe {
                version_output: Some("cardano-node 10.1.4 - linux-x86_64 - ghc-9.6".to_string()),
                ..Default::default()
            };
            let version_run_as = tools.version_run_as.clone();

            discover(
                block_producer_process(&[]),
                FakeProbes {
                    tools,
                    ..Default::default()
                },
            )
            .await;

            assert_eq!(vec![NODE_OWNER], *version_run_as.lock().unwrap());
        }

        #[tokio::test]
        async fn does_not_run_the_version_command_when_the_identity_of_the_node_is_unknown() {
            let process = NodeProcess {
                owner: None,
                ..block_producer_process(&[])
            };
            let tools = FakeToolProbe {
                version_output: Some("cardano-node 10.1.4 - linux-x86_64 - ghc-9.6".to_string()),
                ..Default::default()
            };
            let version_run_as = tools.version_run_as.clone();

            let discovery = discover(
                process,
                FakeProbes {
                    tools,
                    ..Default::default()
                },
            )
            .await;

            assert_eq!(None, discovery.node_version);
            assert!(version_run_as.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn does_not_run_the_version_command_when_the_node_executable_is_unknown() {
            let process = NodeProcess {
                executable: None,
                ..block_producer_process(&[])
            };
            let tools = FakeToolProbe {
                version_output: Some("cardano-node 10.1.4 - linux-x86_64 - ghc-9.6".to_string()),
                ..Default::default()
            };
            let version_run_as = tools.version_run_as.clone();

            let discovery = discover(
                process,
                FakeProbes {
                    tools,
                    ..Default::default()
                },
            )
            .await;

            assert_eq!(None, discovery.node_version);
            assert!(version_run_as.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn leaves_the_facts_absent_from_the_command_line_undiscovered() {
            let discovery = discover(block_producer_process(&[]), FakeProbes::default()).await;

            assert_eq!(None, discovery.socket_path);
            assert_eq!(None, discovery.database_dir);
            assert_eq!(None, discovery.config_file);
            assert_eq!(None, discovery.topology_file);
            assert_eq!(ListeningAddress::default(), discovery.listening_address);
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

        #[tokio::test]
        async fn collects_the_bulk_credentials_file_of_a_block_producer_using_one() {
            let process = node_process(42, &["run", "--bulk-credentials-file", "/opt/bulk.creds"]);

            let discovery = discover(process, FakeProbes::default()).await;

            assert_eq!(
                Some(PathBuf::from("/opt/bulk.creds")),
                discovery.bulk_credentials_file
            );
            assert_eq!(None, discovery.kes_key_path);
            assert_eq!(None, discovery.operational_certificate_path);
        }

        #[tokio::test]
        async fn ignores_invalid_listening_address_values() {
            let process = block_producer_process(&[
                "--host-addr",
                "not-an-ip",
                "--host-ipv6-addr",
                "0.0.0.0",
                "--port",
                "99999",
            ]);

            let discovery = discover(process, FakeProbes::default()).await;

            assert_eq!(ListeningAddress::default(), discovery.listening_address);
        }

        #[tokio::test]
        async fn leaves_the_node_version_undiscovered_when_the_version_command_fails() {
            let discovery = discover(block_producer_process(&[]), FakeProbes::default()).await;

            assert_eq!(None, discovery.node_version);
        }

        #[tokio::test]
        async fn leaves_the_node_version_undiscovered_when_its_output_is_unexpected() {
            let tools = FakeToolProbe {
                version_output: Some("something else 1.0".to_string()),
                ..Default::default()
            };

            let discovery = discover(
                block_producer_process(&[]),
                FakeProbes {
                    tools,
                    ..Default::default()
                },
            )
            .await;

            assert_eq!(None, discovery.node_version);
        }

        #[tokio::test]
        async fn leaves_the_cardano_cli_path_undiscovered_when_not_found() {
            let discovery = discover(block_producer_process(&[]), FakeProbes::default()).await;

            assert_eq!(None, discovery.cardano_cli_path);
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
            let discovery =
                discover_with_files(&[("/opt/cardano/shelley/genesis.json", PREVIEW_GENESIS)])
                    .await;

            assert_eq!(None, discovery.shelley_genesis_file);
            assert_eq!(None, discovery.network);
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
            let discovery =
                discover_with_files(&[("/opt/cardano/topology.json", "{ not json")]).await;

            assert_eq!(Vec::<Peer>::new(), discovery.pool_peers);
        }
    }
}
