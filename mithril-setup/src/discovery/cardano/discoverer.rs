//! Discoverer of the Cardano block producer node

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::discovery::cardano::command_line::NodeCommandLine;
use crate::discovery::cardano::host::{CgroupServiceProbe, HostToolProbe, ProcfsProcessProbe};
use crate::discovery::cardano::{
    CardanoDiscovery, ListeningAddress, NodeInstance, NodeProcess, ProcessProbe, ServiceProbe,
    ToolProbe,
};

/// Reasons why the Cardano block producer node could not be discovered
#[derive(Debug, thiserror::Error)]
pub enum CardanoDiscoveryError {
    /// No Cardano node is running on the machine
    #[error("No running Cardano node found")]
    NoCardanoNode,

    /// Cardano nodes are running, but none of them is a block producer
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
}

impl CardanoDiscoverer {
    /// Create a discoverer observing the runtime through the given probes
    pub fn new(
        processes: Arc<dyn ProcessProbe>,
        services: Arc<dyn ServiceProbe>,
        tools: Arc<dyn ToolProbe>,
    ) -> Self {
        Self {
            processes,
            services,
            tools,
        }
    }

    /// Create a discoverer observing the Linux host the setup runs on
    pub fn host() -> Self {
        Self::new(
            Arc::new(ProcfsProcessProbe::default()),
            Arc::new(CgroupServiceProbe::default()),
            Arc::new(HostToolProbe::from_env()),
        )
    }

    /// Detect the Cardano node instances running as host processes or systemd services
    pub async fn detect_nodes(&self) -> anyhow::Result<Vec<NodeInstance>> {
        let nodes = self.detect().await?;

        Ok(nodes.into_iter().map(|node| node.instance).collect())
    }

    /// Discover the facts of the Cardano block producer node running on the machine
    pub async fn discover(&self) -> Result<CardanoDiscovery, CardanoDiscoveryError> {
        let DetectedNode {
            instance,
            process,
            command_line,
        } = select_block_producer(self.detect().await?)?;
        let resolve = |path: &str| resolve_path(process.working_dir.as_deref(), path);

        Ok(CardanoDiscovery {
            node: instance,
            socket_path: command_line.socket_path.as_deref().map(resolve),
            database_dir: command_line.database_path.as_deref().map(resolve),
            config_file: command_line.config.as_deref().map(resolve),
            topology_file: command_line.topology.as_deref().map(resolve),
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

fn select_block_producer(nodes: Vec<DetectedNode>) -> Result<DetectedNode, CardanoDiscoveryError> {
    if nodes.is_empty() {
        return Err(CardanoDiscoveryError::NoCardanoNode);
    }

    let (mut block_producers, relays): (Vec<_>, Vec<_>) = nodes
        .into_iter()
        .partition(|node| node.command_line.is_block_producer());

    match block_producers.len() {
        0 => Err(CardanoDiscoveryError::NoBlockProducer {
            nodes: relays.into_iter().map(|node| node.instance).collect(),
        }),
        1 => {
            let node = block_producers.remove(0);
            if node.command_line.is_using_kes_agent() {
                return Err(CardanoDiscoveryError::BlockProducerNotHandled {
                    node: node.instance,
                    reason: "The node is using a KES agent, use KES keys instead".to_string(),
                });
            }
            Ok(node)
        }
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

    fn discoverer(
        processes: FakeProcessProbe,
        services: FakeServiceProbe,
        tools: FakeToolProbe,
    ) -> CardanoDiscoverer {
        CardanoDiscoverer::new(Arc::new(processes), Arc::new(services), Arc::new(tools))
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
            let discoverer = discoverer(
                FakeProcessProbe::default(),
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

            let nodes = discoverer.detect_nodes().await.unwrap();

            assert_eq!(Vec::<NodeInstance>::new(), nodes);
        }

        #[tokio::test]
        async fn detects_a_node_running_as_a_host_process() {
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![node_process(42, &["run"])],
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

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
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![node_process(42, &["run"])],
                    ..Default::default()
                },
                FakeServiceProbe {
                    units: HashMap::from([(42, "cardano-node.service".to_string())]),
                },
                FakeToolProbe::default(),
            );

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
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![node_process(42, &["run"]), node_process(43, &["run"])],
                    ..Default::default()
                },
                FakeServiceProbe {
                    units: HashMap::from([(43, "relay.service".to_string())]),
                },
                FakeToolProbe::default(),
            );

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
            let discoverer = discoverer(
                FakeProcessProbe {
                    fails: true,
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

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

    mod select_block_producer {
        use super::*;

        #[tokio::test]
        async fn fails_when_no_node_is_running() {
            let discoverer = discoverer(
                FakeProcessProbe::default(),
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

            let result = discoverer.discover().await;

            assert!(
                matches!(result, Err(CardanoDiscoveryError::NoCardanoNode)),
                "Expected NoCardanoNode, got {result:?}"
            );
        }

        #[tokio::test]
        async fn fails_when_only_relays_are_running() {
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![
                        node_process(42, &["run", "--port", "3001"]),
                        node_process(43, &["run", "--port", "3002"]),
                    ],
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

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
        async fn fails_when_several_block_producers_are_running() {
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![
                        node_process(42, &BLOCK_PRODUCER_ARGS),
                        node_process(43, &["run"]),
                        node_process(44, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

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
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![node_process(
                        42,
                        &["run", "--shelley-kes-agent-socket", "/opt/cardano/kes-agent.socket"],
                    )],
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );
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
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![
                        node_process(42, &["run"]),
                        node_process(43, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                FakeServiceProbe {
                    units: HashMap::from([(43, "cardano-bp.service".to_string())]),
                },
                FakeToolProbe::default(),
            );

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(
                NodeInstance {
                    pid: 43,
                    systemd_unit: Some("cardano-bp.service".to_string())
                },
                discovery.node
            );
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
            let discoverer = discoverer(
                FakeProcessProbe {
                    processes: vec![
                        node_process(42, &standby_args),
                        node_process(43, &BLOCK_PRODUCER_ARGS),
                    ],
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

            let discovery = discoverer.discover().await.unwrap();

            assert_eq!(43, discovery.node.pid);
        }

        #[tokio::test]
        async fn fails_when_the_processes_can_not_be_listed() {
            let discoverer = discoverer(
                FakeProcessProbe {
                    fails: true,
                    ..Default::default()
                },
                FakeServiceProbe::default(),
                FakeToolProbe::default(),
            );

            let result = discoverer.discover().await;

            assert!(
                matches!(result, Err(CardanoDiscoveryError::Probe(_))),
                "Expected Probe error, got {result:?}"
            );
        }
    }

    mod collect_facts {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use crate::discovery::cardano::ListeningAddress;

        use super::*;

        fn block_producer_process(extra_args: &[&str]) -> NodeProcess {
            let args: Vec<&str> = BLOCK_PRODUCER_ARGS.iter().chain(extra_args).copied().collect();
            node_process(42, &args)
        }

        async fn discover(process: NodeProcess, tools: FakeToolProbe) -> CardanoDiscovery {
            discoverer(
                FakeProcessProbe {
                    processes: vec![process],
                    ..Default::default()
                },
                FakeServiceProbe {
                    units: HashMap::from([(42, "cardano-node.service".to_string())]),
                },
                tools,
            )
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

            let discovery = discover(process, tools).await;

            assert_eq!(
                CardanoDiscovery {
                    node: NodeInstance {
                        pid: 42,
                        systemd_unit: Some("cardano-node.service".to_string())
                    },
                    socket_path: Some(PathBuf::from("/opt/cardano/node.socket")),
                    database_dir: Some(PathBuf::from("/opt/cardano/db")),
                    config_file: Some(PathBuf::from("/opt/cardano/config.json")),
                    topology_file: Some(PathBuf::from("/opt/cardano/topology.json")),
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

            discover(block_producer_process(&[]), tools).await;

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

            let discovery = discover(process, tools).await;

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

            let discovery = discover(process, tools).await;

            assert_eq!(None, discovery.node_version);
            assert!(version_run_as.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn leaves_the_facts_absent_from_the_command_line_undiscovered() {
            let discovery = discover(block_producer_process(&[]), FakeToolProbe::default()).await;

            assert_eq!(None, discovery.socket_path);
            assert_eq!(None, discovery.database_dir);
            assert_eq!(None, discovery.config_file);
            assert_eq!(None, discovery.topology_file);
            assert_eq!(ListeningAddress::default(), discovery.listening_address);
            assert_eq!(None, discovery.service_user);
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

            let discovery = discover(process, FakeToolProbe::default()).await;

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

            let discovery = discover(process, FakeToolProbe::default()).await;

            assert_eq!(Some(PathBuf::from("keys/kes.skey")), discovery.kes_key_path);
            assert_eq!(
                Some(PathBuf::from("keys/node.cert")),
                discovery.operational_certificate_path
            );
        }

        #[tokio::test]
        async fn collects_the_bulk_credentials_file_of_a_block_producer_using_one() {
            let process = node_process(42, &["run", "--bulk-credentials-file", "/opt/bulk.creds"]);

            let discovery = discover(process, FakeToolProbe::default()).await;

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

            let discovery = discover(process, FakeToolProbe::default()).await;

            assert_eq!(ListeningAddress::default(), discovery.listening_address);
        }

        #[tokio::test]
        async fn leaves_the_node_version_undiscovered_when_the_version_command_fails() {
            let discovery = discover(block_producer_process(&[]), FakeToolProbe::default()).await;

            assert_eq!(None, discovery.node_version);
        }

        #[tokio::test]
        async fn leaves_the_node_version_undiscovered_when_its_output_is_unexpected() {
            let tools = FakeToolProbe {
                version_output: Some("something else 1.0".to_string()),
                ..Default::default()
            };

            let discovery = discover(block_producer_process(&[]), tools).await;

            assert_eq!(None, discovery.node_version);
        }

        #[tokio::test]
        async fn leaves_the_cardano_cli_path_undiscovered_when_not_found() {
            let discovery = discover(block_producer_process(&[]), FakeToolProbe::default()).await;

            assert_eq!(None, discovery.cardano_cli_path);
        }
    }
}
