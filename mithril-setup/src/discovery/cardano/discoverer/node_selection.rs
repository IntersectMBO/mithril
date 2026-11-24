//! Selection of the Cardano node to discover among the running nodes

use crate::discovery::cardano::NodeRole;

use super::{CardanoDiscoveryError, DetectedNode};

/// Select the block producer, or the only node running when it is not a block producer
pub(super) fn select_node(
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
mod tests {
    use crate::discovery::cardano::{CardanoDiscovery, NodeInstance, NodeProcess, NodeRole};

    use super::super::test_doubles::*;
    use super::super::*;

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
                processes: vec![node_process(42, &["run"]), node_process(43, &BLOCK_PRODUCER_ARGS)],
                ..Default::default()
            },
            ..Default::default()
        }
        .discoverer();

        let discovery = discoverer.discover().await.unwrap();

        assert_eq!(NodeInstance { pid: 43 }, discovery.node);
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
    async fn fails_when_the_only_running_node_is_started_as_non_producing_without_credentials() {
        let result = discover_among(vec![node_process(
            42,
            &["run", "--start-as-non-producing-node"],
        )])
        .await;

        assert_non_producing_node_not_handled(result, 42);
    }

    #[tokio::test]
    async fn fails_on_the_non_producing_node_when_it_runs_beside_a_relay_without_block_producer() {
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
