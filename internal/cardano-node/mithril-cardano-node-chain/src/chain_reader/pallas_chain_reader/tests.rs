use std::fs;

use pallas_network::{
    facades::{DEFAULT_HANDSHAKE_TIMEOUT, NodeServer},
    miniprotocols::chainsync::Tip,
};
use tokio::net::UnixListener;

use mithril_common::current_function;

use crate::test::TestLogger;

use super::fake_node::*;
use super::*;

#[tokio::test]
async fn cached_client_is_dropped_when_the_intersection_acknowledgement_times_out() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            let unix_listener = bind_listener(&socket_path);
            let server = accept_and_intersect(&unix_listener).await;
            std::future::pending::<()>().await;

            server
        }
    });
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        )
        .with_timeout(Duration::from_millis(200));

        let error = chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .expect_err("Setting the chain point should fail when the acknowledgement times out");

        assert!(
            matches!(
                error.downcast_ref::<PallasChainReaderError>(),
                Some(PallasChainReaderError::AcknowledgementTimeout)
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            !chain_reader.has_client(),
            "Client should have been dropped after timeout"
        );
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn set_chain_point_fails_when_the_intersection_point_is_not_a_candidate() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            if socket_path.exists() {
                fs::remove_file(&socket_path).expect("Previous socket removal failed");
            }

            let unix_listener = UnixListener::bind(socket_path.as_path()).unwrap();
            let mut server =
                NodeServer::accept_with_timeout(&unix_listener, 10, DEFAULT_HANDSHAKE_TIMEOUT)
                    .await
                    .unwrap();
            let chainsync_server = server.chainsync();
            chainsync_server.recv_while_idle().await.unwrap();
            chainsync_server
                .send_intersect_found(get_fake_other_specific_point(), get_fake_tip())
                .await
                .unwrap();

            server
        }
    });
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        let error = chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .expect_err("Setting the chain point should fail on a point which is not a candidate");

        assert!(
            matches!(
                error.downcast_ref::<PallasChainReaderError>(),
                Some(PallasChainReaderError::IntersectionNotACandidate { .. })
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            !chain_reader.has_client(),
            "Client should have been dropped after error"
        );
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn set_chain_point_at_an_older_candidate_leaves_the_rollback_to_it_as_the_next_chain_block() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server_intersecting_at_the_second_candidate(socket_path.clone()).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[
                RawCardanoPoint::from(get_fake_specific_point()),
                RawCardanoPoint::from(get_fake_other_specific_point()),
            ])
            .await
            .unwrap();

        chain_reader.get_next_chain_block().await.unwrap().unwrap()
    });

    let (server_result, client_result) = tokio::join!(server, client);
    let (_, candidates_received) = server_result.unwrap();
    assert_eq!(
        vec![get_fake_specific_point(), get_fake_other_specific_point()],
        candidates_received
    );
    assert_eq!(
        ChainBlockNextAction::RollBackward {
            rollback_point: RawCardanoPoint::from(get_fake_other_specific_point())
        },
        client_result.unwrap()
    );
}

#[tokio::test]
async fn get_next_chain_block_rolls_backward() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let known_point = get_fake_specific_point();
    let server = setup_server(socket_path.clone(), ServerAction::RollBackward).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(known_point.clone())])
            .await
            .unwrap();

        chain_reader.get_next_chain_block().await.unwrap().unwrap()
    });

    let (_, client_res) = tokio::join!(server, client);
    let chain_block = client_res.expect("Client failed to get next chain block");
    match chain_block {
        ChainBlockNextAction::RollBackward { rollback_point } => {
            assert_eq!(rollback_point, get_fake_raw_point_backwards());
        }
        _ => panic!("Unexpected chain block action"),
    }
}

#[tokio::test]
async fn get_next_chain_block_rolls_forward() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let known_point = get_fake_specific_point();
    let server = setup_server(socket_path.clone(), ServerAction::RollForward).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(known_point.clone())])
            .await
            .unwrap();

        chain_reader.get_next_chain_block().await.unwrap().unwrap()
    });

    let (_, client_res) = tokio::join!(server, client);
    let chain_block = client_res.expect("Client failed to get next chain block");
    match chain_block {
        ChainBlockNextAction::RollForward { parsed_block } => {
            assert_eq!(parsed_block, get_fake_scanned_block());
        }
        _ => panic!("Unexpected chain block action"),
    }
}

#[tokio::test]
async fn get_next_chain_block_receives_the_owed_block_after_a_wait_reply() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server(socket_path.clone(), ServerAction::WaitReplyThenRollForward).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .unwrap();
        assert_eq!(None, chain_reader.get_next_chain_block().await.unwrap());

        chain_reader.get_next_chain_block().await.unwrap().unwrap()
    });

    let (_, client_result) = tokio::join!(server, client);
    assert_eq!(
        ChainBlockNextAction::RollForward {
            parsed_block: get_fake_scanned_block()
        },
        client_result.unwrap()
    );
}

#[tokio::test]
async fn set_chain_point_renews_the_connection_when_the_node_owes_a_reply() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server_owing_a_reply_then_accepting_again(socket_path.clone()).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .unwrap();
        assert_eq!(None, chain_reader.get_next_chain_block().await.unwrap());

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .unwrap();

        chain_reader.get_next_chain_block().await.unwrap().unwrap()
    });

    let (_, client_result) = tokio::join!(server, client);
    assert_eq!(
        ChainBlockNextAction::RollForward {
            parsed_block: get_fake_scanned_block()
        },
        client_result.unwrap()
    );
}

#[tokio::test]
async fn cached_client_is_dropped_when_returning_error() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let socket_path_clone = socket_path.clone();
    let known_point = get_fake_specific_point();
    let server = setup_server(socket_path.clone(), ServerAction::RollForward).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path_clone.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        chain_reader
            .set_chain_point(&[RawCardanoPoint::from(known_point.clone())])
            .await
            .unwrap();

        chain_reader.get_next_chain_block().await.unwrap().unwrap();

        chain_reader
    });

    let (server_res, client_res) = tokio::join!(server, client);
    let chain_reader = client_res.expect("Client failed to get chain reader");
    let server = server_res.expect("Server failed to get server");
    server.abort().await;

    let client = tokio::spawn(async move {
        let mut chain_reader = chain_reader;

        assert!(chain_reader.has_client(), "Client should exist");

        chain_reader
            .get_next_chain_block()
            .await
            .expect_err("Chain reader get_next_chain_block should fail");

        assert!(
            !chain_reader.has_client(),
            "Client should have been dropped after error"
        );

        chain_reader
    });
    client.await.unwrap();
}

#[tokio::test]
async fn cached_client_is_dropped_when_get_next_chain_block_times_out() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let known_point = get_fake_specific_point();
    let tip_block_number = get_fake_block_number();

    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            if socket_path.exists() {
                fs::remove_file(&socket_path).expect("Previous socket removal failed");
            }

            let unix_listener = UnixListener::bind(socket_path.as_path()).unwrap();
            let mut server =
                NodeServer::accept_with_timeout(&unix_listener, 10, DEFAULT_HANDSHAKE_TIMEOUT)
                    .await
                    .unwrap();
            let chainsync_server = server.chainsync();

            chainsync_server.recv_while_idle().await.unwrap();
            chainsync_server
                .send_intersect_found(
                    known_point.clone(),
                    Tip(known_point.clone(), *tip_block_number),
                )
                .await
                .unwrap();

            chainsync_server.recv_while_idle().await.unwrap();
            chainsync_server
                .send_roll_backward(
                    known_point.clone(),
                    Tip(known_point.clone(), *tip_block_number),
                )
                .await
                .unwrap();

            // Receive the request_next but never respond — simulates a stuck Cardano node
            chainsync_server.recv_while_idle().await.unwrap();

            // Keep server alive until aborted so the socket does not close
            std::future::pending::<()>().await;
            server
        }
    });

    let client = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            )
            .with_timeout(Duration::from_millis(200));

            chain_reader
                .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
                .await
                .unwrap();

            assert!(
                chain_reader.has_client(),
                "Client should exist before timeout"
            );

            let result = chain_reader.get_next_chain_block().await;
            assert!(result.is_err(), "Expected timeout error");

            assert!(
                !chain_reader.has_client(),
                "Client should have been dropped after timeout"
            );

            chain_reader
        }
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn cached_client_is_dropped_when_set_chain_point_times_out() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");

    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            if socket_path.exists() {
                fs::remove_file(&socket_path).expect("Previous socket removal failed");
            }

            let unix_listener = UnixListener::bind(socket_path.as_path()).unwrap();
            let mut server =
                NodeServer::accept_with_timeout(&unix_listener, 10, DEFAULT_HANDSHAKE_TIMEOUT)
                    .await
                    .unwrap();
            let chainsync_server = server.chainsync();

            // Receive the find_intersect request but never respond
            chainsync_server.recv_while_idle().await.unwrap();

            // Keep server alive until aborted so the socket does not close
            std::future::pending::<()>().await;
            server
        }
    });

    let client = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            )
            .with_timeout(Duration::from_millis(200));

            assert!(
                !chain_reader.has_client(),
                "Client should not exist before connection"
            );

            let result = chain_reader
                .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
                .await;
            assert!(result.is_err(), "Expected timeout error");

            assert!(
                !chain_reader.has_client(),
                "Client should have been dropped after timeout"
            );

            chain_reader
        }
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn set_chain_point_fails_when_the_intersection_is_acknowledged_by_a_block() {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server_with_invalid_acknowledgement(
        socket_path.clone(),
        InvalidAcknowledgement::Block,
    )
    .await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        let error = chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .expect_err("Setting the chain point should fail when acknowledged by a block");

        assert!(
            matches!(
                error.downcast_ref::<PallasChainReaderError>(),
                Some(PallasChainReaderError::AcknowledgementWithoutRollback { .. })
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            !chain_reader.has_client(),
            "Client should have been dropped after error"
        );
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn set_chain_point_fails_when_the_intersection_is_acknowledged_by_a_rollback_to_another_point()
 {
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server_with_invalid_acknowledgement(
        socket_path.clone(),
        InvalidAcknowledgement::RollbackToAnotherPoint,
    )
    .await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        let error = chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .expect_err(
                "Setting the chain point should fail when acknowledged by a rollback to another point",
            );

        assert!(
            matches!(
                error.downcast_ref::<PallasChainReaderError>(),
                Some(PallasChainReaderError::AcknowledgementToAnotherPoint { .. })
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            !chain_reader.has_client(),
            "Client should have been dropped after error"
        );
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}

#[tokio::test]
async fn set_chain_point_fails_when_the_intersection_is_not_found() {
    // On a new connection, the node keeps its read-pointer at genesis until an intersection
    // is found. When the chain point is a block the node rolled back in the meantime, the
    // node answers IntersectNotFound and the read-pointer stays at genesis, so the next
    // request would replay the whole chain behind a rollback to the origin.
    // Setting the chain point must fail instead of ignoring the reply.
    let socket_path = create_temp_dir(current_function!()).join("node.socket");
    let server = setup_server_without_intersection(socket_path.clone()).await;
    let client = tokio::spawn(async move {
        let mut chain_reader = PallasChainReader::new(
            socket_path.as_path(),
            CardanoNetwork::TestNet(10),
            TestLogger::stdout(),
        );

        let error = chain_reader
            .set_chain_point(&[RawCardanoPoint::from(get_fake_specific_point())])
            .await
            .expect_err("Setting the chain point should fail when the intersection is not found");

        assert!(
            matches!(
                error.downcast_ref::<PallasChainReaderError>(),
                Some(PallasChainReaderError::IntersectionNotFound { .. })
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            chain_reader.has_client(),
            "The connection should stay usable for another intersection"
        );
    });

    let client_result = client.await;
    server.abort();
    client_result.unwrap();
}
