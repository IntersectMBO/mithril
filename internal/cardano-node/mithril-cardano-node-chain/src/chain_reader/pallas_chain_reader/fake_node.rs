use std::fs;
use std::path::{Path, PathBuf};

use pallas_network::{
    facades::{DEFAULT_HANDSHAKE_TIMEOUT, NodeServer},
    miniprotocols::{
        Point,
        chainsync::{BlockContent, ClientRequest, N2CServer, Tip},
    },
};
use pallas_traverse::MultiEraBlock;
use tokio::net::UnixListener;

use mithril_common::{entities::BlockNumber, test::TempDir};

use crate::entities::{RawCardanoPoint, ScannedBlock};

/// Enum representing the action to be performed by the server.
pub(super) enum ServerAction {
    RollBackward,
    RollForward,
    WaitReplyThenRollForward,
}

/// Enum representing an invalid reply of the server to the request that follows an intersection.
pub(super) enum InvalidAcknowledgement {
    Block,
    RollbackToAnotherPoint,
}

/// Returns a fake specific point for testing purposes.
pub(super) fn get_fake_specific_point() -> Point {
    Point::Specific(
        1654413,
        hex::decode("7de1f036df5a133ce68a82877d14354d0ba6de7625ab918e75f3e2ecb29771c2").unwrap(),
    )
}

/// Returns a fake specific point which is not the intersection point.
pub(super) fn get_fake_other_specific_point() -> Point {
    Point::Specific(
        1654400,
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
}

/// Returns a fake block number for testing purposes.
pub(super) fn get_fake_block_number() -> BlockNumber {
    BlockNumber(1337)
}

/// Returns the fake tip of the chain, at the fake specific point.
pub(super) fn get_fake_tip() -> Tip {
    Tip(get_fake_specific_point(), *get_fake_block_number())
}

/// Returns a fake cardano raw point for testing purposes.
pub(super) fn get_fake_raw_point_backwards() -> RawCardanoPoint {
    RawCardanoPoint::from(get_fake_specific_point())
}

/// Creates a new work directory in the system's temporary folder.
pub(super) fn create_temp_dir(folder_name: &str) -> PathBuf {
    TempDir::create_with_short_path("pallas_chain_observer_test", folder_name)
}

pub(super) fn get_fake_raw_block() -> Vec<u8> {
    let raw_block = include_str!("../../../tests/assets/shelley1.block");

    hex::decode(raw_block).unwrap()
}

pub(super) fn get_fake_scanned_block() -> ScannedBlock {
    let raw_block = get_fake_raw_block();
    let multi_era_block = MultiEraBlock::decode(&raw_block).unwrap();

    ScannedBlock::convert(multi_era_block)
}

/// Binds a listener on the socket, removing a previous socket file.
pub(super) fn bind_listener(socket_path: &Path) -> UnixListener {
    if socket_path.exists() {
        fs::remove_file(socket_path).expect("Previous socket removal failed");
    }

    UnixListener::bind(socket_path).unwrap()
}

/// Accepts a client on the listener and intersects at the fake specific point, leaving the
/// server ready to reply to the request that follows the intersection.
pub(super) async fn accept_and_intersect(unix_listener: &UnixListener) -> NodeServer {
    let mut server = NodeServer::accept_with_timeout(unix_listener, 10, DEFAULT_HANDSHAKE_TIMEOUT)
        .await
        .unwrap();
    let chainsync_server = server.chainsync();

    chainsync_server.recv_while_idle().await.unwrap();
    chainsync_server
        .send_intersect_found(get_fake_specific_point(), get_fake_tip())
        .await
        .unwrap();
    chainsync_server.recv_while_idle().await.unwrap();

    server
}

/// Acknowledges the intersection at the fake specific point with a rollback to it, as the node
/// does, leaving the server ready to reply to the next request.
pub(super) async fn acknowledge_intersection(chainsync_server: &mut N2CServer) {
    chainsync_server
        .send_roll_backward(get_fake_specific_point(), get_fake_tip())
        .await
        .unwrap();
    chainsync_server.recv_while_idle().await.unwrap();
}

/// Sets up a mock server which intersects at the fake specific point, acknowledges the
/// intersection as the node does, then performs the given action.
pub(super) async fn setup_server(
    socket_path: PathBuf,
    action: ServerAction,
) -> tokio::task::JoinHandle<NodeServer> {
    tokio::spawn(async move {
        let unix_listener = bind_listener(&socket_path);
        let mut server = accept_and_intersect(&unix_listener).await;
        let chainsync_server = server.chainsync();
        acknowledge_intersection(chainsync_server).await;

        match action {
            ServerAction::RollBackward => {
                chainsync_server
                    .send_roll_backward(get_fake_specific_point(), get_fake_tip())
                    .await
                    .unwrap();
            }
            ServerAction::RollForward => {
                chainsync_server
                    .send_roll_forward(BlockContent(get_fake_raw_block()), get_fake_tip())
                    .await
                    .unwrap();
            }
            ServerAction::WaitReplyThenRollForward => {
                chainsync_server.send_await_reply().await.unwrap();
                chainsync_server
                    .send_roll_forward(BlockContent(get_fake_raw_block()), get_fake_tip())
                    .await
                    .unwrap();
            }
        }

        server
    })
}

/// Sets up a mock server which intersects at the fake specific point and replies to the
/// request that follows with the given invalid acknowledgement.
pub(super) async fn setup_server_with_invalid_acknowledgement(
    socket_path: PathBuf,
    acknowledgement: InvalidAcknowledgement,
) -> tokio::task::JoinHandle<NodeServer> {
    tokio::spawn(async move {
        let unix_listener = bind_listener(&socket_path);
        let mut server = accept_and_intersect(&unix_listener).await;
        let chainsync_server = server.chainsync();

        match acknowledgement {
            InvalidAcknowledgement::Block => {
                chainsync_server
                    .send_roll_forward(BlockContent(get_fake_raw_block()), get_fake_tip())
                    .await
                    .unwrap();
            }
            InvalidAcknowledgement::RollbackToAnotherPoint => {
                chainsync_server
                    .send_roll_backward(get_fake_other_specific_point(), get_fake_tip())
                    .await
                    .unwrap();
            }
        }

        server
    })
}

/// Sets up a mock server which intersects at the second candidate of the request.
///
/// The server acknowledges the intersection on the request that follows, as the node does, and
/// the candidates received are returned.
pub(super) async fn setup_server_intersecting_at_the_second_candidate(
    socket_path: PathBuf,
) -> tokio::task::JoinHandle<(NodeServer, Vec<Point>)> {
    tokio::spawn(async move {
        if socket_path.exists() {
            fs::remove_file(&socket_path).expect("Previous socket removal failed");
        }

        let unix_listener = UnixListener::bind(socket_path.as_path()).unwrap();
        let mut server =
            NodeServer::accept_with_timeout(&unix_listener, 10, DEFAULT_HANDSHAKE_TIMEOUT)
                .await
                .unwrap();
        let chainsync_server = server.chainsync();

        let Some(ClientRequest::Intersect(candidates)) =
            chainsync_server.recv_while_idle().await.unwrap()
        else {
            panic!("The client should request an intersection");
        };
        chainsync_server
            .send_intersect_found(get_fake_other_specific_point(), get_fake_tip())
            .await
            .unwrap();
        let next_request = chainsync_server.recv_while_idle().await.unwrap();
        assert!(matches!(next_request, Some(ClientRequest::RequestNext)));
        chainsync_server
            .send_roll_backward(get_fake_other_specific_point(), get_fake_tip())
            .await
            .unwrap();

        (server, candidates)
    })
}

/// Sets up a mock server which owes a reply to its first client, then accepts a second one.
///
/// The first connection ends on a wait reply to the request following the acknowledged
/// intersection. The second connection gets its intersection acknowledged and a block on the
/// request that follows.
pub(super) async fn setup_server_owing_a_reply_then_accepting_again(
    socket_path: PathBuf,
) -> tokio::task::JoinHandle<NodeServer> {
    tokio::spawn(async move {
        let unix_listener = bind_listener(&socket_path);
        let mut first_server = accept_and_intersect(&unix_listener).await;
        acknowledge_intersection(first_server.chainsync()).await;
        first_server.chainsync().send_await_reply().await.unwrap();

        let mut second_server = accept_and_intersect(&unix_listener).await;
        acknowledge_intersection(second_server.chainsync()).await;
        second_server
            .chainsync()
            .send_roll_forward(BlockContent(get_fake_raw_block()), get_fake_tip())
            .await
            .unwrap();

        second_server
    })
}

/// Sets up a mock server which finds none of the points of the intersection request on its chain.
pub(super) async fn setup_server_without_intersection(
    socket_path: PathBuf,
) -> tokio::task::JoinHandle<NodeServer> {
    tokio::spawn(async move {
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
            .send_intersect_not_found(get_fake_tip())
            .await
            .unwrap();

        server
    })
}
