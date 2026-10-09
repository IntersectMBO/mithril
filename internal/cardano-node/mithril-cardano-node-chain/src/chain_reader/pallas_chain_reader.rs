use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use pallas_network::{
    facades::NodeClient,
    miniprotocols::{
        Point,
        chainsync::{BlockContent, NextResponse},
    },
};
use pallas_traverse::MultiEraBlock;
use slog::{Logger, debug, warn};
use tokio::time::timeout;

use mithril_common::StdResult;
use mithril_common::entities::CardanoNetwork;
use mithril_common::logging::LoggerExtensions;

use crate::entities::{ChainBlockNextAction, RawCardanoPoint, ScannedBlock};

use super::ChainBlockReader;

/// Default timeout duration for Pallas `chainsync` operations.
const DEFAULT_CHAINSYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// [PallasChainReader] reads blocks with 'chainsync' mini-protocol
pub struct PallasChainReader {
    socket: PathBuf,
    network: CardanoNetwork,
    client: Option<NodeClient>,
    chainsync_timeout: Duration,
    logger: Logger,
}

impl PallasChainReader {
    /// Creates a new `PallasChainReader` with the specified socket and network.
    pub fn new(socket: &Path, network: CardanoNetwork, logger: Logger) -> Self {
        Self {
            socket: socket.to_owned(),
            network,
            client: None,
            chainsync_timeout: DEFAULT_CHAINSYNC_TIMEOUT,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Sets the timeout duration for chainsync operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.chainsync_timeout = timeout;
        self
    }

    /// Creates and returns a new `NodeClient` connected to the specified socket.
    async fn new_client(&self) -> StdResult<NodeClient> {
        let magic = self.network.magic_id();
        timeout(
            self.chainsync_timeout,
            NodeClient::connect(&self.socket, magic),
        )
        .await
        .map_err(|_| {
            warn!(
                self.logger, "Timeout elapsed while connecting to the Cardano node";
                "timeout" => ?self.chainsync_timeout, "socket" => self.socket.display().to_string()
            );
            anyhow::anyhow!("PallasChainReader timed out connecting to the Cardano node")
        })?
        .with_context(|| "PallasChainReader failed to create a new client")
    }

    /// Returns a mutable reference to the client.
    async fn get_client(&mut self) -> StdResult<&mut NodeClient> {
        if self.client.is_none() {
            self.client = Some(self.new_client().await?);
            debug!(self.logger, "Connected to a new client");
        }

        self.client
            .as_mut()
            .with_context(|| "PallasChainReader failed to get a client")
    }

    #[cfg(all(test, unix))]
    /// Check if the client already exists (test only).
    fn has_client(&self) -> bool {
        self.client.is_some()
    }

    /// Drops the client by aborting the connection and setting it to `None`.
    fn drop_client(&mut self) {
        if let Some(client) = self.client.take() {
            tokio::spawn(async move {
                let _ = client.abort().await;
            });
        }
    }

    /// Intersects the point of the chain with the given point and consumes the acknowledgement
    /// of the intersection sent by the node.
    async fn find_intersect_point(&mut self, point: &RawCardanoPoint) -> StdResult<()> {
        let logger = self.logger.clone();
        let chainsync_timeout = self.chainsync_timeout;
        let client = self.get_client().await?;
        let chainsync = client.chainsync();

        if chainsync.has_agency() {
            debug!(logger, "Has agency, finding intersect point..."; "point" => ?point);
            let result = timeout(
                chainsync_timeout,
                chainsync.find_intersect(vec![point.to_owned().into()]),
            )
            .await;
            let intersection_point = match result {
                Ok(Ok((intersection_point, _tip))) => intersection_point,
                Ok(Err(err)) => {
                    self.drop_client();

                    return Err(anyhow::anyhow!(err)
                        .context("PallasChainReader failed to find intersect point"));
                }
                Err(_elapsed) => {
                    warn!(
                        logger, "Timeout elapsed while finding intersect point, dropping connection";
                        "timeout" => ?chainsync_timeout, "point" => ?point
                    );
                    self.drop_client();

                    return Err(anyhow::anyhow!(
                        "PallasChainReader timed out finding intersect point"
                    ));
                }
            };
            if let Some(intersection_point) = intersection_point {
                self.consume_intersection_acknowledgement(intersection_point).await?;
            }
        } else {
            debug!(logger, "Doesn't have agency, no need to find intersect point";);
        }

        Ok(())
    }

    /// Consumes the acknowledgement of an intersection: in the chainsync mini-protocol, the node
    /// answers the first request that follows a found intersection with a rollback to the
    /// intersection point. Reading it here keeps it out of the streamed events, so that every
    /// rollback read afterwards is a genuine one.
    async fn consume_intersection_acknowledgement(
        &mut self,
        intersection_point: Point,
    ) -> StdResult<()> {
        let logger = self.logger.clone();
        let chainsync_timeout = self.chainsync_timeout;
        let client = self.get_client().await?;
        let acknowledgement = timeout(chainsync_timeout, client.chainsync().request_next()).await;
        match acknowledgement {
            Ok(Ok(NextResponse::RollBackward(rollback_point, _tip)))
                if rollback_point == intersection_point =>
            {
                Ok(())
            }
            Ok(Ok(NextResponse::RollBackward(rollback_point, _tip))) => {
                self.drop_client();

                Err(anyhow::anyhow!(
                    "PallasChainReader expected a rollback to the intersection point {:?} as acknowledgement, received a rollback to {:?}",
                    RawCardanoPoint::from(intersection_point),
                    RawCardanoPoint::from(rollback_point)
                ))
            }
            Ok(Ok(_)) => {
                self.drop_client();

                Err(anyhow::anyhow!(
                    "PallasChainReader expected a rollback to the intersection point {:?} as acknowledgement, received no rollback",
                    RawCardanoPoint::from(intersection_point)
                ))
            }
            Ok(Err(err)) => {
                self.drop_client();

                Err(anyhow::anyhow!(err).context(
                    "PallasChainReader failed to receive the acknowledgement of the intersection",
                ))
            }
            Err(_elapsed) => {
                warn!(
                    logger, "Timeout elapsed while waiting for the acknowledgement of the intersection, dropping connection";
                    "timeout" => ?chainsync_timeout, "intersection_point" => ?RawCardanoPoint::from(intersection_point)
                );
                self.drop_client();

                Err(anyhow::anyhow!(
                    "PallasChainReader timed out waiting for the acknowledgement of the intersection"
                ))
            }
        }
    }

    /// Processes a block content next response and returns the appropriate chain block next action.
    async fn process_chain_block_next_action(
        &mut self,
        next: NextResponse<BlockContent>,
    ) -> StdResult<Option<ChainBlockNextAction>> {
        match next {
            NextResponse::RollForward(raw_block, _forward_tip) => {
                let multi_era_block = MultiEraBlock::decode(&raw_block)
                    .with_context(|| "PallasChainReader failed to decode raw block")?;
                let parsed_block = ScannedBlock::convert(multi_era_block);
                Ok(Some(ChainBlockNextAction::RollForward { parsed_block }))
            }
            NextResponse::RollBackward(rollback_point, _) => {
                Ok(Some(ChainBlockNextAction::RollBackward {
                    rollback_point: RawCardanoPoint::from(rollback_point),
                }))
            }
            NextResponse::Await => Ok(None),
        }
    }
}

impl Drop for PallasChainReader {
    fn drop(&mut self) {
        self.drop_client();
    }
}

#[async_trait]
impl ChainBlockReader for PallasChainReader {
    async fn set_chain_point(&mut self, point: &RawCardanoPoint) -> StdResult<()> {
        self.find_intersect_point(point).await
    }

    async fn get_next_chain_block(&mut self) -> StdResult<Option<ChainBlockNextAction>> {
        let chainsync_timeout = self.chainsync_timeout;
        let logger = self.logger.clone();
        let client = self.get_client().await?;
        let chainsync = client.chainsync();
        let next = match chainsync.has_agency() {
            true => timeout(chainsync_timeout, chainsync.request_next()).await,
            false => timeout(chainsync_timeout, chainsync.recv_while_must_reply()).await,
        };
        match next {
            Ok(Ok(response)) => self.process_chain_block_next_action(response).await,
            Ok(Err(err)) => {
                self.drop_client();

                Err(err.into())
            }
            Err(_elapsed) => {
                warn!(
                    logger,
                    "Timeout elapsed while waiting for next chain block from the Cardano node, dropping connection";
                    "timeout" => ?chainsync_timeout
                );
                self.drop_client();

                Err(anyhow::anyhow!(
                    "PallasChainReader timed out waiting for next chain block from the Cardano node"
                ))
            }
        }
    }
}

// Windows does not support Unix sockets, nor pallas_network::facades::NodeServer
#[cfg(all(test, unix))]
mod tests {
    use pallas_network::{
        facades::NodeServer,
        miniprotocols::{
            Point,
            chainsync::{BlockContent, Tip},
        },
    };
    use std::fs;
    use tokio::net::UnixListener;

    use mithril_common::{current_function, entities::BlockNumber, test::TempDir};

    use crate::test::TestLogger;

    use super::*;

    /// Enum representing the action to be performed by the server.
    enum ServerAction {
        RollBackward,
        RollForward,
    }

    /// Enum representing whether the node has agency or not.
    #[derive(Debug, PartialEq)]
    enum HasAgency {
        Yes,
        No,
    }

    /// Enum representing an invalid reply of the server to the request that follows an intersection.
    enum InvalidAcknowledgement {
        Block,
        RollbackToAnotherPoint,
    }

    /// Returns a fake specific point for testing purposes.
    fn get_fake_specific_point() -> Point {
        Point::Specific(
            1654413,
            hex::decode("7de1f036df5a133ce68a82877d14354d0ba6de7625ab918e75f3e2ecb29771c2")
                .unwrap(),
        )
    }

    /// Returns a fake specific point which is not the intersection point.
    fn get_fake_other_specific_point() -> Point {
        Point::Specific(
            1654400,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        )
    }

    /// Returns a fake block number for testing purposes.
    fn get_fake_block_number() -> BlockNumber {
        BlockNumber(1337)
    }

    /// Returns the fake tip of the chain, at the fake specific point.
    fn get_fake_tip() -> Tip {
        Tip(get_fake_specific_point(), *get_fake_block_number())
    }

    /// Returns a fake cardano raw point for testing purposes.
    fn get_fake_raw_point_backwards() -> RawCardanoPoint {
        RawCardanoPoint::from(get_fake_specific_point())
    }

    /// Creates a new work directory in the system's temporary folder.
    fn create_temp_dir(folder_name: &str) -> PathBuf {
        TempDir::create_with_short_path("pallas_chain_observer_test", folder_name)
    }

    fn get_fake_raw_block() -> Vec<u8> {
        let raw_block =
            include_str!("../../../../../mithril-test-lab/test_data/blocks/shelley1.block");

        hex::decode(raw_block).unwrap()
    }

    fn get_fake_scanned_block() -> ScannedBlock {
        let raw_block = get_fake_raw_block();
        let multi_era_block = MultiEraBlock::decode(&raw_block).unwrap();

        ScannedBlock::convert(multi_era_block)
    }

    /// Accepts a client on the socket and intersects at the fake specific point, leaving the
    /// server ready to reply to the request that follows the intersection.
    async fn accept_and_intersect(socket_path: PathBuf) -> NodeServer {
        if socket_path.exists() {
            fs::remove_file(&socket_path).expect("Previous socket removal failed");
        }

        let unix_listener = UnixListener::bind(socket_path.as_path()).unwrap();
        let mut server = NodeServer::accept(&unix_listener, 10).await.unwrap();
        let chainsync_server = server.chainsync();

        chainsync_server.recv_while_idle().await.unwrap();
        chainsync_server
            .send_intersect_found(get_fake_specific_point(), get_fake_tip())
            .await
            .unwrap();
        chainsync_server.recv_while_idle().await.unwrap();

        server
    }

    /// Sets up a mock server which intersects at the fake specific point, acknowledges the
    /// intersection as the node does, then performs the given action.
    async fn setup_server(
        socket_path: PathBuf,
        action: ServerAction,
        has_agency: HasAgency,
    ) -> tokio::task::JoinHandle<NodeServer> {
        tokio::spawn(async move {
            let mut server = accept_and_intersect(socket_path).await;
            let chainsync_server = server.chainsync();

            chainsync_server
                .send_roll_backward(get_fake_specific_point(), get_fake_tip())
                .await
                .unwrap();
            chainsync_server.recv_while_idle().await.unwrap();

            if has_agency == HasAgency::No {
                chainsync_server.send_await_reply().await.unwrap();
            }

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
            }

            server
        })
    }

    /// Sets up a mock server which intersects at the fake specific point and replies to the
    /// request that follows with the given invalid acknowledgement.
    async fn setup_server_with_invalid_acknowledgement(
        socket_path: PathBuf,
        acknowledgement: InvalidAcknowledgement,
    ) -> tokio::task::JoinHandle<NodeServer> {
        tokio::spawn(async move {
            let mut server = accept_and_intersect(socket_path).await;
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

    #[tokio::test]
    async fn get_next_chain_block_rolls_backward() {
        let socket_path = create_temp_dir(current_function!()).join("node.socket");
        let known_point = get_fake_specific_point();
        let server = setup_server(
            socket_path.clone(),
            ServerAction::RollBackward,
            HasAgency::Yes,
        )
        .await;
        let client = tokio::spawn(async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            );

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(known_point.clone()))
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
        let server = setup_server(
            socket_path.clone(),
            ServerAction::RollForward,
            HasAgency::Yes,
        )
        .await;
        let client = tokio::spawn(async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            );

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(known_point.clone()))
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
    async fn get_next_chain_block_has_no_agency() {
        let socket_path = create_temp_dir(current_function!()).join("node.socket");
        let known_point = get_fake_specific_point();
        let server = setup_server(
            socket_path.clone(),
            ServerAction::RollForward,
            HasAgency::No,
        )
        .await;
        let client = tokio::spawn(async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            );

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(known_point.clone()))
                .await
                .unwrap();

            // forces the client to change the chainsync server agency state
            let client = chain_reader.get_client().await.unwrap();
            client.chainsync().request_next().await.unwrap();

            // make sure that the chainsync client returns an error when attempting to find intersection without agency
            client
                .chainsync()
                .find_intersect(vec![known_point.clone()])
                .await
                .expect_err("chainsync find_intersect without agency should fail");

            // make sure that setting the chain point is harmless when the chainsync client does not have agency
            chain_reader
                .set_chain_point(&RawCardanoPoint::from(known_point.clone()))
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
    async fn cached_client_is_dropped_when_returning_error() {
        let socket_path = create_temp_dir(current_function!()).join("node.socket");
        let socket_path_clone = socket_path.clone();
        let known_point = get_fake_specific_point();
        let server = setup_server(
            socket_path.clone(),
            ServerAction::RollForward,
            HasAgency::Yes,
        )
        .await;
        let client = tokio::spawn(async move {
            let mut chain_reader = PallasChainReader::new(
                socket_path_clone.as_path(),
                CardanoNetwork::TestNet(10),
                TestLogger::stdout(),
            );

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(known_point.clone()))
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
                let mut server = NodeServer::accept(&unix_listener, 10).await.unwrap();
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
                    .set_chain_point(&RawCardanoPoint::from(get_fake_specific_point()))
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
                let mut server = NodeServer::accept(&unix_listener, 10).await.unwrap();
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
                    .set_chain_point(&RawCardanoPoint::from(get_fake_specific_point()))
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

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(get_fake_specific_point()))
                .await
                .expect_err("Setting the chain point should fail when acknowledged by a block");

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

            chain_reader
                .set_chain_point(&RawCardanoPoint::from(get_fake_specific_point()))
                .await
                .expect_err(
                    "Setting the chain point should fail when acknowledged by a rollback to another point",
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
}
