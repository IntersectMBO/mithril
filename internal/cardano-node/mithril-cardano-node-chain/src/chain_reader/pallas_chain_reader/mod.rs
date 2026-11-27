mod error;

pub use error::*;

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

    /// Intersects the chain at the first candidate on the chain of the node.
    ///
    /// The acknowledgement of the intersection is consumed when the chain point is the first
    /// candidate, and left in the stream as the genuine rollback to it when the chain point is an
    /// older candidate.
    ///
    /// When the node owes a reply to a previous request, the connection is renewed first, since no
    /// intersection can be requested in that state. When no intersection is found, the error keeps
    /// the connection usable for another intersection.
    async fn find_intersect_point(&mut self, candidates: &[RawCardanoPoint]) -> StdResult<()> {
        let logger = self.logger.clone();
        let chainsync_timeout = self.chainsync_timeout;
        if !self.get_client().await?.chainsync().has_agency() {
            debug!(
                logger,
                "The node owes a reply to a previous request, renewing the connection to intersect the chain"
            );
            self.drop_client();
        }
        let client = self.get_client().await?;
        let chainsync = client.chainsync();

        debug!(logger, "Finding intersect point..."; "candidates" => ?candidates);
        let points = candidates.iter().cloned().map(Point::from).collect();
        let result = timeout(chainsync_timeout, chainsync.find_intersect(points)).await;
        let intersection_point = match result {
            Ok(Ok((Some(intersection_point), _tip))) => intersection_point,
            Ok(Ok((None, tip))) => {
                warn!(
                    logger, "No intersection found with the chain of the Cardano node";
                    "candidates" => ?candidates, "tip" => ?RawCardanoPoint::from(tip.0), "tip_block_number" => tip.1
                );

                return Err(PallasChainReaderError::IntersectionNotFound {
                    candidates: candidates.to_vec(),
                }
                .into());
            }
            Ok(Err(err)) => {
                self.drop_client();

                return Err(anyhow::anyhow!(err)
                    .context("PallasChainReader failed to find intersect point"));
            }
            Err(_elapsed) => {
                warn!(
                    logger, "Timeout elapsed while finding intersect point, dropping connection";
                    "timeout" => ?chainsync_timeout, "candidates" => ?candidates
                );
                self.drop_client();

                return Err(PallasChainReaderError::IntersectionTimeout.into());
            }
        };
        let intersection_is_a_candidate = candidates
            .iter()
            .any(|candidate| Point::from(candidate.clone()) == intersection_point);
        if !intersection_is_a_candidate {
            self.drop_client();

            return Err(PallasChainReaderError::IntersectionNotACandidate {
                intersection_point: RawCardanoPoint::from(intersection_point),
                candidates: candidates.to_vec(),
            }
            .into());
        }
        let intersection_at_first_candidate = candidates
            .first()
            .is_some_and(|candidate| Point::from(candidate.clone()) == intersection_point);
        if intersection_at_first_candidate {
            self.consume_intersection_acknowledgement(intersection_point).await?;
        } else {
            debug!(
                logger, "Intersection found at an older candidate, its acknowledgement is the next chain block";
                "intersection_point" => ?RawCardanoPoint::from(intersection_point)
            );
        }

        Ok(())
    }

    /// Consumes the acknowledgement of an intersection.
    ///
    /// In the chainsync mini-protocol, the node answers the first request that follows a found
    /// intersection with a rollback to the intersection point. Reading it here keeps it out of the
    /// streamed events, so that every rollback read afterwards is a genuine one.
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

                Err(PallasChainReaderError::AcknowledgementToAnotherPoint {
                    intersection_point: RawCardanoPoint::from(intersection_point),
                    rollback_point: RawCardanoPoint::from(rollback_point),
                }
                .into())
            }
            Ok(Ok(_)) => {
                self.drop_client();

                Err(PallasChainReaderError::AcknowledgementWithoutRollback {
                    intersection_point: RawCardanoPoint::from(intersection_point),
                }
                .into())
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

                Err(PallasChainReaderError::AcknowledgementTimeout.into())
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
    async fn set_chain_point(&mut self, candidates: &[RawCardanoPoint]) -> StdResult<()> {
        self.find_intersect_point(candidates).await
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

                Err(PallasChainReaderError::NextChainBlockTimeout.into())
            }
        }
    }
}

// Windows does not support Unix sockets, nor pallas_network::facades::NodeServer
#[cfg(all(test, unix))]
mod fake_node;
#[cfg(all(test, unix))]
mod tests;
