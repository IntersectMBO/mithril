#![allow(missing_docs)]
use anyhow::{Context, anyhow};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    core::{muxing::StreamMuxerBox, transport::dummy::DummyTransport},
    futures::StreamExt,
    gossipsub::{self, ValidationMode},
    noise, ping,
    swarm::{self, DialError},
    tls, yamux,
};
use mithril_common::{
    StdResult,
    crypto_helper::{TryFromBytes, TryToBytes, key_decode_hex, key_encode_hex},
    logging::LoggerExtensions,
    messages::{RegisterSignatureMessageHttp, RegisterSignerMessage},
};
use mithril_dmq::DmqMessage;
use serde::{Deserialize, Serialize};
use slog::{Logger, debug, info};
use std::{collections::HashMap, time::Duration};

use crate::{mithril_p2p_topic, p2p::PeerError};

/// The idle connection timeout for a P2P connection
const P2P_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

pub use behaviour::*;

mod behaviour {
    // The `NetworkBehaviour` derive generates a `|event| Either::Right(event)` closure for each
    // sub-behaviour. `ping::Behaviour`'s handler input event is `Infallible`, so rustc flags that
    // call as unreachable. Lint attributes on the struct don't reach the generated `impl`, hence
    // this module-level allow.
    #![allow(unreachable_code)]

    use libp2p::{gossipsub, ping, swarm::NetworkBehaviour};

    /// [Peer][super::Peer] custom network behaviour
    #[derive(NetworkBehaviour)]
    pub struct PeerBehaviour {
        pub(super) gossipsub: gossipsub::Behaviour,
        pub(super) ping: ping::Behaviour,
    }
}

/// [Peer] event that is polled from the swarm
#[derive(Debug)]
pub enum PeerEvent {
    /// The peer is listening on an address
    ListeningOnAddr {
        /// Listening multi address
        address: Multiaddr,
    },
    /// The peer established a connection with another peer
    ConnectionEstablished {
        /// Remote peer id
        peer_id: PeerId,
    },
    /// The peer can not connect to another peer
    OutgoingConnectionError {
        /// Remote peer id
        peer_id: Option<PeerId>,
        /// Error that occurred when dialing the remote peer
        error: DialError,
    },
    /// The peer received a behaviour related event
    Behaviour {
        /// The behaviour event the peer received
        event: PeerBehaviourEvent,
    },
}

/// The topic name of a P2P pubsub
pub type TopicName = String;

/// The broadcast message received from a Gossip sub event
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum BroadcastMessage {
    /// A HTTP signer registration message received from the Gossip sub
    RegisterSignerHttp(RegisterSignerMessage),

    /// A HTTP signature registration message received from the Gossip sub
    RegisterSignatureHttp(RegisterSignatureMessageHttp),

    /// A DMQ signature registration message received from the Gossip sub
    RegisterSignatureDmq(DmqMessage),
}

impl TryToBytes for BroadcastMessage {
    fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
        let hex_string = key_encode_hex(self)?;
        Ok(hex_string.into_bytes())
    }
}

impl TryFromBytes for BroadcastMessage {
    fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
        let hex_string = std::str::from_utf8(bytes)
            .with_context(|| "Failed to interpret bytes as UTF-8 hex string")?;
        key_decode_hex(hex_string).map_err(|e| e.into())
    }
}

/// A peer in the P2P network
pub struct Peer {
    topics: HashMap<TopicName, gossipsub::IdentTopic>,
    swarm: Option<Swarm<PeerBehaviour>>,
    addr: Multiaddr,
    /// Multi address on which the peer is listening
    pub addr_peer: Option<Multiaddr>,
    logger: Logger,
}

impl Peer {
    /// Peer factory
    pub fn new(addr: &Multiaddr) -> Self {
        Self {
            topics: Self::build_topics(),
            swarm: None,
            addr: addr.to_owned(),
            addr_peer: None,
            logger: Logger::root(slog::Discard, slog::o!()),
        }
    }

    fn build_topics() -> HashMap<TopicName, gossipsub::IdentTopic> {
        HashMap::from([
            (
                mithril_p2p_topic::SIGNATURES_HTTP.into(),
                gossipsub::IdentTopic::new(mithril_p2p_topic::SIGNATURES_HTTP),
            ),
            (
                mithril_p2p_topic::SIGNATURES_DMQ.into(),
                gossipsub::IdentTopic::new(mithril_p2p_topic::SIGNATURES_DMQ),
            ),
            (
                mithril_p2p_topic::SIGNERS_HTTP.into(),
                gossipsub::IdentTopic::new(mithril_p2p_topic::SIGNERS_HTTP),
            ),
        ])
    }

    /// Set the logger for the peer
    pub fn with_logger(mut self, logger: &Logger) -> Self {
        self.logger = logger.new_with_component_name::<Self>();
        self
    }

    /// Start the peer
    pub async fn start(mut self) -> StdResult<Self> {
        debug!(self.logger, "Starting...");
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                Default::default(),
                (tls::Config::new, noise::Config::new),
                yamux::Config::default,
            )?
            .with_quic()
            .with_other_transport(|_key| DummyTransport::<(PeerId, StreamMuxerBox)>::new())?
            .with_dns()?
            .with_websocket(
                (tls::Config::new, noise::Config::new),
                yamux::Config::default,
            )
            .await?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(262144)
                    .heartbeat_initial_delay(Duration::from_millis(100))
                    .heartbeat_interval(Duration::from_millis(200))
                    .history_length(10)
                    .history_gossip(10)
                    .validation_mode(ValidationMode::Strict)
                    .build()?;
                Ok(PeerBehaviour {
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossipsub_config,
                    )
                    .expect("Valid configuration"),
                    ping: ping::Behaviour::new(ping::Config::new()),
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(P2P_IDLE_CONNECTION_TIMEOUT))
            .build();

        for topic in self.topics.values() {
            debug!(self.logger, "Subscribing to"; "topic" => ?topic, "local_peer_id" => ?self.local_peer_id());
            swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        }

        let _listener_id = swarm.listen_on(self.addr.clone())?;
        self.swarm = Some(swarm);

        loop {
            if let Some(PeerEvent::ListeningOnAddr { address }) = self.tick_swarm().await? {
                info!(self.logger, "Listening on"; "address" => ?address, "local_peer_id" => ?self.local_peer_id());
                self.addr_peer = Some(address);
                break;
            }
        }

        Ok(self)
    }

    /// Convert a peer event to a broadcast message
    pub fn convert_peer_event_to_message(
        &mut self,
        event: PeerEvent,
    ) -> StdResult<Option<BroadcastMessage>> {
        match event {
            PeerEvent::Behaviour {
                event: PeerBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }),
            } => Ok(Some(
                BroadcastMessage::try_from_bytes(&message.data).with_context(
                    || "Failed to deserialize BroadcastMessage from gossipsub event",
                )?,
            )),
            _ => Ok(None),
        }
    }

    /// Tick the peer swarm to receive the next event
    pub async fn tick_swarm(&mut self) -> StdResult<Option<PeerEvent>> {
        debug!(self.logger, "Reading next event"; "local_peer_id" => ?self.local_peer_id());
        match self
            .swarm
            .as_mut()
            .ok_or(PeerError::UnavailableSwarm())
            .with_context(|| "Can not publish signature without swarm")?
            .next()
            .await
        {
            Some(swarm::SwarmEvent::NewListenAddr { address, .. }) => {
                debug!(self.logger, "Received listening address event"; "address" => ?address, "local_peer_id" => ?self.local_peer_id());
                Ok(Some(PeerEvent::ListeningOnAddr { address }))
            }
            Some(swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. }) => {
                debug!(self.logger, "Received outgoing connection error event"; "error" => ?error, "remote_peer_id" => ?peer_id, "local_peer_id" => ?self.local_peer_id());
                Ok(Some(PeerEvent::OutgoingConnectionError { peer_id, error }))
            }
            Some(swarm::SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                debug!(self.logger, "Received connection established event"; "remote_peer_id" => ?peer_id, "local_peer_id" => ?self.local_peer_id());
                Ok(Some(PeerEvent::ConnectionEstablished { peer_id }))
            }
            Some(swarm::SwarmEvent::Behaviour(event)) => {
                debug!(self.logger, "Received behaviour event"; "event" => ?event, "local_peer_id" => ?self.local_peer_id());
                Ok(Some(PeerEvent::Behaviour { event }))
            }
            Some(event) => {
                debug!(self.logger, "Received other event"; "event" => ?event, "local_peer_id" => ?self.local_peer_id());
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Publish a HTTP signature on the P2P pubsub
    pub fn publish_signature_http(
        &mut self,
        message: &RegisterSignatureMessageHttp,
    ) -> StdResult<gossipsub::MessageId> {
        self.publish_broadcast_message(
            &BroadcastMessage::RegisterSignatureHttp(message.to_owned()),
            mithril_p2p_topic::SIGNATURES_HTTP,
        )
    }

    /// Publish a DMQ signature on the P2P pubsub
    pub fn publish_signature_dmq(
        &mut self,
        message: &DmqMessage,
    ) -> StdResult<gossipsub::MessageId> {
        self.publish_broadcast_message(
            &BroadcastMessage::RegisterSignatureDmq(message.to_owned()),
            mithril_p2p_topic::SIGNATURES_DMQ,
        )
    }

    /// Publish a signer registration on the P2P pubsub
    pub fn publish_signer_registration(
        &mut self,
        message: &RegisterSignerMessage,
    ) -> StdResult<gossipsub::MessageId> {
        self.publish_broadcast_message(
            &BroadcastMessage::RegisterSignerHttp(message.to_owned()),
            mithril_p2p_topic::SIGNERS_HTTP,
        )
    }

    /// Publish a broadcast message on the P2P pubsub
    pub fn publish_broadcast_message(
        &mut self,
        message: &BroadcastMessage,
        topic_name: &str,
    ) -> StdResult<gossipsub::MessageId> {
        let topic = self
            .topics
            .get(topic_name)
            .ok_or(PeerError::MissingTopic())
            .with_context(|| {
                format!("Can not publish broadcast message on invalid topic: {topic_name}")
            })?
            .to_owned();
        let data = message.to_bytes_vec().with_context(|| {
            format!("Can not publish broadcast message with invalid format on topic {topic_name}")
        })?;

        let message_id = self
            .swarm
            .as_mut()
            .map(|swarm| swarm.behaviour_mut().gossipsub.publish(topic, data))
            .transpose()
            .with_context(|| {
                format!("Can not publish broadcast message on {topic_name} P2P pubsub")
            })?
            .ok_or(PeerError::UnavailableSwarm())
            .with_context(|| {
                format!(
                    "Can not publish broadcast message on {topic_name} P2P pubsub without swarm"
                )
            })?;

        Ok(message_id.to_owned())
    }

    /// Connect to a remote peer
    pub fn dial(&mut self, addr: Multiaddr) -> StdResult<()> {
        debug!(self.logger, "Dialing to"; "address" => ?addr, "local_peer_id" => ?self.local_peer_id());
        self.swarm
            .as_mut()
            .ok_or(PeerError::UnavailableSwarm())
            .with_context(|| "Can not dial without swarm")?
            .dial(addr)
            .map_err(|e| anyhow!(e))
    }

    /// Get the local peer id (if any)
    pub fn local_peer_id(&self) -> Option<PeerId> {
        self.swarm.as_ref().map(|s| s.local_peer_id().to_owned())
    }
}
