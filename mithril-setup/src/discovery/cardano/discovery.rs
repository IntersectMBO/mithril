//! Facts discovered about the Cardano node

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use crate::discovery::cardano::{CardanoNetwork, Peer};

/// Facts discovered about the Cardano node selected on the machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoDiscovery {
    /// The selected node instance
    pub node: NodeInstance,

    /// Role of the selected node
    pub role: NodeRole,

    /// Path of the node socket
    pub socket_path: Option<PathBuf>,

    /// Directory of the node database
    pub database_dir: Option<PathBuf>,

    /// Path of the node configuration file
    pub config_file: Option<PathBuf>,

    /// Path of the node topology file
    pub topology_file: Option<PathBuf>,

    /// Path of the Shelley genesis file, read from the node configuration file
    pub shelley_genesis_file: Option<PathBuf>,

    /// Cardano network the node runs on, identified by the magic of the Shelley genesis
    pub network: Option<CardanoNetwork>,

    /// Peers the node always stays connected to, read from its topology file
    ///
    /// When the role is [NodeRole::BlockProducer], these are the relays of the pool. When the
    /// role is [NodeRole::Relay], these are the block producer and the sibling relays.
    pub pool_peers: Vec<Peer>,

    /// Path of the KES secret key
    pub kes_key_path: Option<PathBuf>,

    /// Path of the operational certificate
    pub operational_certificate_path: Option<PathBuf>,

    /// Socket of the KES agent providing the KES key and operational certificate to the node
    pub kes_agent_socket: Option<PathBuf>,

    /// Path of the bulk credentials file holding the node credentials
    pub bulk_credentials_file: Option<PathBuf>,

    /// Address and port the node listens on
    pub listening_address: ListeningAddress,

    /// Name of the user running the node
    pub service_user: Option<String>,

    /// Version of the node, ie: `10.1.4`
    pub node_version: Option<String>,

    /// Path of the `cardano-cli` executable
    pub cardano_cli_path: Option<PathBuf>,
}

/// Role of the node selected on the machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// A node started with its block producing credentials
    BlockProducer,

    /// A node started without block producing credentials
    ///
    /// It is selected only when it is the only node running on the machine, ie: the relay of a
    /// naive deployment where the signer runs beside a relay (test networks only).
    Relay,
}

/// A running Cardano node instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInstance {
    /// Process identifier of the node
    pub pid: u32,

    /// Name of the systemd unit running the node, if it runs as a systemd service
    pub systemd_unit: Option<String>,
}

/// Address and port a Cardano node listens on, as given on its command line
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListeningAddress {
    /// IPv4 address the node binds to
    pub ipv4: Option<Ipv4Addr>,

    /// IPv6 address the node binds to
    pub ipv6: Option<Ipv6Addr>,

    /// Port the node listens on
    pub port: Option<u16>,
}
