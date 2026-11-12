//! Facts discovered about the Cardano node

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Facts discovered about the Cardano block producer node
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoDiscovery {
    /// The block producer node instance
    pub node: NodeInstance,

    /// Path of the node socket
    pub socket_path: Option<PathBuf>,

    /// Directory of the node database
    pub database_dir: Option<PathBuf>,

    /// Path of the node configuration file
    pub config_file: Option<PathBuf>,

    /// Path of the node topology file
    pub topology_file: Option<PathBuf>,

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
