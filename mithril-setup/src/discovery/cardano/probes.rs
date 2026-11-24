//! Traits through which the discovery observes the runtime hosting the Cardano node

use std::path::{Path, PathBuf};

use async_trait::async_trait;

/// A running `cardano-node` process
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProcess {
    /// Process identifier
    pub pid: u32,

    /// Absolute path of the executable of the process, if known
    pub executable: Option<PathBuf>,

    /// Arguments of the process, without the program name
    pub args: Vec<String>,

    /// Working directory of the process, if known
    pub working_dir: Option<PathBuf>,

    /// Name of the user running the process, if known
    pub user: Option<String>,

    /// Identity the process runs with, if known
    pub owner: Option<ProcessOwner>,
}

/// Identity a process runs with
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessOwner {
    /// Real user identifier
    pub uid: u32,

    /// Real group identifier
    pub gid: u32,
}

/// Lists the running `cardano-node` processes
#[async_trait]
pub trait ProcessProbe: Send + Sync {
    /// Returns the `cardano-node` processes currently running
    async fn cardano_node_processes(&self) -> anyhow::Result<Vec<NodeProcess>>;
}

/// Finds the service manager units running processes
#[async_trait]
pub trait ServiceProbe: Send + Sync {
    /// Returns the name of the systemd unit running the given process, if any
    async fn systemd_unit_of(&self, pid: u32) -> anyhow::Result<Option<String>>;
}

/// Reads the files of the Cardano node
#[async_trait]
pub trait FileProbe: Send + Sync {
    /// Returns the content of the given file
    async fn read_to_string(&self, path: &Path) -> anyhow::Result<String>;
}
