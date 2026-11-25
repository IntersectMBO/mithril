//! Test doubles shared by the tests of the discoverer

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::discovery::cardano::{
    CardanoDiscoverer, CardanoDiscovery, FileProbe, NodeProcess, ProcessOwner, ProcessProbe,
};

#[derive(Default)]
pub(super) struct FakeProcessProbe {
    pub(super) processes: Vec<NodeProcess>,
    pub(super) fails: bool,
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
pub(super) struct FakeFileProbe {
    pub(super) files: HashMap<PathBuf, String>,
}

#[async_trait]
impl FileProbe for FakeFileProbe {
    async fn read_to_string(&self, path: &Path) -> anyhow::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("file not found: {}", path.display()))
    }
}

pub(super) fn node_process(pid: u32, args: &[&str]) -> NodeProcess {
    NodeProcess {
        pid,
        executable: Some(PathBuf::from("/usr/local/bin/cardano-node")),
        args: args.iter().map(|arg| arg.to_string()).collect(),
        working_dir: None,
        user: None,
        owner: Some(NODE_OWNER),
    }
}

pub(super) const NODE_OWNER: ProcessOwner = ProcessOwner {
    uid: 1001,
    gid: 1001,
};

/// Fake probes of a discoverer under test, each test only sets the probes it needs
#[derive(Default)]
pub(super) struct FakeProbes {
    pub(super) processes: FakeProcessProbe,
    pub(super) files: FakeFileProbe,
}

impl FakeProbes {
    pub(super) fn discoverer(self) -> CardanoDiscoverer {
        CardanoDiscoverer::new(Arc::new(self.processes), Arc::new(self.files))
    }
}

pub(super) const BLOCK_PRODUCER_ARGS: [&str; 5] = [
    "run",
    "--shelley-kes-key",
    "/opt/cardano/kes.skey",
    "--shelley-operational-certificate",
    "/opt/cardano/node.cert",
];

pub(super) fn block_producer_process(extra_args: &[&str]) -> NodeProcess {
    let args: Vec<&str> = BLOCK_PRODUCER_ARGS.iter().chain(extra_args).copied().collect();
    node_process(42, &args)
}

pub(super) const CONFIGURATION: &str = "ShelleyGenesisFile: shelley/genesis.json\n";

pub(super) const PREVIEW_GENESIS: &str = r#"{ "networkId": "Testnet", "networkMagic": 2 }"#;

pub(super) const TOPOLOGY: &str = r#"{
            "localRoots": [{ "accessPoints": [{ "address": "relay1.example.com", "port": 3001 }] }],
            "publicRoots": [{ "accessPoints": [{ "address": "backbone.cardano.iog.io", "port": 3001 }] }]
        }"#;

pub(super) fn node_files(files: &[(&str, &str)]) -> FakeFileProbe {
    FakeFileProbe {
        files: files
            .iter()
            .map(|(path, content)| (PathBuf::from(path), content.to_string()))
            .collect(),
    }
}

/// Discover the given block producer process, observed through the other given probes
pub(super) async fn discover(process: NodeProcess, probes: FakeProbes) -> CardanoDiscovery {
    FakeProbes {
        processes: FakeProcessProbe {
            processes: vec![process],
            ..Default::default()
        },
        ..probes
    }
    .discoverer()
    .discover()
    .await
    .unwrap()
}
