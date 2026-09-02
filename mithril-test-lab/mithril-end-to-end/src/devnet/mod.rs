mod cardano;
mod ipfs;

pub use cardano::{Devnet, DevnetBootstrapArgs, DevnetTopology, FullNode, PoolNode};
pub use ipfs::{IpfsDevnet, IpfsDevnetBootstrapArgs, KuboNode};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("Retryable devnet error: `{0}`")]
pub struct RetryableDevnetError(pub String);
