//! Errors of the Cardano node discovery

use crate::discovery::cardano::NodeInstance;

/// Reasons why the Cardano block producer node could not be discovered
#[derive(Debug, thiserror::Error)]
pub enum CardanoDiscoveryError {
    /// No Cardano node is running on the machine
    #[error("No running Cardano node found")]
    NoCardanoNode,

    /// Several Cardano nodes are running, but none of them is a block producer
    #[error("No running Cardano block producer node found among the running nodes: {nodes:?}")]
    NoBlockProducer {
        /// The running nodes
        nodes: Vec<NodeInstance>,
    },

    /// Several Cardano block producer nodes are running, the one to use can't be chosen
    #[error("Several running Cardano block producer nodes found: {nodes:?}")]
    SeveralBlockProducers {
        /// The running block producer nodes
        nodes: Vec<NodeInstance>,
    },

    /// The running block producer node is not handled by Mithril
    #[error("The running Cardano block producer is not handled by Mithril: {node:?} {reason}")]
    BlockProducerNotHandled {
        /// The running block producer node
        node: NodeInstance,

        /// Reason
        reason: String,
    },

    /// A probe failed to observe the machine
    #[error("Cardano node discovery failed")]
    Probe(#[from] anyhow::Error),
}
