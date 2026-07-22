use std::sync::Arc;

use mithril_protocol_config::ProtocolConfigurationReader;
use slog::Logger;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::CardanoNetwork;

/// Dependencies container for the protocol configuration commands
pub struct ProtocolConfigurationCommandDependenciesContainer {
    /// Cardano network
    pub network: CardanoNetwork,

    /// Chain observer
    pub chain_observer: Arc<dyn ChainObserver>,

    /// Protocol configuration reader
    pub protocol_configuration_reader: Arc<ProtocolConfigurationReader>,

    /// Logger.
    pub logger: Logger,
}
