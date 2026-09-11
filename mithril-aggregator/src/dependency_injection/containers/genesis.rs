use std::sync::Arc;

use slog::Logger;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
#[cfg(feature = "future_snark")]
use mithril_common::crypto_helper::CircuitVerificationKeyRegistryRetriever;
use mithril_common::{CardanoNetwork, entities::SupportedEra};

use crate::database::repository::CertificateRepository;
use crate::{ProtocolParametersRetriever, VerificationKeyStorer};

/// Dependencies container for the genesis commands
pub struct GenesisCommandDependenciesContainer {
    /// Cardano network
    pub network: CardanoNetwork,

    /// Verification key store
    pub verification_key_store: Arc<dyn VerificationKeyStorer>,

    /// Chain observer
    pub chain_observer: Arc<dyn ChainObserver>,

    /// Protocol parameters retriever service.
    pub protocol_parameters_retriever: Arc<dyn ProtocolParametersRetriever>,

    /// Certificate store.
    pub certificate_repository: Arc<CertificateRepository>,

    /// Mithril era to use for the genesis certificate.
    pub mithril_era: SupportedEra,

    /// Circuit verification key registry retriever.
    #[cfg(feature = "future_snark")]
    pub circuit_verification_key_registry_retriever:
        Arc<dyn CircuitVerificationKeyRegistryRetriever>,

    /// Logger.
    pub logger: Logger,
}
