//! The orchestration for the signer (Discovery, Guessing)

use crate::{
    orchestrator::{
        interfaces::Orchestrator,
        store::{Field, FieldType, Store},
    },
    signer::discoverer::{SignerDiscoverer, SignerDiscovery},
};

/// Representation of a Signer
pub struct SignerOrchestrator {
    discoverer: SignerDiscoverer,
}

impl SignerOrchestrator {
    /// Create a new signer orchestrator
    pub fn new() -> Self {
        Self {
            discoverer: SignerDiscoverer,
        }
    }
}

impl Default for SignerOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Orchestrator for SignerOrchestrator {
    type Discovery = SignerDiscovery;
    type Discoverer = SignerDiscoverer;

    fn discoverer(&self) -> &Self::Discoverer {
        &self.discoverer
    }

    fn initial_store(&self) -> Store {
        Store::new(vec![
            Field::init(
                "network".to_string(),
                "The Cardano network to target".to_string(),
                FieldType::String,
                None,
            ),
            Field::init(
                "magic_id".to_string(),
                "The magic ID".to_string(),
                FieldType::String,
                None,
            ),
        ])
    }

    fn apply_discovery(
        &self,
        mut store: Store,
        discovery: Self::Discovery,
    ) -> anyhow::Result<Store> {
        store
            .discover_field("network", discovery.network)?
            .discover_field("magic_id", discovery.magic_id)?;

        Ok(store)
    }

    fn save(&self, _store: &Store) -> anyhow::Result<()> {
        // TODO: write the signer configuration file
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use crate::orchestrator::store::FieldState;

    use super::*;

    #[test]
    fn test_signer_orchestrator_discover_must_fill_store_with_information_from_the_discoverer() {
        let signer_orchestrator = SignerOrchestrator::new();

        unsafe { std::env::set_var("NETWORK", "mainnet") };

        let initial_store = signer_orchestrator.initial_store();

        let actual_network = initial_store.get_field("network").unwrap();
        assert_eq!(None, actual_network.value.clone());
        assert_eq!(FieldState::Unset, actual_network.state);

        let actual_magic_id = initial_store.get_field("magic_id").unwrap();
        assert_eq!(None, actual_magic_id.value.clone());
        assert_eq!(FieldState::Unset, actual_magic_id.state);

        let store_updated = signer_orchestrator.discover().unwrap();

        let actual_network = store_updated.get_field("network").unwrap();
        assert_eq!("mainnet", actual_network.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_network.state);

        let actual_magic_id = store_updated.get_field("magic_id").unwrap();
        assert_eq!("1", actual_magic_id.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_magic_id.state);
    }
}
