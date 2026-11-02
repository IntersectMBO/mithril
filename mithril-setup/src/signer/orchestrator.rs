//! The orchestration for the signer (Discovery, Guessing)

use crate::{
    orchestrator::{
        interfaces::Orchestrator,
        store::{Field, FieldState, FieldType, Store},
    },
    signer::discoverer::{SignerDiscoverer, SignerDiscovery},
};

/// Representation of a Signer
struct SignerOrchestrator {
    discoverer: SignerDiscoverer,
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
                "toto".to_string(),
                "Dummy field".to_string(),
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
            .update_field("network", discovery.network, FieldState::Discovered)?
            .update_field("toto", discovery.toto, FieldState::Discovered)?;

        Ok(store)
    }

    fn save(&self, _store: &Store) -> anyhow::Result<()> {
        // TODO: write the signer configuration file
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signer_orchestrator_discover_must_fill_store_with_information_from_the_discoverer() {
        let signer_orchestrator = SignerOrchestrator {
            discoverer: SignerDiscoverer,
        };

        unsafe { std::env::set_var("NETWORK", "mainnet") };

        let initial_store = signer_orchestrator.initial_store();

        let actual_network = initial_store.get_field("network").unwrap();
        assert_eq!(None, actual_network.value.clone());
        assert_eq!(FieldState::Unset, actual_network.state);

        let actual_toto = initial_store.get_field("toto").unwrap();
        assert_eq!(None, actual_toto.value.clone());
        assert_eq!(FieldState::Unset, actual_toto.state);

        let store_updated = signer_orchestrator.discover().unwrap();

        let actual_network = store_updated.get_field("network").unwrap();
        assert_eq!("mainnet", actual_network.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_network.state);

        let actual_toto = store_updated.get_field("toto").unwrap();
        assert_eq!("toto", actual_toto.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_toto.state);
    }
}
