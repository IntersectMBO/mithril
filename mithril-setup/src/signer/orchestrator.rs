//! The orchestration for the signer (Discovery, Guessing)

use crate::{
    orchestrator::{
        interfaces::Orchestrator,
        store::{State, Store},
    },
    signer::discoverer::{SignerDiscoverer, SignerDiscovery},
};

/// Representation of a Signer
struct SignerOrchestrator {
    pub store: Store,
    discoverer: SignerDiscoverer,
}

impl Orchestrator for SignerOrchestrator {
    type Discovery = SignerDiscovery;
    type Discoverer = SignerDiscoverer;

    fn discoverer(&self) -> &Self::Discoverer {
        &self.discoverer
    }

    fn apply_discovery(&self, discovery: Self::Discovery) -> anyhow::Result<Store> {
        let mut store = self.store.clone();

        store
            .update_field("network", discovery.network, State::Discovered)?
            .update_field("toto", discovery.toto, State::Discovered)?;

        Ok(store)
    }
}
#[cfg(test)]
mod test {
    use crate::orchestrator::store::{Field, FieldType};

    use super::*;

    #[test]
    fn test_signer_orchestrator_discover_must_fill_store_with_information_from_the_discoverer() {
        let signer_orchestrator = SignerOrchestrator {
            store: Store::new(vec![
                Field::init(
                    "network".to_string(),
                    "description".to_string(),
                    FieldType::String,
                    None,
                ),
                Field::init(
                    "toto".to_string(),
                    "description".to_string(),
                    FieldType::String,
                    None,
                ),
            ]),
            discoverer: SignerDiscoverer,
        };

        unsafe { std::env::set_var("NETWORK", "mainnet") };

        let actual_network = signer_orchestrator.store.get_field("network").unwrap();
        assert_eq!(None, actual_network.value.clone());
        assert_eq!(State::Unset, actual_network.state);

        let actual_toto = signer_orchestrator.store.get_field("toto").unwrap();
        assert_eq!(None, actual_toto.value.clone());
        assert_eq!(State::Unset, actual_toto.state);

        let store_updated = signer_orchestrator.discover().unwrap();

        let actual_network = store_updated.get_field("network").unwrap();
        assert_eq!("mainnet", actual_network.value.clone().unwrap());
        assert_eq!(State::Discovered, actual_network.state);

        let actual_toto = store_updated.get_field("toto").unwrap();
        assert_eq!("toto", actual_toto.value.clone().unwrap());
        assert_eq!(State::Discovered, actual_toto.state);
    }
}
