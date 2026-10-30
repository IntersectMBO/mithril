//! Discoverer module interface

use crate::orchestrator::store::Store;

/// Discoverer trait defines the interface for discovering configuration values
pub trait Discoverer {
    /// The output structure reprensenting the discovery
    type Output;

    /// Run the discoverer logic and fill the output structure
    fn run(&self) -> anyhow::Result<Self::Output>;
}

/// Orchestrator trait, working with a mutable store
pub trait Orchestrator {
    /// type representing the discoverer result
    type Discovery;
    /// type representing the discoverer logic
    type Discoverer: Discoverer<Output = Self::Discovery>;

    /// Return the discoverer
    fn discoverer(&self) -> &Self::Discoverer;

    /// Update the store with the discovery
    fn apply_discovery(&self, discovery: Self::Discovery) -> anyhow::Result<Store>;

    /// Run the discoverer and then update the store with the discovery
    fn discover(&self) -> anyhow::Result<Store> {
        let discovery = self.discoverer().run()?;
        self.apply_discovery(discovery)
    }
}

#[cfg(test)]
mod test {
    use crate::orchestrator::{
        interfaces::Discoverer,
        store::{Field, FieldType, State},
    };

    use super::*;

    struct MockDiscoverer;
    struct MockDiscovery {
        color: String,
        shape: String,
    }
    impl Discoverer for MockDiscoverer {
        type Output = MockDiscovery;
        fn run(&self) -> anyhow::Result<Self::Output> {
            Ok(MockDiscovery {
                color: "Purple".to_string(),
                shape: "Rectangle".to_string(),
            })
        }
    }

    struct MockOrchestrator {
        pub store: Store,
        discoverer: MockDiscoverer,
    }

    impl Orchestrator for MockOrchestrator {
        type Discovery = MockDiscovery;
        type Discoverer = MockDiscoverer;

        fn discoverer(&self) -> &Self::Discoverer {
            &self.discoverer //TODO can be a blanket of the trait ?
        }

        fn apply_discovery(&self, discovery: Self::Discovery) -> anyhow::Result<Store> {
            let mut store = self.store.clone();

            store
                .update_field(
                    "color",
                    discovery.color,
                    // State::Discovered
                )?
                .update_field(
                    "shape",
                    discovery.shape,
                    // State::Discovered
                )?;

            Ok(store)
        }
    }

    #[test]
    fn test_orchestrator_discover_must_fill_store_with_information_from_the_discoverer() {
        let signer_orchestrator = MockOrchestrator {
            store: Store::new(vec![
                Field::init(
                    "color".to_string(),
                    "description".to_string(),
                    FieldType::String,
                    None,
                ),
                Field::init(
                    "shape".to_string(),
                    "description".to_string(),
                    FieldType::String,
                    None,
                ),
            ]),
            discoverer: MockDiscoverer,
        };

        let actual_network = signer_orchestrator.store.get_field("color").unwrap();
        assert_eq!(None, actual_network.value.clone());
        //assert_eq!(State::Unset, actual_network.state);

        let actual_toto = signer_orchestrator.store.get_field("shape").unwrap();
        assert_eq!(None, actual_toto.value.clone());
        //assert_eq!(State::Unset, actual_toto.state);

        let store_updated = signer_orchestrator.discover().unwrap();

        let actual_network = store_updated.get_field("color").unwrap();
        assert_eq!("Purple", actual_network.value.clone().unwrap());
        //assert_eq!(State::Discovered, actual_network.state);

        let actual_toto = store_updated.get_field("shape").unwrap();
        assert_eq!("Rectangle", actual_toto.value.clone().unwrap());
        //assert_eq!(State::Discovered, actual_toto.state);
    }
}
