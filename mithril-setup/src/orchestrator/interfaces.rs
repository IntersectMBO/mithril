//! Discoverer module interface

use crate::orchestrator::store::Store;

/// Discoverer trait defines the interface for discovering configuration values
pub trait Discoverer {
    /// The output structure reprensenting the discovery
    type Output;

    /// Run the discoverer logic and fill the output structure
    fn discover(&self) -> anyhow::Result<Self::Output>;
}

/// Orchestrator trait, performing the effects requested by the state machine
pub trait Orchestrator {
    /// type representing the discoverer result
    type Discovery;
    /// type representing the discoverer logic
    type Discoverer: Discoverer<Output = Self::Discovery>;

    /// Return the discoverer
    fn discoverer(&self) -> &Self::Discoverer;

    /// Return the store with all the fields to fill, not set yet
    fn initial_store(&self) -> Store;

    /// Update the given store with the discovery
    fn apply_discovery(&self, store: Store, discovery: Self::Discovery) -> anyhow::Result<Store>;

    /// Persist the given store
    fn save(&self, store: &Store) -> anyhow::Result<()>;

    /// Run the discoverer and then update the initial store with the discovery
    fn discover(&self) -> anyhow::Result<Store> {
        let discovery = self.discoverer().discover()?;
        self.apply_discovery(self.initial_store(), discovery)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::cell::RefCell;

    use crate::orchestrator::{
        interfaces::Discoverer,
        store::{Field, FieldState, FieldType},
    };

    use super::*;

    #[derive(Default)]
    pub(crate) struct MockDiscoverer;
    pub(crate) struct MockDiscovery {
        color: String,
        shape: String,
    }
    impl Discoverer for MockDiscoverer {
        type Output = MockDiscovery;
        fn discover(&self) -> anyhow::Result<Self::Output> {
            Ok(MockDiscovery {
                color: "Purple".to_string(),
                shape: "Rectangle".to_string(),
            })
        }
    }

    #[derive(Default)]
    pub(crate) struct MockOrchestrator {
        discoverer: MockDiscoverer,
        pub saved_stores: RefCell<Vec<Store>>,
    }

    impl Orchestrator for MockOrchestrator {
        type Discovery = MockDiscovery;
        type Discoverer = MockDiscoverer;

        fn discoverer(&self) -> &Self::Discoverer {
            &self.discoverer
        }

        fn initial_store(&self) -> Store {
            Store::new(vec![
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
            ])
        }

        fn apply_discovery(
            &self,
            mut store: Store,
            discovery: Self::Discovery,
        ) -> anyhow::Result<Store> {
            store
                .update_field("color", discovery.color, FieldState::Discovered)?
                .update_field("shape", discovery.shape, FieldState::Discovered)?;

            Ok(store)
        }

        fn save(&self, store: &Store) -> anyhow::Result<()> {
            self.saved_stores.borrow_mut().push(store.clone());
            Ok(())
        }
    }

    #[test]
    fn test_orchestrator_discover_must_fill_store_with_information_from_the_discoverer() {
        let orchestrator = MockOrchestrator::default();

        let initial_store = orchestrator.initial_store();

        let actual_color = initial_store.get_field("color").unwrap();
        assert_eq!(None, actual_color.value.clone());
        assert_eq!(FieldState::Unset, actual_color.state);

        let actual_shape = initial_store.get_field("shape").unwrap();
        assert_eq!(None, actual_shape.value.clone());
        assert_eq!(FieldState::Unset, actual_shape.state);

        let store_updated = orchestrator.discover().unwrap();

        let actual_color = store_updated.get_field("color").unwrap();
        assert_eq!("Purple", actual_color.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_color.state);

        let actual_shape = store_updated.get_field("shape").unwrap();
        assert_eq!("Rectangle", actual_shape.value.clone().unwrap());
        assert_eq!(FieldState::Discovered, actual_shape.state);
    }
}
