//! Setup of a Mithril signer

use async_trait::async_trait;

use crate::rules::{integer_between, one_of, valid_path};
use crate::runner::{EffectHandler, ReviewOutcome};
use crate::schema::{FieldError, FieldSpec, Presence};
use crate::store::Store;

/// Key of the Cardano node socket path
pub const CARDANO_NODE_SOCKET_PATH: &str = "cardano_node_socket_path";

/// Key of the Cardano network name
pub const NETWORK: &str = "network";

/// Key of the Cardano network magic
pub const NETWORK_MAGIC: &str = "network_magic";

/// Configuration values expected to setup a Mithril signer
pub fn signer_schema() -> Vec<FieldSpec> {
    vec![
        FieldSpec {
            key: CARDANO_NODE_SOCKET_PATH,
            label: "Cardano node socket path",
            description: "Path of the IPC socket of the Cardano node",
            presence: Presence::Required,
            rules: vec![valid_path()],
        },
        FieldSpec {
            key: NETWORK,
            label: "Network",
            description: "Name of the Cardano network",
            presence: Presence::Required,
            rules: vec![one_of(&["mainnet", "preprod", "preview"])],
        },
        FieldSpec {
            key: NETWORK_MAGIC,
            label: "Network magic",
            description: "Magic number of the Cardano network",
            presence: Presence::Optional,
            rules: vec![integer_between(0, u32::MAX as u64)],
        },
    ]
}

/// Effect handler performing the I/O needed to setup a Mithril signer
pub struct SignerEffectHandler;

#[async_trait]
impl EffectHandler for SignerEffectHandler {
    async fn discover(&self) -> Result<Store, String> {
        Ok(Store::default())
    }

    async fn guess(&self, store: Store) -> Result<Store, String> {
        Ok(store)
    }

    async fn review(&self, store: Store, _errors: Vec<FieldError>) -> ReviewOutcome {
        ReviewOutcome::Confirmed(store)
    }

    async fn validate(&self, _store: Store) -> Result<(), Vec<FieldError>> {
        Ok(())
    }

    async fn save(&self, store: Store) -> Result<(), String> {
        println!("{store:?}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod schema {
        use crate::schema::check_store;
        use crate::store::Origin;

        use super::*;

        fn valid_store() -> Store {
            let mut store = Store::default();
            store.set(
                CARDANO_NODE_SOCKET_PATH,
                "/ipc/node.socket",
                Origin::Discovered,
            );
            store.set(NETWORK, "preview", Origin::Guessed);
            store.set(NETWORK_MAGIC, "2", Origin::Guessed);
            store
        }

        #[test]
        fn accepts_a_valid_store() {
            assert_eq!(Ok(()), check_store(&signer_schema(), &valid_store()));
        }
    }

    #[tokio::test]
    async fn discover_returns_an_empty_store() {
        let result = SignerEffectHandler.discover().await;

        assert_eq!(Ok(Store::default()), result);
    }

    #[tokio::test]
    async fn guess_returns_the_given_store() {
        let result = SignerEffectHandler.guess(Store::default()).await;

        assert_eq!(Ok(Store::default()), result);
    }

    #[tokio::test]
    async fn review_confirms_the_given_store() {
        let result = SignerEffectHandler.review(Store::default(), vec![]).await;

        assert_eq!(ReviewOutcome::Confirmed(Store::default()), result);
    }

    #[tokio::test]
    async fn validate_accepts_any_store() {
        let result = SignerEffectHandler.validate(Store::default()).await;

        assert_eq!(Ok(()), result);
    }

    #[tokio::test]
    async fn save_succeeds() {
        let result = SignerEffectHandler.save(Store::default()).await;

        assert_eq!(Ok(()), result);
    }
}
