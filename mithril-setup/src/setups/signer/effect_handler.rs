//! Effect handler of the Mithril signer setup

use async_trait::async_trait;

use crate::runner::{EffectHandler, ReviewOutcome};
use crate::schema::{FieldError, check_store};
use crate::setups::signer::{CARDANO_NODE_SOCKET_PATH, NETWORK, signer_schema};
use crate::store::{Origin, Store};
use crate::tui;

/// Effect handler performing the I/O needed to setup a Mithril signer
pub struct SignerEffectHandler;

#[async_trait]
impl EffectHandler for SignerEffectHandler {
    async fn discover(&self) -> Result<Store, String> {
        // Hardcoded values until the real discovery is implemented
        let mut store = Store::default();
        store.set(
            CARDANO_NODE_SOCKET_PATH,
            "/ipc/node.socket",
            Origin::Discovered,
        );
        store.set(NETWORK, "preview", Origin::Discovered);

        Ok(store)
    }

    async fn guess(&self, store: Store) -> Result<Store, String> {
        Ok(store)
    }

    async fn review(&self, store: Store, errors: Vec<FieldError>) -> Result<ReviewOutcome, String> {
        tokio::task::spawn_blocking(move || tui::terminal::review(signer_schema(), store, errors))
            .await
            .map_err(|error| format!("Review task failed: {error}"))?
            .map_err(|error| format!("Review failed: {error}"))
    }

    async fn validate(&self, store: Store) -> Result<(), Vec<FieldError>> {
        check_store(&signer_schema(), &store)
    }

    async fn save(&self, store: Store) -> Result<(), String> {
        println!("{store:?}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discover_returns_values_following_the_signer_schema() {
        let store = SignerEffectHandler.discover().await.unwrap();

        assert_eq!(Ok(()), check_store(&signer_schema(), &store));
    }

    #[tokio::test]
    async fn guess_returns_the_given_store() {
        let result = SignerEffectHandler.guess(Store::default()).await;

        assert_eq!(Ok(Store::default()), result);
    }

    #[tokio::test]
    async fn validate_accepts_the_discovered_store() {
        let store = SignerEffectHandler.discover().await.unwrap();

        let result = SignerEffectHandler.validate(store).await;

        assert_eq!(Ok(()), result);
    }

    #[tokio::test]
    async fn validate_rejects_a_store_not_following_the_signer_schema() {
        let result = SignerEffectHandler.validate(Store::default()).await;

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    #[tokio::test]
    async fn save_succeeds() {
        let result = SignerEffectHandler.save(Store::default()).await;

        assert_eq!(Ok(()), result);
    }
}
