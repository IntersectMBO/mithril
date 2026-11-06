//! Setup of a Mithril signer

use async_trait::async_trait;

use crate::runner::EffectHandler;
use crate::store::Store;

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

    async fn review(&self, store: Store, _errors: Vec<String>) -> Store {
        store
    }

    async fn validate(&self, _store: Store) -> Result<(), Vec<String>> {
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
    async fn review_returns_the_given_store() {
        let result = SignerEffectHandler.review(Store::default(), vec![]).await;

        assert_eq!(Store::default(), result);
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
