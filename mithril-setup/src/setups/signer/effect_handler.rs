//! Effect handler of the Mithril signer setup

use async_trait::async_trait;

use crate::runner::{EffectHandler, ResultOutcome, ReviewOutcome};
use crate::schema::{FieldError, check_store};
use crate::setups::signer::{CARDANO_NODE_SOCKET_PATH, NETWORK, signer_schema};
use crate::store::{Origin, Store};
use crate::tui;
use crate::tui::setup_result::model::SetupResult;

/// Message shown once the setup script is generated
const SCRIPT_GENERATED_MESSAGE: &str = "The setup script of the Mithril signer is generated";

/// Placeholder of the command running the setup script, to update once the script exists
const SETUP_COMMAND_PLACEHOLDER: &str = "./mithril-signer-setup.sh --env-file ./mithril-signer.env";

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

    async fn export_to_artifact(&self, _store: Store) -> Result<(), String> {
        // The setup script is not generated yet
        Ok(())
    }

    async fn show_result(&self) -> Result<ResultOutcome, String> {
        let setup_result = SetupResult {
            message: SCRIPT_GENERATED_MESSAGE,
            command: SETUP_COMMAND_PLACEHOLDER,
        };

        tokio::task::spawn_blocking(move || tui::terminal::show_result(setup_result))
            .await
            .map_err(|error| format!("Result task failed: {error}"))?
            .map_err(|error| format!("Result display failed: {error}"))
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
        let result = SignerEffectHandler.export_to_artifact(Store::default()).await;

        assert_eq!(Ok(()), result);
    }
}
