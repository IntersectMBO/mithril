//! Effect handler of the Mithril signer setup

use async_trait::async_trait;

use crate::runner::{EffectHandler, ResultOutcome, ReviewOutcome};
use crate::schema::{FieldError, check_store};
use crate::setups::signer::{
    AGGREGATOR_ENDPOINT, CARDANO_NODE_SOCKET_PATH, DATA_STORES_DIRECTORY, DB_DIRECTORY,
    ENABLE_METRICS_SERVER, ERA_READER_ADAPTER_PARAMS, ERA_READER_ADAPTER_TYPE, KES_SECRET_KEY_PATH,
    METRICS_SERVER_IP, NETWORK, NETWORK_MAGIC, PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG,
    RUN_INTERVAL, STORE_RETENTION_LIMIT, signer_schema,
};
use crate::store::{Origin, Store};
use crate::tui;
use crate::tui::setup_result::model::SetupResult;

/// Era reader adapter parameters of the mainnet example of the signer guide, a long value
// Placeholder until the real guessing is implemented
const ERA_READER_ADAPTER_PARAMS_EXAMPLE: &str = r#"{"address": "addr1qy72kwgm6kypyc5maw0h8mfagwag8wjnx6emgfnsnhqaml6gx7gg4tzplw9l32nsgclqax7stc4u6c5dn0ctljwscm2sqv0teg", "verification_key": "5b31312c3133342c3231352c37362c3134312c3232302c3131312c3135342c36332c3233302c3131342c31322c38372c37342c39342c3137322c3133322c32372c39362c3138362c3132362c3137382c31392c3131342c33302c3234332c36342c3134312c3131302c38332c38362c31395d"}"#;

/// Protocol configuration reader adapter configuration of the mainnet example of the signer guide
// Placeholder until the real guessing is implemented
const PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG_EXAMPLE: &str = r#"{"type": "cardano-chain", "address": "addr1v9lsegaw82vh9w37km08s8szleet6adw82xzl8wjujpcyxq84hq9a", "verification_key": "5b3134392c3133392c38352c38302c32342c3130352c3130382c3138332c33352c33382c33382c34342c37332c3130312c3136392c35352c372c37382c302c3136372c3231302c31392c31392c3138372c3134312c37352c3134352c36392c31312c3234382c3132322c31305d"}"#;

/// Message shown once the setup script is generated
const SCRIPT_GENERATED_MESSAGE: &str = "The setup script of the Mithril signer is generated";

/// Placeholder of the command running the setup script, to update once the script exists
const SETUP_COMMAND_PLACEHOLDER: &str = "./mithril-signer-setup.sh --env-file ./mithril-signer.env";

/// Effect handler performing the I/O needed to setup a Mithril signer
pub struct SignerEffectHandler;

#[async_trait]
impl EffectHandler for SignerEffectHandler {
    async fn discover(&self) -> Result<Store, String> {
        // Hardcoded values until the real discovery is used, the operational certificate is left
        // unset to show a missing value
        // The Cardano CLI path is neither discovered nor guessed, the user enters it
        let mut store = Store::default();
        for (key, value) in [
            (CARDANO_NODE_SOCKET_PATH, "/ipc/node.socket"),
            (DB_DIRECTORY, "/cardano/db"),
            (KES_SECRET_KEY_PATH, "/cardano/keys/kes.skey"),
        ] {
            store.set(key, value, Origin::Discovered);
        }

        Ok(store)
    }

    async fn guess(&self, mut store: Store) -> Result<Store, String> {
        // Hardcoded values until the real guessing is implemented, the network and its magic are
        // guessed from the network discovered from the node files
        for (key, value) in [
            (NETWORK, "preview"),
            (NETWORK_MAGIC, "2"),
            (
                AGGREGATOR_ENDPOINT,
                "https://aggregator.pre-release-preview.api.mithril.network/aggregator",
            ),
            (ERA_READER_ADAPTER_TYPE, "cardano-chain"),
            (ERA_READER_ADAPTER_PARAMS, ERA_READER_ADAPTER_PARAMS_EXAMPLE),
            (
                PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG,
                PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG_EXAMPLE,
            ),
            (DATA_STORES_DIRECTORY, "/opt/mithril/stores"),
            (STORE_RETENTION_LIMIT, "5"),
            (RUN_INTERVAL, "60000"),
            (ENABLE_METRICS_SERVER, "true"),
            (METRICS_SERVER_IP, "0.0.0.0"),
        ] {
            store.set(key, value, Origin::Guessed);
        }

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
    use crate::setups::signer::{CARDANO_CLI_PATH, OPERATIONAL_CERTIFICATE_PATH};

    use super::*;

    async fn discovered_and_guessed_store() -> Store {
        let discovered = SignerEffectHandler.discover().await.unwrap();

        SignerEffectHandler.guess(discovered).await.unwrap()
    }

    #[tokio::test]
    async fn discover_and_guess_set_all_the_required_values_but_the_cli_and_the_certificate() {
        let store = discovered_and_guessed_store().await;

        assert_eq!(
            Err(vec![
                FieldError::new(CARDANO_CLI_PATH, "Cardano CLI path is required"),
                FieldError::new(
                    OPERATIONAL_CERTIFICATE_PATH,
                    "Operational certificate path is required"
                ),
            ]),
            check_store(&signer_schema(), &store)
        );
    }

    #[tokio::test]
    async fn guess_keeps_the_discovered_values_and_adds_guessed_ones() {
        let store = discovered_and_guessed_store().await;

        let origin = |key| store.get(key).map(|entry| entry.origin);
        assert_eq!(Some(Origin::Discovered), origin(CARDANO_NODE_SOCKET_PATH));
        assert_eq!(Some(Origin::Guessed), origin(AGGREGATOR_ENDPOINT));
    }

    #[tokio::test]
    async fn validate_accepts_the_discovered_and_guessed_store_once_completed() {
        let mut store = discovered_and_guessed_store().await;
        store.set(CARDANO_CLI_PATH, "cardano-cli", Origin::User);
        store.set(
            OPERATIONAL_CERTIFICATE_PATH,
            "/cardano/keys/node.cert",
            Origin::User,
        );

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
