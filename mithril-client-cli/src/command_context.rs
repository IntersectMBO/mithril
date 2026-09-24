use anyhow::anyhow;
use slog::Logger;
use std::str::FromStr;
use std::sync::Arc;

use mithril_client::{
    AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MithrilResult,
};

use crate::certificate_chain_cache::CertificateChainCacheConfiguration;
use crate::configuration::ConfigParameters;
use crate::utils::ForcedEraFetcher;

/// Context for the command execution
pub struct CommandContext {
    config_parameters: ConfigParameters,
    unstable_enabled: bool,
    json: bool,
    logger: Logger,
    certificate_chain_cache: CertificateChainCacheConfiguration,
}

impl CommandContext {
    /// Create a new command context
    pub fn new(
        config_parameters: ConfigParameters,
        unstable_enabled: bool,
        json: bool,
        logger: Logger,
    ) -> Self {
        Self {
            config_parameters,
            unstable_enabled,
            json,
            logger,
            certificate_chain_cache: CertificateChainCacheConfiguration::default(),
        }
    }

    /// Set the certificate chain cache configuration
    pub fn with_certificate_chain_cache(
        mut self,
        certificate_chain_cache: CertificateChainCacheConfiguration,
    ) -> Self {
        self.certificate_chain_cache = certificate_chain_cache;
        self
    }

    /// Check if unstable commands are enabled
    pub fn is_unstable_enabled(&self) -> bool {
        self.unstable_enabled
    }

    /// Check if JSON output is enabled
    pub fn is_json_output_enabled(&self) -> bool {
        self.json
    }

    /// Ensure that unstable commands are enabled
    pub fn require_unstable(
        &self,
        sub_command: &str,
        command_example: Option<&str>,
    ) -> MithrilResult<()> {
        if self.is_unstable_enabled() {
            Ok(())
        } else {
            let example = command_example.map(|e| format!(" {e}")).unwrap_or_default();
            Err(anyhow!(
                "The \"{sub_command}\" subcommand is only accepted using the --unstable flag.\n\n\
                ie: \"mithril-client --unstable {sub_command}{example}\""
            ))
        }
    }

    /// Get a reference to the configured parameters
    pub fn config_parameters(&self) -> &ConfigParameters {
        &self.config_parameters
    }

    /// Get a mutable reference to the configured parameters
    pub fn config_parameters_mut(&mut self) -> &mut ConfigParameters {
        &mut self.config_parameters
    }

    /// Get the shared logger
    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    /// Get the certificate chain cache configuration
    pub fn certificate_chain_cache(&self) -> &CertificateChainCacheConfiguration {
        &self.certificate_chain_cache
    }

    /// Set up a mithril client builder with the configured parameters and the certificate chain
    /// cache, if enabled.
    pub fn setup_mithril_client_builder(&self) -> MithrilResult<ClientBuilder> {
        let builder = self.setup_mithril_client_builder_internal(None)?;
        self.add_certificate_chain_cache(builder)
    }

    /// Add the certificate chain cache to the given client builder, if enabled.
    ///
    /// The cache directory is prepared first, so only the commands that verify a certificate
    /// chain should call it.
    pub fn add_certificate_chain_cache(
        &self,
        builder: ClientBuilder,
    ) -> MithrilResult<ClientBuilder> {
        match self.certificate_chain_cache.verifier_cache() {
            Some((cache, mode)) => {
                self.certificate_chain_cache.prepare_directory()?;
                Ok(builder.with_certificate_verifier_cache(Some(cache), mode))
            }
            None => Ok(builder),
        }
    }

    /// Set up a mithril client builder with the configured parameters, but with a dummy genesis verification key.
    ///
    /// [ClientBuilder](mithril_client::ClientBuilder) always requires one to build the client, but
    /// it's really used with commands that run certificate chain verification.
    pub fn setup_mithril_client_builder_with_fallback_genesis_key(
        &self,
    ) -> MithrilResult<ClientBuilder> {
        // TODO: This should not be done this way.
        // Now that mithril-client-cli uses the mithril-client library, the genesis verification key is required for all commands
        const FALLBACK_GENESIS_VERIFICATION_KEY: &str = "5b33322c3235332c3138362c3230312c3137372c31312c3131372c3133352c3138372c3136372c3138312c3138\
        382c32322c35392c3230362c3130352c3233312c3135302c3231352c33302c37382c3231322c37362c31362c323\
        5322c3138302c37322c3133342c3133372c3234372c3136312c36385d";

        self.setup_mithril_client_builder_internal(Some(FALLBACK_GENESIS_VERIFICATION_KEY))
    }

    fn setup_mithril_client_builder_internal(
        &self,
        fallback_genesis_verification_key: Option<&str>,
    ) -> MithrilResult<ClientBuilder> {
        const CLIENT_TYPE_CLI: &str = "CLI";

        let params = self.config_parameters();
        let mut builder = ClientBuilder::new(AggregatorDiscoveryType::from_str(
            &params.require("aggregator_endpoint")?,
        )?)
        .with_logger(self.logger().clone())
        .with_origin_tag(params.get("origin_tag"))
        .with_client_type(Some(CLIENT_TYPE_CLI.to_string()));

        if let Some(fallback_genesis_verification_key) = fallback_genesis_verification_key {
            builder = builder.set_genesis_verification_key(GenesisVerificationKey::JsonHex(
                params.get_or(
                    "genesis_verification_key",
                    fallback_genesis_verification_key,
                ),
            ));
        } else {
            builder = builder.set_genesis_verification_key(GenesisVerificationKey::JsonHex(
                params.require("genesis_verification_key")?,
            ));
        }

        if let Some(era) = params.get("era") {
            builder = builder.with_era_fetcher(Arc::new(ForcedEraFetcher::new(era.to_string())));
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use slog::o;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::certificate_chain_cache::CertificateChainCacheMode;
    use crate::configuration::{ConfigError, ConfigSource};

    use super::*;

    #[test]
    fn require_unstable_return_ok_if_unstable_enabled() {
        let unstable_enabled = true;
        let context = CommandContext::new(
            ConfigParameters::default(),
            unstable_enabled,
            true,
            Logger::root(slog::Discard, o!()),
        );

        let result = context.require_unstable("test", None);
        assert!(result.is_ok(), "Expected Ok, got {result:?}");
    }

    #[test]
    fn require_unstable_return_err_if_unstable_disabled() {
        let unstable_enabled = false;
        let context = CommandContext::new(
            ConfigParameters::default(),
            unstable_enabled,
            true,
            Logger::root(slog::Discard, o!()),
        );

        let result = context.require_unstable("test", None);
        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    #[test]
    fn can_edit_config_parameters() {
        struct ParamSource {
            key: String,
            value: String,
        }
        impl ConfigSource for ParamSource {
            fn collect(&self) -> Result<HashMap<String, String>, ConfigError> {
                Ok(HashMap::from([(self.key.clone(), self.value.clone())]))
            }
        }

        let mut context = CommandContext::new(
            ConfigParameters::default(),
            false,
            true,
            Logger::root(slog::Discard, o!()),
        );

        assert_eq!(context.config_parameters_mut().get("key"), None,);

        context
            .config_parameters_mut()
            .add_source(&ParamSource {
                key: "key".to_string(),
                value: "value".to_string(),
            })
            .unwrap();

        assert_eq!(
            context.config_parameters_mut().get("key"),
            Some("value".to_string())
        );
    }

    mod certificate_chain_cache {
        use mithril_common::temp_dir_create;

        use super::*;

        fn context_with_certificate_chain_cache(
            cache_enabled: bool,
            cache_directory: PathBuf,
        ) -> CommandContext {
            let config_parameters = ConfigParameters::new(HashMap::from([
                (
                    "aggregator_endpoint".to_string(),
                    "http://localhost:8080/aggregator".to_string(),
                ),
                (
                    "genesis_verification_key".to_string(),
                    "genesis_verification_key".to_string(),
                ),
            ]));

            CommandContext::new(
                config_parameters,
                true,
                true,
                Logger::root(slog::Discard, o!()),
            )
            .with_certificate_chain_cache(CertificateChainCacheConfiguration {
                enabled: cache_enabled,
                mode: CertificateChainCacheMode::EarlyStopVerification,
                directory: cache_directory,
            })
        }

        fn has_marker_file(cache_directory: &Path) -> bool {
            cache_directory
                .join(CertificateChainCacheConfiguration::MARKER_FILE_NAME)
                .is_file()
        }

        #[test]
        fn setup_client_builder_prepares_the_cache_directory_if_cache_enabled() {
            let cache_directory = temp_dir_create!().join("cache");
            let context = context_with_certificate_chain_cache(true, cache_directory.clone());

            context.setup_mithril_client_builder().unwrap();

            assert!(has_marker_file(&cache_directory));
        }

        #[test]
        fn setup_client_builder_fails_if_cache_enabled_in_a_foreign_directory() {
            let cache_directory = temp_dir_create!();
            fs::write(cache_directory.join("data.txt"), "content").unwrap();
            let context = context_with_certificate_chain_cache(true, cache_directory);

            let result = context.setup_mithril_client_builder();

            assert!(result.is_err(), "Expected Err, got Ok");
        }

        #[test]
        fn setup_client_builder_does_not_touch_the_cache_directory_if_cache_disabled() {
            let cache_directory = temp_dir_create!().join("cache");
            let context = context_with_certificate_chain_cache(false, cache_directory.clone());

            context.setup_mithril_client_builder().unwrap();

            assert!(!cache_directory.exists());
        }

        #[test]
        fn setup_client_builder_with_fallback_genesis_key_does_not_touch_the_cache_directory() {
            let cache_directory = temp_dir_create!().join("cache");
            let context = context_with_certificate_chain_cache(true, cache_directory.clone());

            context
                .setup_mithril_client_builder_with_fallback_genesis_key()
                .unwrap();

            assert!(!cache_directory.exists());
        }

        #[test]
        fn add_certificate_chain_cache_prepares_the_cache_directory_if_cache_enabled() {
            let cache_directory = temp_dir_create!().join("cache");
            let context = context_with_certificate_chain_cache(true, cache_directory.clone());
            let builder = context
                .setup_mithril_client_builder_with_fallback_genesis_key()
                .unwrap();

            context.add_certificate_chain_cache(builder).unwrap();

            assert!(has_marker_file(&cache_directory));
        }
    }
}
