use std::path::absolute;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use serde_json::json;

use mithril_client::MithrilResult;
use mithril_client::certificate_client::CertificateVerifierCache;

use crate::{
    CertificateChainCacheConfiguration, CertificateChainCacheDirectoryState, CommandContext,
};

/// Cache related commands
#[derive(Subcommand, Debug, Clone)]
pub enum CacheCommands {
    /// Reset the certificate chain cache
    Reset(CacheResetCommand),
}

impl CacheCommands {
    /// Execute cache command
    pub async fn execute(&self, context: CommandContext) -> MithrilResult<()> {
        match self {
            Self::Reset(cmd) => cmd.execute(context).await,
        }
    }
}

/// Clap command to reset the certificate chain cache
#[derive(Parser, Debug, Clone)]
pub struct CacheResetCommand {}

impl CacheResetCommand {
    /// Main command execution
    pub async fn execute(&self, context: CommandContext) -> MithrilResult<()> {
        let configuration = context.certificate_chain_cache();
        let cache_directory = absolute(&configuration.directory).with_context(|| {
            format!(
                "Failed to resolve the certificate chain cache path '{}'",
                configuration.directory.display()
            )
        })?;

        let is_reset = Self::reset_cache(configuration).await.with_context(|| {
            format!(
                "Failed to reset the certificate chain cache in '{}'",
                cache_directory.display()
            )
        })?;

        if context.is_json_output_enabled() {
            println!(
                "{}",
                json!({
                    "certificate_chain_cache_path": cache_directory.display().to_string(),
                    "reset": is_reset,
                })
            );
        } else if is_reset {
            println!(
                "Certificate chain cache reset in '{}'",
                cache_directory.display()
            );
        } else {
            println!(
                "No certificate chain cache data found in '{}'",
                cache_directory.display()
            );
        }

        Ok(())
    }

    /// Reset the cache of the given configuration, returning whether it held data
    async fn reset_cache(
        configuration: &CertificateChainCacheConfiguration,
    ) -> MithrilResult<bool> {
        match configuration.directory_state()? {
            CertificateChainCacheDirectoryState::Foreign => Err(anyhow!(
                "Directory is not empty and is not a certificate chain cache, it was not reset"
            )),
            CertificateChainCacheDirectoryState::Absent => Ok(false),
            CertificateChainCacheDirectoryState::Cache => {
                configuration.build_cache().reset().await?;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use slog::Logger;

    use mithril_client::MithrilCertificate;
    use mithril_client::certificate_client::CertificateVerifierCacheSpace;
    use mithril_common::crypto_helper::GenesisSigner;
    use mithril_common::temp_dir_create;
    use mithril_common::test::double::Dummy;

    use crate::{CertificateChainCacheMode, ConfigParameters};

    use super::*;

    fn directory_entries(directory: &Path) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        entries.sort();
        entries
    }

    fn dummy_certificate(hash: &str) -> MithrilCertificate {
        MithrilCertificate {
            hash: hash.to_string(),
            ..Dummy::dummy()
        }
    }

    #[tokio::test]
    async fn reset_leaves_only_the_marker_file_in_the_cache_directory() {
        let directory = temp_dir_create!();
        let configuration = CertificateChainCacheConfiguration {
            enabled: false,
            mode: CertificateChainCacheMode::FullVerification,
            directory: directory.clone(),
        };
        let space = CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        );
        configuration.prepare_directory().unwrap();
        let cache = configuration.build_cache();
        cache
            .stage_certificate("committed_chain_id", dummy_certificate("committed"))
            .await
            .unwrap();
        cache
            .commit_staged_certificates(&space, "committed_chain_id")
            .await
            .unwrap();
        cache
            .stage_certificate("staged_chain_id", dummy_certificate("staged"))
            .await
            .unwrap();
        assert_eq!(
            vec![
                CertificateChainCacheConfiguration::MARKER_FILE_NAME.to_string(),
                "committed".to_string(),
                "staged".to_string(),
            ],
            directory_entries(&directory)
        );
        let context = CommandContext::new(
            ConfigParameters::default(),
            true,
            true,
            Logger::root(slog::Discard, slog::o!()),
        )
        .with_certificate_chain_cache(configuration);

        CacheResetCommand {}.execute(context).await.unwrap();

        assert_eq!(
            vec![CertificateChainCacheConfiguration::MARKER_FILE_NAME.to_string()],
            directory_entries(&directory)
        );
    }

    #[tokio::test]
    async fn reset_succeeds_when_the_cache_directory_does_not_exist() {
        let configuration = CertificateChainCacheConfiguration {
            enabled: false,
            mode: CertificateChainCacheMode::FullVerification,
            directory: temp_dir_create!().join("not_existing"),
        };
        let context = CommandContext::new(
            ConfigParameters::default(),
            true,
            true,
            Logger::root(slog::Discard, slog::o!()),
        )
        .with_certificate_chain_cache(configuration);

        CacheResetCommand {}.execute(context).await.unwrap();
    }

    #[tokio::test]
    async fn reset_refuses_a_directory_that_is_not_a_certificate_chain_cache() {
        let directory = temp_dir_create!();
        let foreign_directory = directory.join("committed");
        fs::create_dir(&foreign_directory).unwrap();
        let configuration = CertificateChainCacheConfiguration {
            enabled: false,
            mode: CertificateChainCacheMode::FullVerification,
            directory,
        };
        let context = CommandContext::new(
            ConfigParameters::default(),
            true,
            true,
            Logger::root(slog::Discard, slog::o!()),
        )
        .with_certificate_chain_cache(configuration);

        CacheResetCommand {}
            .execute(context)
            .await
            .expect_err("Reset should refuse a foreign directory");

        assert!(foreign_directory.is_dir());
    }

    mod reset_cache {
        use super::*;

        fn configuration(directory: PathBuf) -> CertificateChainCacheConfiguration {
            CertificateChainCacheConfiguration {
                enabled: false,
                mode: CertificateChainCacheMode::FullVerification,
                directory,
            }
        }

        #[tokio::test]
        async fn returns_true_when_the_cache_holds_data() {
            let configuration = configuration(temp_dir_create!());
            configuration.prepare_directory().unwrap();
            configuration
                .build_cache()
                .stage_certificate("chain_id", dummy_certificate("hash"))
                .await
                .unwrap();

            let is_reset = CacheResetCommand::reset_cache(&configuration).await.unwrap();

            assert!(is_reset);
        }

        #[tokio::test]
        async fn returns_false_when_the_cache_holds_only_the_marker_file() {
            let configuration = configuration(temp_dir_create!());
            configuration.prepare_directory().unwrap();

            let is_reset = CacheResetCommand::reset_cache(&configuration).await.unwrap();

            assert!(!is_reset);
        }

        #[tokio::test]
        async fn returns_false_when_the_cache_directory_does_not_exist() {
            let configuration = configuration(temp_dir_create!().join("not_existing"));

            let is_reset = CacheResetCommand::reset_cache(&configuration).await.unwrap();

            assert!(!is_reset);
        }

        #[tokio::test]
        async fn returns_false_on_a_second_reset() {
            let configuration = configuration(temp_dir_create!());
            configuration.prepare_directory().unwrap();
            configuration
                .build_cache()
                .stage_certificate("chain_id", dummy_certificate("hash"))
                .await
                .unwrap();
            CacheResetCommand::reset_cache(&configuration).await.unwrap();

            let is_reset = CacheResetCommand::reset_cache(&configuration).await.unwrap();

            assert!(!is_reset);
        }
    }
}
