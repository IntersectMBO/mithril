mod v2;

use v2::PreparedCardanoDbV2Download;

use clap::Parser;
use std::{collections::HashMap, path::PathBuf};

use mithril_client::{MithrilResult, common::ImmutableFileNumber};

use crate::{
    CommandContext,
    commands::cardano_db::CardanoDbCommandsBackend,
    configuration::{ConfigError, ConfigSource},
    utils::{self, JSON_CAUTION_KEY, print_simple_warning},
};

const DB_DIRECTORY_NAME: &str = "db";

/// Clap command to download a Cardano db and verify its associated certificate.
#[derive(Parser, Debug, Clone)]
pub struct CardanoDbDownloadCommand {
    /// Backend to use.
    #[arg(short, long, value_enum, default_value_t)]
    backend: CardanoDbCommandsBackend,

    /// Digest of the Cardano db snapshot to download  or `latest` for the latest artifact
    ///
    /// Use the `list` command to get that information.
    digest: String,

    /// Directory where the immutable and ancillary files will be downloaded.
    ///
    /// By default, a subdirectory will be created in this directory to extract and verify the
    /// certificate.
    #[clap(long)]
    download_dir: Option<PathBuf>,

    /// Genesis verification key to check the certificate chain.
    #[clap(long, env = "GENESIS_VERIFICATION_KEY")]
    genesis_verification_key: Option<String>,

    /// `unstable` Set the base URL of a Kubo node's RPC API.
    ///
    /// When set, downloads can use IPFS locations advertised for an artifact. If an IPFS
    /// download fails, the client tries the artifact's other available locations.
    ///
    /// The URL must point to a running and reachable Kubo node, for example, `http://127.0.0.1:5001/`.
    ///
    /// Reminder: The Kubo RPC API provides admin-level access and must never be exposed to the
    /// public internet.
    #[clap(long, env = "IPFS_RPC_URL")]
    ipfs_rpc_url: Option<String>,

    /// Include ancillary files in the download, if set the `ancillary_verification_key` is required
    /// in order to verify the ancillary files.
    ///
    /// By default, only finalized immutable files are downloaded.
    /// The last ledger state snapshot and the last immutable file (the ancillary files) can be
    /// downloaded with this option.
    #[clap(long)]
    include_ancillary: bool,

    /// Ancillary verification key to verify the ancillary files.
    #[clap(long, env = "ANCILLARY_VERIFICATION_KEY")]
    ancillary_verification_key: Option<String>,

    /// The first immutable file number to download.
    ///
    /// If not set, the download process will start from the first immutable file.
    #[clap(long)]
    start: Option<ImmutableFileNumber>,

    /// The last immutable file number to download.
    ///
    /// If not set, the download will continue until the last certified immutable file.
    #[clap(long)]
    end: Option<ImmutableFileNumber>,

    /// Allow existing files in the download directory to be overridden.
    #[clap(long)]
    allow_override: bool,
}

impl CardanoDbDownloadCommand {
    /// Command execution
    pub async fn execute(&self, mut context: CommandContext) -> MithrilResult<()> {
        context.config_parameters_mut().add_source(self)?;
        match self.backend {
            CardanoDbCommandsBackend::V2 => {
                let prepared_command = self.prepare_v2(&context)?;
                prepared_command.execute(&context).await
            }
        }
    }

    fn prepare_v2(&self, context: &CommandContext) -> MithrilResult<PreparedCardanoDbV2Download> {
        let ancillary_verification_key = if self.include_ancillary {
            self.warn_ancillary_not_signed_by_mithril(context);
            Some(context.config_parameters().require("ancillary_verification_key")?)
        } else {
            self.warn_fast_bootstrap_not_available(context);
            None
        };

        Ok(PreparedCardanoDbV2Download {
            hash: self.digest.clone(),
            download_dir: context.config_parameters().require("download_dir")?,
            start: self.start,
            end: self.end,
            include_ancillary: self.include_ancillary,
            ancillary_verification_key,
            ipfs_rpc_url: self.ipfs_rpc_url.clone(),
            allow_override: self.allow_override,
        })
    }

    /// Provides guidance on how to enable fast bootstrap by including ancillary files
    fn warn_fast_bootstrap_not_available(&self, context: &CommandContext) {
        if context.is_json_output_enabled() {
            let json = serde_json::json!({
                JSON_CAUTION_KEY: "The fast bootstrap of the Cardano node is not available with the current parameters used in this command",
                "impact": "The ledger state will be recomputed from genesis at startup of the Cardano node",
                "solution": {
                    "description": "To activate the fast bootstrap of the Cardano node, add the following parameters to the command:",
                    "parameters": [
                        "--include-ancillary",
                        "--ancillary-verification-key (or environment variable ANCILLARY_VERIFICATION_KEY)"
                    ]
                },
            });
            eprintln!("{json}");
        } else {
            eprintln!("The fast bootstrap of the Cardano node is not available with the current parameters used in this command.
This means that the ledger state will be recomputed from genesis at startup of the Cardano node.

In order to activate the fast bootstrap of the Cardano node, add the following parameters to the command:
--include-ancillary and --ancillary-verification-key (or environment variable ANCILLARY_VERIFICATION_KEY).

Caution: The ancillary files, including the ledger state, are not currently signed by Mithril.
As a mitigation, IOG owned keys are used to sign these files.
For more information, please refer to the network configuration page of the documentation (https://mithril.network/doc/manual/getting-started/network-configurations).");
        }
    }

    fn warn_ancillary_not_signed_by_mithril(&self, context: &CommandContext) {
        let message = "Ancillary verification does not use the Mithril certification: as a mitigation, IOG owned keys are used to sign these files.";

        print_simple_warning(message, context.is_json_output_enabled());
    }
}

impl ConfigSource for CardanoDbDownloadCommand {
    fn collect(&self) -> Result<HashMap<String, String>, ConfigError> {
        let mut map = HashMap::new();

        if let Some(download_dir) = self.download_dir.clone() {
            let param = "download_dir".to_string();
            map.insert(
                param.clone(),
                utils::path_to_string(&download_dir)
                    .map_err(|e| ConfigError::Conversion(param, e))?,
            );
        }

        if let Some(genesis_verification_key) = self.genesis_verification_key.clone() {
            map.insert(
                "genesis_verification_key".to_string(),
                genesis_verification_key,
            );
        }

        if let Some(ancillary_verification_key) = self.ancillary_verification_key.clone() {
            map.insert(
                "ancillary_verification_key".to_string(),
                ancillary_verification_key,
            );
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use slog::Logger;

    use crate::ConfigParameters;

    use super::*;

    fn dummy_command() -> CardanoDbDownloadCommand {
        CardanoDbDownloadCommand {
            backend: Default::default(),
            digest: "whatever_digest".to_string(),
            download_dir: Some(std::path::PathBuf::from("whatever_dir")),
            genesis_verification_key: "whatever".to_string().into(),
            ipfs_rpc_url: None,
            include_ancillary: true,
            ancillary_verification_key: "whatever".to_string().into(),
            start: None,
            end: None,
            allow_override: false,
        }
    }

    #[tokio::test]
    async fn ancillary_verification_key_is_mandatory_when_include_ancillary_is_true() {
        let command = CardanoDbDownloadCommand {
            include_ancillary: true,
            ancillary_verification_key: None,
            ..dummy_command()
        };
        let command_context = CommandContext::new(
            ConfigParameters::default(),
            false,
            true,
            Logger::root(slog::Discard, slog::o!()),
        );

        let result = command.execute(command_context).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parameter 'ancillary_verification_key' is mandatory."
        );
    }

    mod prepare_v2 {
        use super::*;

        #[test]
        fn ancillary_verification_key_can_be_read_through_configuration_file() {
            let command = CardanoDbDownloadCommand {
                ancillary_verification_key: None,
                ..dummy_command()
            };
            let config = ConfigParameters::new(HashMap::from([(
                "ancillary_verification_key".to_string(),
                "value from config".to_string(),
            )]));
            let mut command_context =
                CommandContext::new(config, false, true, Logger::root(slog::Discard, slog::o!()));

            command_context.config_parameters_mut().add_source(&command).unwrap();

            let result = command.prepare_v2(&command_context);

            assert!(result.is_ok());
        }

        #[test]
        fn db_download_dir_is_mandatory_to_execute_command() {
            let command = CardanoDbDownloadCommand {
                download_dir: None,
                ..dummy_command()
            };
            let mut command_context = CommandContext::new(
                ConfigParameters::default(),
                false,
                true,
                Logger::root(slog::Discard, slog::o!()),
            );

            command_context.config_parameters_mut().add_source(&command).unwrap();

            let result = command.prepare_v2(&command_context);

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                "Parameter 'download_dir' is mandatory."
            );
        }
    }
}
