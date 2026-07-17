use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{ConfigBuilder, builder::DefaultState};
use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSecretKey,
};
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use mithril_common::StdResult;
use mithril_common::entities::{
    CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
    HexEncodedProtocolConfigurationMarkersSecretKey, ProtocolParameters,
    SignedEntityTypeDiscriminants,
};
use mithril_doc::StructDoc;

use crate::extract_all;
use crate::tools::ProtocolConfigurationTools;

pub struct ProtocolConfigurationParametersConfiguration {}

#[derive(Serialize, Deserialize, Clone)]
pub struct HumanReadableProtocolConfiguration {
    pub epoch: Epoch,
    pub protocol_parameters: ProtocolParameters,
    pub cardano_transaction_signing_config: Option<CardanoTransactionsSigningConfig>,
    pub cardano_blocks_transactions_signing_config: Option<CardanoBlocksTransactionsSigningConfig>,
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,
}

impl HumanReadableProtocolConfiguration {
    pub fn new(
        epoch: Epoch,
        protocol_parameters: ProtocolParameters,
        cardano_transaction_signing_config: Option<CardanoTransactionsSigningConfig>,
        cardano_blocks_transactions_signing_config: Option<CardanoBlocksTransactionsSigningConfig>,
        enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminants>,
    ) -> Self {
        HumanReadableProtocolConfiguration {
            epoch,
            protocol_parameters,
            cardano_transaction_signing_config,
            cardano_blocks_transactions_signing_config,
            enabled_signed_entity_types,
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct ProtocolConfigurationCommand {
    /// commands
    #[clap(subcommand)]
    pub protocol_configuration_sub_command: ProtocolConfigurationSubCommand,
}

impl ProtocolConfigurationCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        self.protocol_configuration_sub_command
            .execute(root_logger, config_builder)
            .await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            ProtocolConfigurationSubCommand,
            ExportMarkers = { ExportProtocolConfigurationSubCommand },
            ImportMarkers = { ImportProtocolConfigurationSubCommand },
        )
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProtocolConfigurationSubCommand {
    /// Protocol configuration export command.
    ExportMarkers(ExportProtocolConfigurationSubCommand),

    /// Protocol configuration import command.
    ImportMarkers(ImportProtocolConfigurationSubCommand),
}

impl ProtocolConfigurationSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match self {
            Self::ExportMarkers(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::ImportMarkers(cmd) => cmd.execute(root_logger, config_builder).await,
        }
    }
}

/// Protocol configuration export command
#[derive(Parser, Debug, Clone)]
pub struct ExportProtocolConfigurationSubCommand {
    /// Target path
    #[clap(long)]
    target_path: PathBuf,
}

impl ExportProtocolConfigurationSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Protocol configuration import command
#[derive(Parser, Debug, Clone)]
pub struct ImportProtocolConfigurationSubCommand {
    /// Import path of the human readable configurations
    #[clap(long, value_parser)]
    pub import_path: PathBuf,

    /// target path of the tx datum file
    #[clap(long, value_parser)]
    pub target_path: PathBuf,

    /// Protocol Configuration Markers Secret Key
    #[clap(long, env = "PROTOCOL_CONFIGURATION_MARKERS_SECRET_KEY")]
    protocol_configuration_markers_secret_key: HexEncodedProtocolConfigurationMarkersSecretKey,
}

impl ImportProtocolConfigurationSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        //1 - we need to read the protocol configuration from the file
        println!(
            "Reading file content {}",
            &self.import_path.to_string_lossy()
        );
        let json_protocol_configurations = fs::read_to_string(&self.import_path);

        //2 - we need to parse the json into a protocol configuration using serde_json
        println!("Json parsing ...");
        let protocol_configurations: Vec<HumanReadableProtocolConfiguration> =
            serde_json::from_str(&json_protocol_configurations?)?;

        //3 - Verify protocol config consistency, TODO could be move in ProtocolConfigurationTools ?
        println!("Verifying protocol configuration consistency...");
        Self::verify_protocol_configurations(protocol_configurations.clone())?; //return a VerifiedProtocolConfigurations ?

        //3.2 Check epoch consistency on chain ?

        //4 - Generate Tx datum
        println!("Generating Tx datum ...");
        let protocol_configuration_markers_signer =
            Self::get_markers_signer(self.protocol_configuration_markers_secret_key.clone())?;

        let tools = ProtocolConfigurationTools::new();
        let tx_datum = tools.generate_tx_datum(
            protocol_configurations,
            &protocol_configuration_markers_signer,
        )?;

        //5 - TODO: check size < 10kb

        //6 - Write datum file
        println!("Generating Tx datum output file...");
        let mut target_file = File::create(&self.target_path)?;
        target_file.write_all(tx_datum.as_bytes())?;

        println!(
            "Sucessfuly write Tx datum file at {}",
            &self.target_path.to_string_lossy()
        );

        Ok(())
    }

    fn get_markers_signer(
        secret_key: HexEncodedProtocolConfigurationMarkersSecretKey,
    ) -> StdResult<ProtocolConfigurationMarkersSigner> {
        let markers_secret_key =
            ProtocolConfigurationMarkersVerifierSecretKey::from_json_hex(&secret_key)
                .with_context(
                    || "json hex decode of protocol configuration markers secret key failure",
                )?;
        Ok(ProtocolConfigurationMarkersSigner::from_secret_key(
            markers_secret_key,
        ))
    }

    pub fn verify_protocol_configurations(
        configurations: Vec<HumanReadableProtocolConfiguration>,
    ) -> StdResult<()> {
        for config in configurations {
            if config.protocol_parameters.k == 0
                || config.protocol_parameters.m == 0
                || config.protocol_parameters.phi_f == 0.0
            {
                return Err(anyhow::anyhow!(
                    "Protocol parameters must be non-zero: {:?}",
                    config.protocol_parameters
                ));
            }
        }
        //TODO verify epoch consistency (no epoch smaller than latest export ?)
        //TODO verify that if CardanoBlocksSigningConfig is filled that CardanoBlocksTransactions is in available signed entity types
        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{entities::ProtocolParameters, test::double::Dummy};

    use super::*;

    #[test]
    fn test_verify_protocol_configurations_should_throw_error_with_protocol_parameter_at_zero() {
        let protocol_parameters_list_to_test = [
            ProtocolParameters::new(0, 1, 0.123),
            ProtocolParameters::new(1, 0, 0.123),
            ProtocolParameters::new(1, 1, 0.0),
        ];

        for protocol_parameters in protocol_parameters_list_to_test {
            let configurations = vec![HumanReadableProtocolConfiguration {
                protocol_parameters: protocol_parameters.clone(),
                ..Dummy::dummy()
            }];

            let result = ImportProtocolConfigurationSubCommand::verify_protocol_configurations(
                configurations,
            );

            assert_eq!(
                result.unwrap_err().to_string(),
                format!(
                    "Protocol parameters must be non-zero: {:?}",
                    protocol_parameters
                )
            );
        }
    }

    #[test]
    fn import_subcommand_parses_flag() {
        let signer_secret_key = ProtocolConfigurationMarkersSigner::create_deterministic_signer()
            .secret_key()
            .to_json_hex()
            .expect("create_deterministic_signer for secret key should not fail");
        println!("Signer secret key: {}", signer_secret_key);
        ImportProtocolConfigurationSubCommand::try_parse_from([
            "import-markers",
            "--import-path",
            "tests/human_readable_protocol_configuration.json",
            "--target-path",
            "/tests/protocol_configuration_tx_datum",
            "--protocol-configuration-markers-secret-key",
            &signer_secret_key,
        ])
        .expect("CLI parse should succeed");
    }
}
