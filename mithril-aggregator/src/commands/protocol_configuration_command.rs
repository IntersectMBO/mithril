use clap::{Parser, Subcommand};
use config::{ConfigBuilder, builder::DefaultState};
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;

use mithril_common::StdResult;
use mithril_common::entities::{
    CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
    ProtocolParameters, SignedEntityTypeDiscriminants,
};
use mithril_doc::StructDoc;

use crate::extract_all;

pub struct ProtocolConfigurationParametersConfiguration {}

#[derive(Serialize, Deserialize)]
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
    /// Import path
    #[clap(long, value_parser)]
    pub path: PathBuf,
}

impl ImportProtocolConfigurationSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        //1 - we need to read the protocol configuration from the file
        let json_protocol_configurations = fs::read_to_string(&self.path);

        //2 - we need to parse the json into a protocol configuration using serde_json
        let protocol_configurations: Vec<HumanReadableProtocolConfiguration> =
            serde_json::from_str(&json_protocol_configurations?)?;

        //3 - Verify protocol config consistency
        println!("Verifying protocol configuration consistency...");
        match Self::verify_protocol_configurations(protocol_configurations) {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "Protocol configuration is not consistent: {}",
                e
            )),
        }

        //4 - Cbor conversion

        //5 - check size < 10kb
        //6 - Generate Tx datum
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
        ImportProtocolConfigurationSubCommand::try_parse_from([
            "import-markers",
            "--path",
            "tests/human_readable_protocol_configuration.json",
        ])
        .expect("CLI parse should succeed");
        // assert_eq!(cmd.mithril_era, Some(SupportedEra::Lagrange));
        //TODO when available check that a tx datum file is written
    }
}
