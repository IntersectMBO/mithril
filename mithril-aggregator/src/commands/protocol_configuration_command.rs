use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::{Deserialize, Serialize};
use slog::{Logger, debug};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::Arc,
};
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserverType;
use mithril_cli_helper::serde_deserialization;
use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSecretKey,
};
use mithril_common::entities::{
    CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
    HexEncodedProtocolConfigurationMarkersSecretKey, InconsistentSignedEntityConfigError,
    ProtocolParameters, ProtocolParametersError,
};
use mithril_common::messages::SignedEntityTypeDiscriminantsMessage::{self, Known};
use mithril_common::{StdResult, entities::SignedEntityConfigValidator};
use mithril_doc::{Documenter, StructDoc};

use crate::{
    ConfigurationSource, ExecutionEnvironment,
    configuration::ProtocolConfigurationReaderParameters, extract_all,
};
use crate::{dependency_injection::DependenciesBuilder, tools::ProtocolConfigurationTools};

#[derive(Debug, Error)]
pub enum InputConfigurationImportVerificationError {
    #[error("Protocol parameters are invalid: {0:?} {1:?}")]
    InvalidProtocolParameters(ProtocolParameters, ProtocolParametersError),

    #[error("Signed entity configuration is invalid: {0:?}")]
    InvalidSignedEntityConfiguration(InconsistentSignedEntityConfigError),
}

/// Protocol configuration parameters configuration
#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ProtocolConfigurationParametersConfiguration {
    /// Path of the socket opened by the Cardano node
    #[example = "`/ipc/node.socket`"]
    pub cardano_node_socket_path: PathBuf,

    /// Cardano network
    #[example = "`mainnet` or `preprod` or `devnet`"]
    network: String,

    /// Cardano chain observer type
    pub chain_observer_type: ChainObserverType,

    /// Protocol configuration Reader Adapter Parameters
    #[example = "\
    `{ \"address\": \"address\", \"verification_key\": \"key\" }`\
    "]
    #[serde(deserialize_with = "serde_deserialization::string_or_struct")]
    pub protocol_configuration_reader_adapter_params: ProtocolConfigurationReaderParameters,
}

impl ConfigurationSource for ProtocolConfigurationParametersConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn cardano_node_socket_path(&self) -> PathBuf {
        self.cardano_node_socket_path.clone()
    }

    fn network(&self) -> String {
        self.network.clone()
    }

    fn chain_observer_type(&self) -> ChainObserverType {
        self.chain_observer_type.clone()
    }

    fn protocol_configuration_reader_parameters(&self) -> ProtocolConfigurationReaderParameters {
        self.protocol_configuration_reader_adapter_params.clone()
    }
}

/// Human readable protocol configuration
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct HumanReadableProtocolConfiguration {
    pub epoch: Epoch,
    pub protocol_parameters: ProtocolParameters,
    pub cardano_transaction_signing_config: Option<CardanoTransactionsSigningConfig>,
    pub cardano_blocks_transactions_signing_config: Option<CardanoBlocksTransactionsSigningConfig>,
    pub enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,
}

impl HumanReadableProtocolConfiguration {
    pub fn new(
        epoch: Epoch,
        protocol_parameters: ProtocolParameters,
        cardano_transaction_signing_config: Option<CardanoTransactionsSigningConfig>,
        cardano_blocks_transactions_signing_config: Option<CardanoBlocksTransactionsSigningConfig>,
        enabled_signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,
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

/// Protocol configuration command
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
        let config: ProtocolConfigurationParametersConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "EXPORT PROTOCOL CONFIGURATION command"; "config" => format!("{config:?}"));

        let mut dependencies_builder =
            DependenciesBuilder::new(root_logger.clone(), Arc::new(config.clone()));

        let dependencies = dependencies_builder
            .create_protocol_configuration_container()
            .await
            .with_context(
                || "Dependencies Builder can not create protocol configuration command dependencies container",
            )?;

        // 1: Read the protocol configurations from the file
        println!(
            "Reading file content {}",
            &self.import_path.to_string_lossy()
        );
        let json_protocol_configurations = fs::read_to_string(&self.import_path);

        // 2: Parse the json into a protocol configuration list using serde_json
        println!("Json parsing ...");
        let protocol_configurations: Vec<HumanReadableProtocolConfiguration> =
            serde_json::from_str(&json_protocol_configurations?)?;

        // 3: Verify protocol configuration consistency
        println!("Verifying protocol configuration consistency...");
        Self::verify_protocol_configurations(&protocol_configurations)?;

        // 4: Verify protocol configuration against on chain configuration
        println!("Verifying protocol configuration against on chain configuration...");
        let tools = ProtocolConfigurationTools::from_dependencies(dependencies)
            .await
            .with_context(|| "protocol-configuration-tools: initialization error")?;
        tools.verify_configurations_against_chain(protocol_configurations.clone())?;

        // 5: Generate Tx datum
        println!("Generating Tx datum ...");
        let protocol_configuration_markers_signer =
            Self::get_markers_signer(self.protocol_configuration_markers_secret_key.clone())?;

        let tx_datum = tools.generate_tx_datum(
            protocol_configurations,
            &protocol_configuration_markers_signer,
        )?;

        // 6: Verifying datum size
        println!("Verifying datum content do not exceed maximum size...");
        tools.verify_tx_datum_size(tx_datum.clone())?;

        // 7: Write datum file
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
        configurations: &Vec<HumanReadableProtocolConfiguration>,
    ) -> Result<(), InputConfigurationImportVerificationError> {
        for config in configurations {
            match config.protocol_parameters.check_parameters() {
                Ok(()) => (),
                Err(e) => {
                    return Err(
                        InputConfigurationImportVerificationError::InvalidProtocolParameters(
                            config.protocol_parameters.clone(),
                            e,
                        ),
                    );
                }
            }

            let known_enabled_discriminants = config
                .enabled_signed_entity_types
                .iter()
                .filter_map(|d| match d {
                    Known(discriminant) => Some(*discriminant),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();

            match SignedEntityConfigValidator::check_consistency(
                &known_enabled_discriminants,
                &config.cardano_transaction_signing_config,
                &config.cardano_blocks_transactions_signing_config,
            ) {
                Ok(()) => (),
                Err(e) => {
                    return Err(
                        InputConfigurationImportVerificationError::InvalidSignedEntityConfiguration(
                            e,
                        ),
                    );
                }
            }
        }

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

    mod verify_protocol_configurations {

        use mithril_common::entities::SignedEntityTypeDiscriminants::CardanoTransactions;
        use mithril_common::messages::SignedEntityTypeDiscriminantsMessage;

        use super::*;

        #[test]
        fn should_throw_error_with_invalid_protocol_parameters() {
            let protocol_parameters = ProtocolParameters::new(0, 1, 0.123);

            let configurations = vec![HumanReadableProtocolConfiguration {
                protocol_parameters: protocol_parameters.clone(),
                ..Dummy::dummy()
            }];

            let error = ImportProtocolConfigurationSubCommand::verify_protocol_configurations(
                &configurations,
            )
            .unwrap_err();

            assert!(matches!(
                error,
                InputConfigurationImportVerificationError::InvalidProtocolParameters(_, _)
            ));
        }

        #[test]
        fn shoud_throw_error_if_a_enabled_entity_type_have_no_configuration() {
            let configurations = vec![HumanReadableProtocolConfiguration {
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                ]),
                cardano_transaction_signing_config: None,
                ..Dummy::dummy()
            }];

            let error = ImportProtocolConfigurationSubCommand::verify_protocol_configurations(
                &configurations,
            )
            .unwrap_err();

            assert!(matches!(
                error,
                InputConfigurationImportVerificationError::InvalidSignedEntityConfiguration(_)
            ));
        }
    }

    #[test]
    fn import_subcommand_parses_flag() {
        let signer_secret_key = ProtocolConfigurationMarkersSigner::create_deterministic_signer()
            .secret_key()
            .to_json_hex()
            .expect("create_deterministic_signer for secret key should not fail");

        ImportProtocolConfigurationSubCommand::try_parse_from([
            "import-markers",
            "--import-path",
            "tests/human_readable_protocol_configuration_toto.json",
            "--target-path",
            "/tests/protocol_configuration_tx_datum",
            "--protocol-configuration-markers-secret-key",
            &signer_secret_key,
        ])
        .expect("CLI parse should succeed");
    }
}
