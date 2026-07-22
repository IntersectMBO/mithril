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

use mithril_cardano_node_chain::chain_observer::ChainObserverType;
use mithril_common::StdResult;
use mithril_common::crypto_helper::{
    ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSecretKey,
};
use mithril_common::entities::{
    CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, Epoch,
    HexEncodedProtocolConfigurationMarkersSecretKey, ProtocolParameters,
    SignedEntityTypeDiscriminants,
};
use mithril_doc::{Documenter, StructDoc};

use crate::{ConfigurationSource, ExecutionEnvironment, extract_all};
use crate::{dependency_injection::DependenciesBuilder, tools::ProtocolConfigurationTools};

/// Protocol configuration parameters configuration
#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ProtocolConfigurationParametersConfiguration {
    /// Cardano Network Magic number
    ///
    /// useful for TestNet & DevNet
    #[example = "`1097911063` or `42`"]
    pub network_magic: Option<u64>,

    /// Cardano network
    #[example = "`mainnet` or `preprod` or `devnet`"]
    network: String,

    /// Cardano chain observer type
    pub chain_observer_type: ChainObserverType,
}

impl ConfigurationSource for ProtocolConfigurationParametersConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn network_magic(&self) -> Option<u64> {
        self.network_magic
    }

    fn network(&self) -> String {
        self.network.clone()
    }

    fn chain_observer_type(&self) -> ChainObserverType {
        self.chain_observer_type.clone()
    }

    fn store_retention_limit(&self) -> Option<usize> {
        None
    }
}

/// Human readable protocol configuration
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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

/// Protocol configuration command
#[derive(Parser, Debug, Clone)]
pub struct ProtocolConfigurationCommand {
    /// Protocol configuration reader adapter type
    #[clap(long, env = "PROTOCOL_CONFIGURATION_READER_ADAPTER_TYPE")]
    pub protocol_configuration_reader_adapter_type: String,

    /// Protocol configation reader adapter parameters
    /// example {"address":"your-address","verification_key":"your-verification-key"}
    #[clap(long, env = "PROTOCOL_CONFIGURATION_READER_ADAPTER_PARAMS")]
    pub protocol_configuration_reader_adapter_params: String,

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
        // 0 conf & dependencies
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

        //1 - Read the protocol configurations from the file
        println!(
            "Reading file content {}",
            &self.import_path.to_string_lossy()
        );
        let json_protocol_configurations = fs::read_to_string(&self.import_path);

        //2 - Parse the json into a protocol configuration list using serde_json
        println!("Json parsing ...");
        let protocol_configurations: Vec<HumanReadableProtocolConfiguration> =
            serde_json::from_str(&json_protocol_configurations?)?;

        //3 - Verify protocol config consistency, TODO could be move in ProtocolConfigurationTools ?
        println!("Verifying protocol configuration consistency...");
        Self::verify_protocol_configurations(&protocol_configurations)?; //return a VerifiedProtocolConfigurations ?

        //3.2 Check epoch consistency on chain

        let tools = ProtocolConfigurationTools::from_dependencies(dependencies)
            .await
            .with_context(|| "protocol-configuration-tools: initialization error")?;
        // tools.verify_configuration_against_production(&protocol_configurations);

        //4 - Generate Tx datum
        println!("Generating Tx datum ...");
        let protocol_configuration_markers_signer =
            Self::get_markers_signer(self.protocol_configuration_markers_secret_key.clone())?;

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
        configurations: &Vec<HumanReadableProtocolConfiguration>,
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

    // to delete, moved to dep injection
    // /// Create era reader adapter from configuration settings.
    // fn build_protocol_configuration_reader_adapter(
    //     chain_observer: Arc<dyn ChainObserver>,
    //     adapter_type: ProtocolConfigurationReaderAdapterType,
    //     adapter_params: Option<String>,
    // ) -> StdResult<Arc<dyn ProtocolConfigurationReaderAdapter>> {
    //     ProtocolConfigurationReaderAdapterBuilder::new(&adapter_type, &adapter_params)
    //         .build(chain_observer)
    //         .with_context(|| {
    //             format!(
    //                 "Configuration: can not create protocol configuration reader for adapter '{}'.",
    //                 adapter_type
    //             )
    //         })
    // }
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
                &configurations,
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
