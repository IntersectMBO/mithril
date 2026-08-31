use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::Deserialize;
use slog::{Logger, debug};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::Arc,
};
use thiserror::Error;

use mithril_cardano_node_chain::chain_observer::ChainObserverType;
use mithril_cli_helper::serde_deserialization;
use mithril_common::{
    StdResult,
    crypto_helper::{
        ProtocolConfigurationMarkersSigner, ProtocolConfigurationMarkersVerifierSecretKey,
    },
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch, HexEncodedProtocolConfigurationMarkersSecretKey,
        InconsistentSignedEntityConfigError, ProtocolParameters, ProtocolParametersError,
        SignedEntityConfigValidator,
        SignedEntityTypeDiscriminants::{self},
    },
    messages::SignedEntityTypeDiscriminantsMessage::Known,
};
use mithril_doc::{Documenter, StructDoc};
use mithril_protocol_config::{
    builder::AdapterConfig,
    model::{ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch},
};

use crate::{
    ConfigurationSource, ExecutionEnvironment, extract_all,
    tools::HumanReadableProtocolConfiguration,
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

    /// Protocol configuration reader adapter configuration
    #[example = "\
    - cardano-chain:<br/>`{ \"type\": \"cardano-chain\", \"address\": \"test_address\",  \"verification_key\": \"136372c3138312c3138382c3130352c3233312c3135\" }`<br/>\
    "]
    #[serde(
        default,
        deserialize_with = "serde_deserialization::string_or_struct_optional"
    )]
    pub protocol_configuration_reader_adapter_config: Option<AdapterConfig>,
}

impl ConfigurationSource for ProtocolConfigurationParametersConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn cardano_node_socket_path(&self) -> PathBuf {
        self.cardano_node_socket_path.clone()
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

    fn protocol_configuration_reader_adapter_config(&self) -> Option<AdapterConfig> {
        self.protocol_configuration_reader_adapter_config.clone()
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

    /// Use default protocol configurations instead of retrieving  them from the chain
    #[clap(long, default_value = "false")]
    default: bool,
}

impl ExportProtocolConfigurationSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let protocol_configurations_markers = if self.default {
            println!("Getting default protocol configurations output file...");
            get_default_protocol_configurations()
        } else {
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

            let tools = ProtocolConfigurationTools::from_dependencies(dependencies)
                .await
                .with_context(|| "protocol-configuration-tools: initialization error")?;

            // 1: Retrieve markers from chain or fallback to default configuration
            let on_chain_configurations = tools.get_on_chain_configurations();
            if on_chain_configurations.markers.is_empty() {
                println!(
                    "No protocol configurations found on chain, getting default protocol configurations output file..."
                );
                get_default_protocol_configurations()
            } else {
                println!(
                    "Protocol configurations found on chain, getting protocol configurations output file..."
                );
                on_chain_configurations
            }
        };

        // 2: transform to human readable
        let protocol_configurations =
            HumanReadableProtocolConfiguration::to_vec_human_readable_protocol_configuration(
                protocol_configurations_markers,
            );

        // 3: write human readable configurations file
        println!("Generating JSON protocol configurations output file...");
        let json_protocol_configurations = serde_json::to_string(&protocol_configurations)?;
        let mut target_file = File::create(&self.target_path)?;
        target_file.write_all(json_protocol_configurations.as_bytes())?;

        println!(
            "Successfully wrote JSON protocol configurations file at {}",
            self.target_path.to_string_lossy()
        );
        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

pub fn get_default_protocol_configurations() -> ConfigurationResolverFromMarkers {
    ConfigurationResolverFromMarkers {
        markers: BTreeMap::from([(
            Epoch(0),
            ProtocolConfigurationForEpoch {
                protocol_parameters: ProtocolParameters {
                    k: 1944,
                    m: 16948,
                    phi_f: 0.2,
                },
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoDatabase,
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ]),
                cardano_transactions: Some(CardanoTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(100),
                    step: BlockNumber(30),
                }),
                cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(100),
                    step: BlockNumber(30),
                }),
            },
        )]),
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
    #[clap(long, env = "PROTOCOL_CONFIGURATION_READER_SECRET_KEY")]
    protocol_configuration_markers_secret_key: HexEncodedProtocolConfigurationMarkersSecretKey,

    /// Force datum file generation without verifying protocol configuration markers against on chain configuration
    #[clap(long)]
    force: bool,
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
        debug!(root_logger, "IMPORT PROTOCOL CONFIGURATION command"; "config" => format!("{config:?}"));

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
            self.import_path.to_string_lossy()
        );
        let json_protocol_configurations = fs::read_to_string(&self.import_path);

        // 2: Parse the json into a protocol configuration list using serde_json
        println!("Json parsing ...");
        let protocol_configurations: Vec<HumanReadableProtocolConfiguration> =
            serde_json::from_str(&json_protocol_configurations?)?;

        // 3: Verify protocol configuration consistency
        println!("Verifying protocol configuration consistency...");
        Self::verify_protocol_configurations(&protocol_configurations)?;

        let tools = ProtocolConfigurationTools::from_dependencies(dependencies)
            .await
            .with_context(|| "protocol-configuration-tools: initialization error")?;

        // 4: Verify protocol configuration against on chain configuration
        if self.force {
            println!("/!\\ --force option is set, bypassing the verification against chain /!\\");
        } else {
            println!("Verifying protocol configuration against on chain configuration...");
            tools.verify_configurations_against_chain(protocol_configurations.clone())?;
        }

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
            "Successfully wrote Tx datum file at {}",
            self.target_path.to_string_lossy()
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
    use mithril_common::{
        entities::{
            BlockNumber, BlockNumberOffset, ProtocolParameters,
            SignedEntityTypeDiscriminants::{
                CardanoDatabase, CardanoTransactions, MithrilStakeDistribution,
            },
        },
        messages::SignedEntityTypeDiscriminantsMessage,
        test::double::Dummy,
    };

    use super::*;

    mod verify_protocol_configurations {

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
    fn export_subcommand_parses_flag() {
        ExportProtocolConfigurationSubCommand::try_parse_from([
            "export-markers",
            "--target-path",
            "human_readable_protocol_configuration.json",
        ])
        .expect("CLI parse should succeed");
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
            "human_readable_protocol_configuration.json",
            "--target-path",
            "protocol_configuration_tx_datum.json",
            "--protocol-configuration-markers-secret-key",
            &signer_secret_key,
            "--force",
        ])
        .expect("CLI parse should succeed");
    }

    #[test]
    fn to_vec_human_readable_protocol_configuration_converts_markers_to_human_readable_list() {
        let configuration = ProtocolConfigurationForEpoch {
            protocol_parameters: ProtocolParameters {
                k: 9,
                m: 77,
                phi_f: 0.5,
            },
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoDatabase,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_transactions: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(150),
                step: BlockNumber(20),
            }),
        };
        let configurations =
            ConfigurationResolverFromMarkers::new(BTreeMap::from([(Epoch(42), configuration)]));

        let expected_human_readable_configurations = vec![HumanReadableProtocolConfiguration {
            epoch: Epoch(42),
            protocol_parameters: ProtocolParameters {
                k: 9,
                m: 77,
                phi_f: 0.5,
            },
            enabled_signed_entity_types: BTreeSet::from_iter(vec![
                SignedEntityTypeDiscriminantsMessage::Known(MithrilStakeDistribution),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
            ]),
            cardano_transaction_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(100),
                step: BlockNumber(10),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(150),
                    step: BlockNumber(20),
                },
            ),
        }];

        assert_eq!(
            HumanReadableProtocolConfiguration::to_vec_human_readable_protocol_configuration(
                configurations
            ),
            expected_human_readable_configurations
        );
    }
}
