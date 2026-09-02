use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::{ConfigBuilder, Map, Value, builder::DefaultState};
use serde::Deserialize;
use slog::{Logger, debug};

use mithril_cardano_node_chain::chain_observer::ChainObserverType;
#[cfg(not(feature = "future_snark"))]
use mithril_common::crypto_helper::GenesisEd25519VerificationKey;
use mithril_common::crypto_helper::GenesisVerifier;
use mithril_common::{
    StdResult,
    crypto_helper::GenesisSigner,
    entities::{HexEncodedGenesisSecretKey, HexEncodedGenesisVerificationKey, SupportedEra},
};
use mithril_doc::{Documenter, StructDoc};

use crate::{
    ConfigurationSource, ExecutionEnvironment, dependency_injection::DependenciesBuilder,
    extract_all, tools::GenesisTools,
};

/// Resolve the Mithril era for the genesis command.
///
/// If the era is explicitly provided, it is returned as-is.
/// If not provided and only one era exists, that era is used automatically.
/// If not provided and multiple eras exist, an error is returned.
fn resolve_mithril_era(mithril_era: Option<SupportedEra>) -> StdResult<SupportedEra> {
    match mithril_era {
        Some(era) => Ok(era),
        None => {
            let eras = SupportedEra::eras();
            if eras.len() == 1 {
                Ok(eras[0])
            } else {
                Err(anyhow::anyhow!(
                    "Multiple Mithril eras are supported ({eras:?}), please specify which era to use with --mithril-era"
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct GenesisCommandConfiguration {
    /// Cardano CLI tool path
    #[example = "`cardano-cli`"]
    pub cardano_cli_path: Option<PathBuf>,

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

    /// Directory to store aggregator data (Certificates, Snapshots, Protocol Parameters, ...)
    #[example = "`./mithril-aggregator/stores`"]
    pub data_stores_directory: PathBuf,
}

impl ConfigurationSource for GenesisCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        ExecutionEnvironment::Production
    }

    fn cardano_cli_path(&self) -> PathBuf {
        match self.chain_observer_type {
            ChainObserverType::CardanoCli => {
                if let Some(path) = &self.cardano_cli_path {
                    path.clone()
                } else {
                    panic!("Cardano CLI path must be set when using Cardano CLI chain observer")
                }
            }
            _ => PathBuf::new(),
        }
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

    fn data_stores_directory(&self) -> PathBuf {
        self.data_stores_directory.clone()
    }

    fn store_retention_limit(&self) -> Option<usize> {
        None
    }
}

/// Genesis tools
#[derive(Parser, Debug, Clone)]
pub struct GenesisCommand {
    /// commands
    #[clap(subcommand)]
    pub genesis_subcommand: GenesisSubCommand,
}

impl GenesisCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        self.genesis_subcommand.execute(root_logger, config_builder).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        #[cfg(feature = "future_snark")]
        {
            extract_all!(
                command_path,
                GenesisSubCommand,
                Export = { ExportGenesisSubCommand },
                Import = { ImportGenesisSubCommand },
                Sign = { SignGenesisSubCommand },
                Bootstrap = { BootstrapGenesisSubCommand },
                GenerateKeypair = { GenerateKeypairGenesisSubCommand },
                UpgradeKeyToDual = { UpgradeKeyToDualGenesisSubCommand },
                CircuitKeyRegistry = { CircuitKeyRegistryGenesisCommand },
            )
        }
        #[cfg(not(feature = "future_snark"))]
        {
            extract_all!(
                command_path,
                GenesisSubCommand,
                Export = { ExportGenesisSubCommand },
                Import = { ImportGenesisSubCommand },
                Sign = { SignGenesisSubCommand },
                Bootstrap = { BootstrapGenesisSubCommand },
                GenerateKeypair = { GenerateKeypairGenesisSubCommand },
            )
        }
    }
}

/// Genesis tools commands.
#[derive(Debug, Clone, Subcommand)]
pub enum GenesisSubCommand {
    /// Genesis certificate export command.
    Export(ExportGenesisSubCommand),

    /// Genesis certificate import command.
    Import(ImportGenesisSubCommand),

    /// Genesis certificate sign command.
    Sign(SignGenesisSubCommand),

    /// Genesis certificate bootstrap command.
    Bootstrap(BootstrapGenesisSubCommand),

    /// Genesis keypair generation command.
    GenerateKeypair(GenerateKeypairGenesisSubCommand),

    /// Upgrade a legacy single-Ed25519 genesis keypair into a dual signing/verification bundle.
    #[cfg(feature = "future_snark")]
    UpgradeKeyToDual(UpgradeKeyToDualGenesisSubCommand),

    /// Circuit verification key registry commands.
    #[cfg(feature = "future_snark")]
    CircuitKeyRegistry(CircuitKeyRegistryGenesisCommand),
}

impl GenesisSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match self {
            Self::Bootstrap(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Export(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Import(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::Sign(cmd) => cmd.execute(root_logger).await,
            Self::GenerateKeypair(cmd) => cmd.execute(root_logger).await,
            #[cfg(feature = "future_snark")]
            Self::UpgradeKeyToDual(cmd) => cmd.execute(root_logger).await,
            #[cfg(feature = "future_snark")]
            Self::CircuitKeyRegistry(cmd) => cmd.execute(root_logger).await,
        }
    }
}

/// Genesis certificate export command
#[derive(Parser, Debug, Clone)]
pub struct ExportGenesisSubCommand {
    /// Target path
    #[clap(long)]
    target_path: PathBuf,

    /// Mithril era to use for the genesis certificate
    ///
    /// Optional when only one era exists, required when multiple eras are supported.
    #[clap(long)]
    mithril_era: Option<SupportedEra>,
}

impl ExportGenesisSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let config: GenesisCommandConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "EXPORT GENESIS command"; "config" => format!("{config:?}"));
        println!(
            "Genesis export payload to sign to {}",
            self.target_path.display()
        );
        let mithril_era = resolve_mithril_era(self.mithril_era)?;
        let mut dependencies_builder =
            DependenciesBuilder::new(root_logger.clone(), Arc::new(config.clone()));
        let dependencies = dependencies_builder
            .create_genesis_container(mithril_era)
            .await
            .with_context(
                || "Dependencies Builder can not create genesis command dependencies container",
            )?;

        let genesis_tools = GenesisTools::from_dependencies(dependencies)
            .await
            .with_context(|| "genesis-tools: initialization error")?;
        genesis_tools
            .export_payload_to_sign(&self.target_path)
            .with_context(|| "genesis-tools: export error")?;
        Ok(())
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(command_path, GenesisCommandConfiguration::extract())])
    }
}

#[derive(Parser, Debug, Clone)]
pub struct ImportGenesisSubCommand {
    /// Signed Payload Path
    #[clap(long)]
    signed_payload_path: PathBuf,

    /// Genesis Verification Key
    #[clap(long)]
    genesis_verification_key: HexEncodedGenesisVerificationKey,

    /// Mithril era to use for the genesis certificate
    ///
    /// Optional when only one era exists, required when multiple eras are supported.
    #[clap(long)]
    mithril_era: Option<SupportedEra>,
}

impl ImportGenesisSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let config: GenesisCommandConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "IMPORT GENESIS command"; "config" => format!("{config:?}"));
        println!(
            "Genesis import signed payload from {}",
            self.signed_payload_path.display()
        );
        let mithril_era = resolve_mithril_era(self.mithril_era)?;
        let mut dependencies_builder =
            DependenciesBuilder::new(root_logger.clone(), Arc::new(config.clone()));
        let dependencies = dependencies_builder
            .create_genesis_container(mithril_era)
            .await
            .with_context(
                || "Dependencies Builder can not create genesis command dependencies container",
            )?;

        let genesis_tools = GenesisTools::from_dependencies(dependencies)
            .await
            .with_context(|| "genesis-tools: initialization error")?;

        self.run_import(&genesis_tools, mithril_era).await
    }

    #[cfg(not(feature = "future_snark"))]
    async fn run_import(
        &self,
        genesis_tools: &GenesisTools,
        _mithril_era: SupportedEra,
    ) -> StdResult<()> {
        let genesis_verifier = GenesisVerifier::from_ed25519(
            GenesisEd25519VerificationKey::from_json_hex(&self.genesis_verification_key)?,
        );
        genesis_tools
            .import_payload_signature(&self.signed_payload_path, &genesis_verifier)
            .await
            .with_context(|| "genesis-tools: import error")
    }

    #[cfg(feature = "future_snark")]
    async fn run_import(
        &self,
        genesis_tools: &GenesisTools,
        mithril_era: SupportedEra,
    ) -> StdResult<()> {
        let verifier = GenesisVerifier::try_from_hex(&self.genesis_verification_key)?;
        match mithril_era {
            SupportedEra::Lagrange => genesis_tools
                .import_dual_payload_signature(&self.signed_payload_path, &verifier)
                .await
                .with_context(|| "genesis-tools: import error"),
            _ => genesis_tools
                .import_payload_signature(&self.signed_payload_path, &verifier)
                .await
                .with_context(|| "genesis-tools: import error"),
        }
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(command_path, GenesisCommandConfiguration::extract())])
    }
}

#[derive(Parser, Debug, Clone)]
pub struct SignGenesisSubCommand {
    /// To Sign Payload Path
    #[clap(long)]
    to_sign_payload_path: PathBuf,

    /// Target Signed Payload Path
    #[clap(long)]
    target_signed_payload_path: PathBuf,

    /// Genesis Secret Key Path
    #[clap(long)]
    genesis_secret_key_path: PathBuf,

    /// Mithril era to use for the genesis certificate
    ///
    /// Optional when only one era exists, required when multiple eras are supported.
    #[clap(long)]
    mithril_era: Option<SupportedEra>,
}

impl SignGenesisSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "SIGN GENESIS command");
        println!(
            "Genesis sign payload from {} to {}",
            self.to_sign_payload_path.display(),
            self.target_signed_payload_path.display()
        );
        let mithril_era = resolve_mithril_era(self.mithril_era)?;

        GenesisTools::sign_genesis_certificate(
            &self.to_sign_payload_path,
            &self.target_signed_payload_path,
            &self.genesis_secret_key_path,
            mithril_era,
        )
        .await
        .with_context(|| "genesis-tools: sign error")?;

        Ok(())
    }

    pub fn extract_config(_command_path: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}
#[derive(Parser, Debug, Clone)]
pub struct BootstrapGenesisSubCommand {
    /// Genesis Secret Key (test only)
    #[clap(long, env = "GENESIS_SECRET_KEY")]
    genesis_secret_key: HexEncodedGenesisSecretKey,

    /// Mithril era to use for the genesis certificate
    ///
    /// Optional when only one era exists, required when multiple eras are supported.
    #[clap(long)]
    mithril_era: Option<SupportedEra>,
}

impl BootstrapGenesisSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        let config: GenesisCommandConfiguration = config_builder
            .build()
            .with_context(|| "configuration build error")?
            .try_deserialize()
            .with_context(|| "configuration deserialize error")?;
        debug!(root_logger, "BOOTSTRAP GENESIS command"; "config" => format!("{config:?}"));
        println!("Genesis bootstrap for test only!");
        let mithril_era = resolve_mithril_era(self.mithril_era)?;
        let mut dependencies_builder =
            DependenciesBuilder::new(root_logger.clone(), Arc::new(config.clone()));
        let dependencies = dependencies_builder
            .create_genesis_container(mithril_era)
            .await
            .with_context(
                || "Dependencies Builder can not create genesis command dependencies container",
            )?;

        let genesis_tools = GenesisTools::from_dependencies(dependencies)
            .await
            .with_context(|| "genesis-tools: initialization error")?;
        let genesis_signer = GenesisSigner::try_from_hex(&self.genesis_secret_key)
            .with_context(|| "hex decode of genesis secret key failure")?;
        genesis_tools
            .bootstrap_test_genesis_certificate(genesis_signer)
            .await
            .with_context(|| "genesis-tools: bootstrap error")?;
        Ok(())
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        HashMap::from([(command_path, GenesisCommandConfiguration::extract())])
    }
}

/// Genesis keypair generation command.
#[derive(Parser, Debug, Clone)]
pub struct GenerateKeypairGenesisSubCommand {
    /// Target path for the generated keypair
    #[clap(long)]
    target_path: PathBuf,

    /// Mithril era to use for the generated keypair
    ///
    /// Optional when only one era exists, required when multiple eras are supported.
    #[clap(long)]
    mithril_era: Option<SupportedEra>,
}

impl GenerateKeypairGenesisSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "GENERATE KEYPAIR GENESIS command");
        println!("Genesis generate keypair to {}", self.target_path.display());
        let mithril_era = resolve_mithril_era(self.mithril_era)?;

        GenesisTools::create_and_save_genesis_keypair(&self.target_path, mithril_era)
            .with_context(|| "genesis-tools: keypair generation error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Upgrade a legacy single-Ed25519 genesis keypair into a dual signing/verification bundle.
#[cfg(feature = "future_snark")]
#[derive(Parser, Debug, Clone)]
pub struct UpgradeKeyToDualGenesisSubCommand {
    /// Legacy single-Ed25519 secret key file (genesis.sk).
    #[clap(long)]
    legacy_secret_key_path: PathBuf,

    /// Target path for the dual signing/verification bundle files.
    #[clap(long)]
    target_path: PathBuf,
}

#[cfg(feature = "future_snark")]
impl UpgradeKeyToDualGenesisSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "UPGRADE-KEY-TO-DUAL GENESIS command");
        println!(
            "Upgrade legacy genesis keypair from {} to dual bundle at {}",
            self.legacy_secret_key_path.display(),
            self.target_path.display()
        );

        GenesisTools::upgrade_legacy_keypair_to_dual(
            &self.legacy_secret_key_path,
            &self.target_path,
        )
        .with_context(|| "genesis-tools: upgrade-key-to-dual error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Circuit verification key registry commands.
#[cfg(feature = "future_snark")]
#[derive(Parser, Debug, Clone)]
pub struct CircuitKeyRegistryGenesisCommand {
    /// commands
    #[clap(subcommand)]
    pub circuit_key_registry_subcommand: CircuitKeyRegistryGenesisSubCommand,
}

#[cfg(feature = "future_snark")]
impl CircuitKeyRegistryGenesisCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        self.circuit_key_registry_subcommand.execute(root_logger).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            CircuitKeyRegistryGenesisSubCommand,
            Sign = { SignCircuitKeyRegistrySubCommand },
            Bootstrap = { BootstrapCircuitKeyRegistrySubCommand },
        )
    }
}

/// Circuit verification key registry commands.
#[cfg(feature = "future_snark")]
#[derive(Debug, Clone, Subcommand)]
pub enum CircuitKeyRegistryGenesisSubCommand {
    /// Circuit verification key registry sign command.
    Sign(SignCircuitKeyRegistrySubCommand),

    /// Circuit verification key registry bootstrap command.
    Bootstrap(BootstrapCircuitKeyRegistrySubCommand),
}

#[cfg(feature = "future_snark")]
impl CircuitKeyRegistryGenesisSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        match self {
            Self::Sign(cmd) => cmd.execute(root_logger).await,
            Self::Bootstrap(cmd) => cmd.execute(root_logger).await,
        }
    }
}

/// Circuit verification key registry sign command.
#[cfg(feature = "future_snark")]
#[derive(Parser, Debug, Clone)]
pub struct SignCircuitKeyRegistrySubCommand {
    /// To Sign Registry Path
    #[clap(long)]
    to_sign_registry_path: PathBuf,

    /// Target Signed Registry Path
    #[clap(long)]
    target_signed_registry_path: PathBuf,

    /// Genesis Secret Key Path
    #[clap(long)]
    genesis_secret_key_path: PathBuf,
}

#[cfg(feature = "future_snark")]
impl SignCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "SIGN CIRCUIT KEY REGISTRY GENESIS command");
        println!(
            "Sign circuit verification key registry from {} to {}",
            self.to_sign_registry_path.display(),
            self.target_signed_registry_path.display()
        );

        GenesisTools::sign_circuit_verification_key_registry(
            &self.to_sign_registry_path,
            &self.target_signed_registry_path,
            &self.genesis_secret_key_path,
        )
        .with_context(|| "genesis-tools: sign circuit key registry error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Circuit verification key registry bootstrap command (test only): create and sign the registry
/// whitelisting the production circuit keys from epoch 0.
#[cfg(feature = "future_snark")]
#[derive(Parser, Debug, Clone)]
pub struct BootstrapCircuitKeyRegistrySubCommand {
    /// Genesis Secret Key (test only)
    #[clap(long, env = "GENESIS_SECRET_KEY")]
    genesis_secret_key: HexEncodedGenesisSecretKey,

    /// Target Registry Path
    #[clap(long)]
    target_registry_path: PathBuf,
}

#[cfg(feature = "future_snark")]
impl BootstrapCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(
            root_logger,
            "BOOTSTRAP CIRCUIT KEY REGISTRY GENESIS command"
        );
        println!(
            "Circuit verification key registry bootstrap for test only, to {}",
            self.target_registry_path.display()
        );

        GenesisTools::bootstrap_circuit_verification_key_registry(
            &self.genesis_secret_key,
            &self.target_registry_path,
        )
        .with_context(|| "genesis-tools: bootstrap circuit key registry error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(feature = "future_snark")]
    use mithril_common::crypto_helper::GenesisEd25519Signer;
    use mithril_common::temp_dir;
    #[cfg(feature = "future_snark")]
    use mithril_common::temp_dir_create;

    use crate::test::TestLogger;

    use super::*;

    #[test]
    fn resolve_mithril_era_returns_provided_era() {
        let era = resolve_mithril_era(Some(SupportedEra::Lagrange)).unwrap();
        assert_eq!(SupportedEra::Lagrange, era);
    }

    #[test]
    fn resolve_mithril_era_returns_error_when_multiple_eras_and_none_provided() {
        let eras = SupportedEra::eras();
        if eras.len() > 1 {
            let result = resolve_mithril_era(None);
            assert!(
                result.is_err(),
                "Should error when multiple eras exist and none is provided"
            );
        }
    }

    #[test]
    fn import_subcommand_parses_era_flag() {
        let cmd = ImportGenesisSubCommand::try_parse_from([
            "import",
            "--signed-payload-path",
            "/tmp/signed",
            "--genesis-verification-key",
            "deadbeef",
            "--mithril-era",
            &SupportedEra::Lagrange.to_string(),
        ])
        .expect("CLI parse should succeed");
        assert_eq!(cmd.mithril_era, Some(SupportedEra::Lagrange));
    }

    #[test]
    fn bootstrap_subcommand_parses_era_flag() {
        let cmd = BootstrapGenesisSubCommand::try_parse_from([
            "bootstrap",
            "--genesis-secret-key",
            "deadbeef",
            "--mithril-era",
            &SupportedEra::Lagrange.to_string(),
        ])
        .expect("CLI parse should succeed");
        assert_eq!(cmd.mithril_era, Some(SupportedEra::Lagrange));
    }

    #[test]
    fn sign_subcommand_parses_era_flag() {
        let cmd = SignGenesisSubCommand::try_parse_from([
            "sign",
            "--to-sign-payload-path",
            "/tmp/to-sign",
            "--target-signed-payload-path",
            "/tmp/signed",
            "--genesis-secret-key-path",
            "/tmp/genesis.sk",
            "--mithril-era",
            &SupportedEra::Lagrange.to_string(),
        ])
        .expect("CLI parse should succeed");
        assert_eq!(cmd.mithril_era, Some(SupportedEra::Lagrange));
    }

    #[test]
    fn generate_keypair_subcommand_parses_era_flag() {
        let cmd = GenerateKeypairGenesisSubCommand::try_parse_from([
            "generate-keypair",
            "--target-path",
            "/tmp/keys",
            "--mithril-era",
            &SupportedEra::Pythagoras.to_string(),
        ])
        .expect("CLI parse should succeed");
        assert_eq!(cmd.mithril_era, Some(SupportedEra::Pythagoras));
    }

    #[tokio::test]
    async fn generate_keypair_subcommand_writes_key_files() {
        let target = temp_dir!().join("keys");
        std::fs::create_dir_all(&target).unwrap();
        let cmd = GenerateKeypairGenesisSubCommand {
            target_path: target.clone(),
            mithril_era: Some(SupportedEra::Pythagoras),
        };

        cmd.execute(TestLogger::stdout())
            .await
            .expect("generate-keypair should succeed with explicit era");
        assert!(target.join("genesis.sk").exists());
        assert!(target.join("genesis.vk").exists());
    }

    #[cfg(feature = "future_snark")]
    #[tokio::test]
    async fn upgrade_key_to_dual_subcommand_writes_bundle_files() {
        let temp = temp_dir_create!();
        let legacy_path = temp.join("genesis.sk");
        let signer = GenesisEd25519Signer::create_deterministic_signer();
        signer.secret_key().write_json_hex_to_file(&legacy_path).unwrap();
        let target = temp.join("out");
        std::fs::create_dir_all(&target).unwrap();

        let cmd = UpgradeKeyToDualGenesisSubCommand {
            legacy_secret_key_path: legacy_path,
            target_path: target.clone(),
        };

        cmd.execute(TestLogger::stdout())
            .await
            .expect("upgrade should succeed");
        assert!(target.join("genesis.sk").exists());
        assert!(target.join("genesis.vk").exists());
    }

    #[tokio::test]
    async fn create_container_does_not_panic() {
        let config = GenesisCommandConfiguration {
            cardano_cli_path: None,
            cardano_node_socket_path: PathBuf::new(),
            network_magic: Some(42),
            network: "devnet".to_string(),
            chain_observer_type: ChainObserverType::Fake,
            data_stores_directory: temp_dir!().join("stores"),
        };
        let mut dependencies_builder =
            DependenciesBuilder::new(TestLogger::stdout(), Arc::new(config));

        dependencies_builder
            .create_genesis_container(SupportedEra::Pythagoras)
            .await
            .expect("Expected container creation to succeed without panicking");
    }
}
