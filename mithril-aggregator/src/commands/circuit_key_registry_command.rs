use std::{collections::HashMap, path::PathBuf};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use slog::{Logger, debug};

use mithril_common::{
    StdResult,
    crypto_helper::{
        CircuitVerificationKeyDigest, CircuitVerificationKeyEntry, CircuitVerificationKeyStatus,
    },
    entities::{Epoch, HexEncodedGenesisSecretKey, ProtocolParameters},
};
use mithril_doc::StructDoc;

use crate::{extract_all, tools::CircuitKeyRegistryTools};

/// Circuit verification key registry tools
#[derive(Parser, Debug, Clone)]
pub struct CircuitKeyRegistryCommand {
    /// commands
    #[clap(subcommand)]
    pub circuit_key_registry_subcommand: CircuitKeyRegistrySubCommand,
}

impl CircuitKeyRegistryCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        self.circuit_key_registry_subcommand.execute(root_logger).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            CircuitKeyRegistrySubCommand,
            Export = { ExportCircuitKeyRegistrySubCommand },
            Whitelist = { WhitelistCircuitKeyRegistrySubCommand },
            Revoke = { RevokeCircuitKeyRegistrySubCommand },
            Sign = { SignCircuitKeyRegistrySubCommand },
            Bootstrap = { BootstrapCircuitKeyRegistrySubCommand },
        )
    }

    /// Parse protocol parameters from their JSON representation.
    fn parse_protocol_parameters(value: &str) -> Result<ProtocolParameters, String> {
        serde_json::from_str(value)
            .map_err(|error| format!("invalid protocol parameters JSON: {error}"))
    }
}

/// Circuit verification key registry commands.
#[derive(Debug, Clone, Subcommand)]
pub enum CircuitKeyRegistrySubCommand {
    /// Circuit verification key digests export command.
    Export(ExportCircuitKeyRegistrySubCommand),

    /// Circuit verification key whitelist command.
    Whitelist(WhitelistCircuitKeyRegistrySubCommand),

    /// Circuit verification key revoke command.
    Revoke(RevokeCircuitKeyRegistrySubCommand),

    /// Circuit verification key registry sign command.
    Sign(SignCircuitKeyRegistrySubCommand),

    /// Circuit verification key registry bootstrap command (test only).
    Bootstrap(BootstrapCircuitKeyRegistrySubCommand),
}

impl CircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        match self {
            Self::Export(cmd) => cmd.execute(root_logger).await,
            Self::Whitelist(cmd) => cmd.execute(root_logger).await,
            Self::Revoke(cmd) => cmd.execute(root_logger).await,
            Self::Sign(cmd) => cmd.execute(root_logger).await,
            Self::Bootstrap(cmd) => cmd.execute(root_logger).await,
        }
    }
}

/// Circuit verification key digests export command
#[derive(Parser, Debug, Clone)]
pub struct ExportCircuitKeyRegistrySubCommand {
    /// Protocol parameters of the network as JSON (e.g. '{"k":5,"m":9,"phi_f":0.95}'), defaults to
    /// the production protocol parameters of the embedded certificate circuit key
    #[clap(long, value_parser = CircuitKeyRegistryCommand::parse_protocol_parameters)]
    protocol_parameters: Option<ProtocolParameters>,

    /// Target Path
    #[clap(long)]
    target_path: PathBuf,
}

impl ExportCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "EXPORT CIRCUIT KEY REGISTRY command");
        println!(
            "Circuit verification key digests export to {}",
            self.target_path.display()
        );

        let digests = CircuitKeyRegistryTools::export_digests(
            self.protocol_parameters.as_ref(),
            &self.target_path,
        )
        .with_context(|| "circuit-key-registry-tools: export digests error")?;
        println!("certificate-circuit: {}", digests.certificate_circuit);
        println!("ivc-circuit: {}", digests.ivc_circuit);

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Arguments identifying a registry entry and the signed registry to add it to
#[derive(Args, Debug, Clone)]
pub struct CircuitKeyRegistryEntryArguments {
    /// Signed Registry Path, created when missing and updated in place
    #[clap(long)]
    registry_path: PathBuf,

    /// Genesis Secret Key Path
    #[clap(long)]
    genesis_secret_key_path: PathBuf,

    /// Digest of the circuit verification key (hex encoded)
    #[clap(long)]
    digest: CircuitVerificationKeyDigest,

    /// Name of the circuit verification key (e.g. 'certificate-circuit v1')
    #[clap(long)]
    name: String,

    /// First epoch (inclusive) covered by the entry
    #[clap(long)]
    start_epoch: u64,

    /// Last epoch (inclusive) covered by the entry, open-ended when omitted
    #[clap(long)]
    end_epoch: Option<u64>,
}

impl CircuitKeyRegistryEntryArguments {
    /// Add the entry with the given status and comment to the signed registry and print the
    /// resulting registry version.
    fn add_entry(
        &self,
        status: CircuitVerificationKeyStatus,
        comment: Option<String>,
    ) -> StdResult<()> {
        let entry = CircuitVerificationKeyEntry {
            digest: self.digest,
            name: self.name.clone(),
            status,
            start_epoch: Epoch(self.start_epoch),
            end_epoch: self.end_epoch.map(Epoch),
            comment,
        };
        let registry = CircuitKeyRegistryTools::add_entry(
            &self.registry_path,
            &self.genesis_secret_key_path,
            entry,
        )
        .with_context(|| "circuit-key-registry-tools: add entry error")?;
        println!(
            "Circuit verification key registry version {} signed and written to {}",
            registry.version,
            self.registry_path.display()
        );

        Ok(())
    }
}

/// Circuit verification key whitelist command
#[derive(Parser, Debug, Clone)]
pub struct WhitelistCircuitKeyRegistrySubCommand {
    #[clap(flatten)]
    entry: CircuitKeyRegistryEntryArguments,

    /// Comment recorded in the entry
    #[clap(long)]
    comment: Option<String>,
}

impl WhitelistCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "WHITELIST CIRCUIT KEY REGISTRY command");
        println!(
            "Circuit verification key '{}' whitelist in {}",
            self.entry.name,
            self.entry.registry_path.display()
        );

        self.entry
            .add_entry(CircuitVerificationKeyStatus::Allowed, self.comment.clone())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Circuit verification key revoke command
#[derive(Parser, Debug, Clone)]
pub struct RevokeCircuitKeyRegistrySubCommand {
    #[clap(flatten)]
    entry: CircuitKeyRegistryEntryArguments,

    /// Comment recorded in the entry, explaining the revocation
    #[clap(long)]
    comment: String,
}

impl RevokeCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "REVOKE CIRCUIT KEY REGISTRY command");
        println!(
            "Circuit verification key '{}' revocation in {}",
            self.entry.name,
            self.entry.registry_path.display()
        );

        self.entry.add_entry(
            CircuitVerificationKeyStatus::Revoked,
            Some(self.comment.clone()),
        )
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Circuit verification key registry sign command
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

impl SignCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "SIGN CIRCUIT KEY REGISTRY command");
        println!(
            "Circuit verification key registry sign from {} to {}",
            self.to_sign_registry_path.display(),
            self.target_signed_registry_path.display()
        );

        CircuitKeyRegistryTools::sign(
            &self.to_sign_registry_path,
            &self.target_signed_registry_path,
            &self.genesis_secret_key_path,
        )
        .with_context(|| "circuit-key-registry-tools: sign registry error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Circuit verification key registry bootstrap command (test only)
#[derive(Parser, Debug, Clone)]
pub struct BootstrapCircuitKeyRegistrySubCommand {
    /// Genesis Secret Key (test only)
    #[clap(long, env = "GENESIS_SECRET_KEY")]
    genesis_secret_key: HexEncodedGenesisSecretKey,

    /// Protocol parameters of the network as JSON (e.g. '{"k":5,"m":9,"phi_f":0.95}'), defaults to
    /// the production protocol parameters of the embedded certificate circuit key
    #[clap(long, value_parser = CircuitKeyRegistryCommand::parse_protocol_parameters)]
    protocol_parameters: Option<ProtocolParameters>,

    /// Target Registry Path
    #[clap(long)]
    target_registry_path: PathBuf,
}

impl BootstrapCircuitKeyRegistrySubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "BOOTSTRAP CIRCUIT KEY REGISTRY command");
        println!(
            "Circuit verification key registry bootstrap for test only, to {}",
            self.target_registry_path.display()
        );

        CircuitKeyRegistryTools::bootstrap(
            &self.genesis_secret_key,
            self.protocol_parameters.as_ref(),
            &self.target_registry_path,
        )
        .with_context(|| "circuit-key-registry-tools: bootstrap registry error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}
