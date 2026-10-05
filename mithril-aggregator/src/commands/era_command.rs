use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use mithril_common::{
    StdResult,
    crypto_helper::{EraMarkersSigner, EraMarkersVerifierSecretKey},
    entities::{Epoch, HexEncodedEraMarkersSecretKey},
};
use mithril_doc::StructDoc;
use slog::{Logger, debug};

use crate::{extract_all, tools::EraTools};

/// Era tools
#[derive(Parser, Debug, Clone)]
pub struct EraCommand {
    /// commands
    #[clap(subcommand)]
    pub era_subcommand: EraSubCommand,
}

impl EraCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        self.era_subcommand.execute(root_logger).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            EraSubCommand,
            List = { ListEraSubCommand },
            GenerateTxDatum = { GenerateTxDatumEraSubCommand },
            GenerateKeypair = { GenerateKeypairEraSubCommand },
        )
    }
}

/// Era tools commands.
#[derive(Debug, Clone, Subcommand)]
pub enum EraSubCommand {
    /// Era list command.
    List(ListEraSubCommand),

    /// Era tx datum generate command.
    GenerateTxDatum(GenerateTxDatumEraSubCommand),

    /// Deprecated, use `tools generate-keypair ed25519` instead
    GenerateKeypair(GenerateKeypairEraSubCommand),
}

impl EraSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        match self {
            Self::List(cmd) => cmd.execute(root_logger).await,
            Self::GenerateTxDatum(cmd) => cmd.execute(root_logger).await,
            Self::GenerateKeypair(cmd) => cmd.execute(root_logger).await,
        }
    }
}

/// Era list command
#[derive(Parser, Debug, Clone)]
pub struct ListEraSubCommand {
    /// Enable JSON output.
    #[clap(long)]
    json: bool,
}

impl ListEraSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "LIST ERA command");
        let era_tools = EraTools::new();
        let eras = era_tools.get_supported_eras_list()?;

        if self.json {
            println!("{}", serde_json::to_string(&eras)?);
        } else {
            println!("Supported Eras:");
            println!("{eras:#?}");
        }

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// Era tx datum generate command
#[derive(Parser, Debug, Clone)]
pub struct GenerateTxDatumEraSubCommand {
    /// Current Era epoch
    #[clap(long, env = "CURRENT_ERA_EPOCH")]
    current_era_epoch: u64,

    /// Next Era epoch start, if exists
    #[clap(long, env = "NEXT_ERA_EPOCH")]
    next_era_epoch: Option<u64>,

    /// Era Markers Secret Key
    #[clap(long, env = "ERA_MARKERS_SECRET_KEY")]
    era_markers_secret_key: HexEncodedEraMarkersSecretKey,

    /// Target path
    #[clap(long)]
    target_path: PathBuf,
}

impl GenerateTxDatumEraSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "GENERATETXDATUM ERA command");
        let era_tools = EraTools::new();

        let era_markers_secret_key =
            EraMarkersVerifierSecretKey::from_json_hex(&self.era_markers_secret_key)
                .with_context(|| "json hex decode of era markers secret key failure")?;
        let era_markers_signer = EraMarkersSigner::from_secret_key(era_markers_secret_key);
        let tx_datum = era_tools.generate_tx_datum(
            Epoch(self.current_era_epoch),
            self.next_era_epoch.map(Epoch),
            &era_markers_signer,
        )?;

        let mut target_file = File::create(&self.target_path)?;
        target_file.write_all(tx_datum.as_bytes())?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

/// [Deprecated] Era keypair generation command.
#[derive(Parser, Debug, Clone)]
pub struct GenerateKeypairEraSubCommand {
    /// Target path for the generated keypair
    #[clap(long)]
    target_path: PathBuf,
}

impl GenerateKeypairEraSubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        println!(
            "Era keypair generation is deprecated and will be removed in future versions. Please use the `tools generate-keypair ed25519` command instead."
        );
        debug!(root_logger, "GENERATE KEYPAIR ERA command");
        println!("Era generate keypair to {}", self.target_path.display());

        EraTools::create_and_save_era_keypair(&self.target_path)
            .with_context(|| "era-tools: keypair generation error")?;

        Ok(())
    }

    pub fn extract_config(_parent: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}
