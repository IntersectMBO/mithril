use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use mithril_common::{
    StdResult,
    crypto_helper::{EraMarkersSigner, EraMarkersVerifierSecretKey},
    entities::{Epoch, HexEncodedEraMarkersSecretKey},
};
use mithril_doc::StructDoc;
use slog::{Logger, debug};

use crate::{
    extract_all,
    tools::{EraMarkersDatumFormat, EraTools},
};

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

    /// Sequence number of the era markers, strictly greater than the one of the last era markers
    /// signed for the network
    #[clap(long, required_unless_present = "legacy", conflicts_with = "legacy")]
    sequence_number: Option<u64>,

    /// Generate the deprecated legacy era markers (without sequence number), for the nodes that
    /// can not read the era markers with a sequence number yet
    #[clap(long)]
    legacy: bool,

    /// Era Markers Secret Key
    #[clap(long, env = "ERA_MARKERS_SECRET_KEY")]
    era_markers_secret_key: HexEncodedEraMarkersSecretKey,

    /// Target path
    #[clap(long)]
    target_path: PathBuf,
}

impl GenerateTxDatumEraSubCommand {
    /// Format of the era markers to generate
    fn era_markers_datum_format(&self) -> StdResult<EraMarkersDatumFormat> {
        match (self.legacy, self.sequence_number) {
            (false, Some(sequence_number)) => {
                Ok(EraMarkersDatumFormat::Sequenced { sequence_number })
            }
            (true, None) => Ok(EraMarkersDatumFormat::Legacy),
            (true, Some(_)) => Err(anyhow!(
                "the sequence number can not be used with the legacy era markers"
            )),
            (false, None) => Err(anyhow!(
                "the sequence number is required unless the legacy era markers are generated"
            )),
        }
    }

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
            self.era_markers_datum_format()?,
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

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    const BASE_ARGUMENTS: [&str; 7] = [
        "generate-tx-datum",
        "--current-era-epoch",
        "1",
        "--era-markers-secret-key",
        "secret-key",
        "--target-path",
        "datum.json",
    ];

    fn parse(additional_arguments: &[&str]) -> Result<GenerateTxDatumEraSubCommand, clap::Error> {
        GenerateTxDatumEraSubCommand::try_parse_from(
            BASE_ARGUMENTS.iter().chain(additional_arguments.iter()),
        )
    }

    #[test]
    fn generate_tx_datum_with_a_sequence_number_targets_the_sequenced_format() {
        let command = parse(&["--sequence-number", "5"]).unwrap();

        assert_eq!(
            EraMarkersDatumFormat::Sequenced { sequence_number: 5 },
            command.era_markers_datum_format().unwrap()
        );
    }

    #[test]
    fn generate_tx_datum_with_legacy_targets_the_legacy_format() {
        let command = parse(&["--legacy"]).unwrap();

        assert_eq!(
            EraMarkersDatumFormat::Legacy,
            command.era_markers_datum_format().unwrap()
        );
    }

    #[test]
    fn era_markers_datum_format_fails_with_both_a_sequence_number_and_legacy() {
        let command = GenerateTxDatumEraSubCommand {
            sequence_number: Some(5),
            ..parse(&["--legacy"]).unwrap()
        };

        command
            .era_markers_datum_format()
            .expect_err("a sequence number with legacy should be rejected");
    }

    #[test]
    fn era_markers_datum_format_fails_without_sequence_number_nor_legacy() {
        let command = GenerateTxDatumEraSubCommand {
            legacy: false,
            ..parse(&["--legacy"]).unwrap()
        };

        command
            .era_markers_datum_format()
            .expect_err("a missing sequence number without legacy should be rejected");
    }

    #[test]
    fn generate_tx_datum_without_sequence_number_nor_legacy_is_rejected() {
        let error = parse(&[]).unwrap_err();

        assert_eq!(ErrorKind::MissingRequiredArgument, error.kind());
    }

    #[test]
    fn generate_tx_datum_with_both_sequence_number_and_legacy_is_rejected() {
        let error = parse(&["--sequence-number", "5", "--legacy"]).unwrap_err();

        assert_eq!(ErrorKind::ArgumentConflict, error.kind());
    }
}
