use anyhow::{Context, anyhow};
use slog_scope::warn;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mithril_common::StdResult;
use mithril_common::entities::{BlockHash, EpochSpecifier, TransactionHash};

use crate::utils::{MithrilCommand, NodeVersion};
use crate::{ANCILLARY_MANIFEST_VERIFICATION_KEY, GENESIS_VERIFICATION_KEY};

#[derive(Debug)]
pub struct Client {
    command: MithrilCommand,
    version: NodeVersion,
}

#[derive(Debug)]
pub enum CardanoDbV2Command {
    List,
    ListPerEpoch { epoch_specifier: EpochSpecifier },
    Show { hash: String },
    Download { hash: String },
}

impl CardanoDbV2Command {
    fn name(&self) -> String {
        match self {
            CardanoDbV2Command::List => "list".to_string(),
            CardanoDbV2Command::ListPerEpoch { epoch_specifier } => {
                format!("list-epoch-{epoch_specifier}")
            }
            CardanoDbV2Command::Show { hash } => format!("show-{hash}"),
            CardanoDbV2Command::Download { hash } => format!("download-{hash}"),
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            CardanoDbV2Command::List => {
                vec!["snapshot".to_string(), "list".to_string()]
            }
            CardanoDbV2Command::ListPerEpoch { epoch_specifier } => {
                vec![
                    "snapshot".to_string(),
                    "list".to_string(),
                    "--epoch".to_string(),
                    epoch_specifier.to_string(),
                ]
            }
            CardanoDbV2Command::Show { hash } => {
                vec!["snapshot".to_string(), "show".to_string(), hash.clone()]
            }
            CardanoDbV2Command::Download { hash } => {
                vec![
                    "download".to_string(),
                    "--include-ancillary".to_string(),
                    "--allow-override".to_string(),
                    "--download-dir".to_string(),
                    "v2".to_string(),
                    hash.clone(),
                ]
            }
        }
    }
}

#[derive(Debug)]
pub enum MithrilStakeDistributionCommand {
    List,
    Download { hash: String },
}

impl MithrilStakeDistributionCommand {
    fn name(&self) -> String {
        match self {
            MithrilStakeDistributionCommand::List => "list".to_string(),
            MithrilStakeDistributionCommand::Download { hash } => format!("download-{hash}"),
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            MithrilStakeDistributionCommand::List => {
                vec!["list".to_string()]
            }
            MithrilStakeDistributionCommand::Download { hash } => {
                vec!["download".to_string(), hash.clone()]
            }
        }
    }
}

#[derive(Debug)]
pub enum CardanoTransactionCommand {
    ListSnapshot,
    ShowSnapshot { hash: String },
    Certify { tx_hashes: Vec<TransactionHash> },
}

impl CardanoTransactionCommand {
    fn name(&self) -> String {
        match self {
            CardanoTransactionCommand::ListSnapshot => "list-snapshot".to_string(),
            CardanoTransactionCommand::ShowSnapshot { hash } => format!("show-snapshot-{hash}"),
            CardanoTransactionCommand::Certify { tx_hashes } if tx_hashes.len() > 1 => {
                // Only output first & last hash to avoid too long filenames
                format!("certify-{}..{}", tx_hashes[0], tx_hashes.last().unwrap())
            }
            CardanoTransactionCommand::Certify { tx_hashes } => {
                format!("certify-{}", tx_hashes.first().unwrap_or(&String::new()))
            }
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            CardanoTransactionCommand::ListSnapshot => {
                vec!["snapshot".to_string(), "list".to_string()]
            }
            CardanoTransactionCommand::ShowSnapshot { hash } => {
                vec!["snapshot".to_string(), "show".to_string(), hash.clone()]
            }
            CardanoTransactionCommand::Certify { tx_hashes } => {
                vec!["certify".to_string(), tx_hashes.join(",")]
            }
        }
    }
}

#[derive(Debug)]
pub enum CardanoTransactionV2Command {
    ListSnapshot,
    ShowSnapshot { hash: String },
    Certify { tx_hashes: Vec<TransactionHash> },
}

impl CardanoTransactionV2Command {
    fn name(&self) -> String {
        match self {
            CardanoTransactionV2Command::ListSnapshot => "list-snapshot".to_string(),
            CardanoTransactionV2Command::ShowSnapshot { hash } => format!("show-snapshot-{hash}"),
            CardanoTransactionV2Command::Certify { tx_hashes } if tx_hashes.len() > 1 => {
                // Only output first & last hash to avoid too long filenames
                format!("certify-{}..{}", tx_hashes[0], tx_hashes.last().unwrap())
            }
            CardanoTransactionV2Command::Certify { tx_hashes } => {
                format!("certify-{}", tx_hashes.first().unwrap_or(&String::new()))
            }
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            CardanoTransactionV2Command::ListSnapshot => {
                vec!["snapshot".to_string(), "list".to_string()]
            }
            CardanoTransactionV2Command::ShowSnapshot { hash } => {
                vec!["snapshot".to_string(), "show".to_string(), hash.clone()]
            }
            CardanoTransactionV2Command::Certify { tx_hashes } => {
                vec!["certify".to_string(), tx_hashes.join(",")]
            }
        }
    }
}

#[derive(Debug)]
pub enum CardanoBlockCommand {
    ListSnapshot,
    ShowSnapshot { hash: String },
    Certify { block_hashes: Vec<BlockHash> },
}

impl CardanoBlockCommand {
    fn name(&self) -> String {
        match self {
            CardanoBlockCommand::ListSnapshot => "list-snapshot".to_string(),
            CardanoBlockCommand::ShowSnapshot { hash } => format!("show-snapshot-{hash}"),
            CardanoBlockCommand::Certify { block_hashes } if block_hashes.len() > 1 => {
                // Only output first & last hash to avoid too long filenames
                format!(
                    "certify-{}..{}",
                    block_hashes[0],
                    block_hashes.last().unwrap()
                )
            }
            CardanoBlockCommand::Certify { block_hashes } => {
                format!("certify-{}", block_hashes.first().unwrap_or(&String::new()))
            }
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            CardanoBlockCommand::ListSnapshot => {
                vec!["snapshot".to_string(), "list".to_string()]
            }
            CardanoBlockCommand::ShowSnapshot { hash } => {
                vec!["snapshot".to_string(), "show".to_string(), hash.clone()]
            }
            CardanoBlockCommand::Certify { block_hashes } => {
                vec!["certify".to_string(), block_hashes.join(",")]
            }
        }
    }
}

#[derive(Debug)]
pub enum CardanoStakeDistributionCommand {
    List,
    Download { unique_identifier: String },
}

impl CardanoStakeDistributionCommand {
    fn name(&self) -> String {
        match self {
            CardanoStakeDistributionCommand::List => "list".to_string(),
            CardanoStakeDistributionCommand::Download { unique_identifier } => {
                format!("download-{unique_identifier}")
            }
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            CardanoStakeDistributionCommand::List => {
                vec!["list".to_string()]
            }
            CardanoStakeDistributionCommand::Download { unique_identifier } => {
                vec!["download".to_string(), unique_identifier.clone()]
            }
        }
    }
}
#[derive(Debug)]
pub enum ToolsCommand {
    UtxoHd(UtxoHdCommand),
}

impl ToolsCommand {
    fn name(&self) -> String {
        match self {
            ToolsCommand::UtxoHd(cmd) => format!("utxo-hd-{}", cmd.name()),
        }
    }

    fn cli_arg(&self, client_version: &NodeVersion) -> Vec<String> {
        match self {
            ToolsCommand::UtxoHd(cmd) => cmd.cli_arg(client_version),
        }
    }
}

#[derive(Debug)]
pub enum UtxoHdCommand {
    SnapshotConverter {
        db_directory: String,
        cardano_node_version: String,
        binary_path: String,
        config_path: String,
        utxo_hd_flavor: String,
        commit: bool,
    },
}

impl UtxoHdCommand {
    fn name(&self) -> String {
        match self {
            UtxoHdCommand::SnapshotConverter { .. } => "snapshot-converter".to_string(),
        }
    }

    fn cli_arg(&self, _client_version: &NodeVersion) -> Vec<String> {
        match self {
            UtxoHdCommand::SnapshotConverter {
                db_directory,
                cardano_node_version,
                binary_path,
                config_path,
                utxo_hd_flavor,
                commit,
            } => {
                let mut arguments = vec![
                    "utxo-hd".to_string(),
                    "snapshot-converter".to_string(),
                    "--db-directory".to_string(),
                    db_directory.clone(),
                    "--cardano-node-version".to_string(),
                    cardano_node_version.clone(),
                    "--binary-path".to_string(),
                    binary_path.clone(),
                    "--config-path".to_string(),
                    config_path.clone(),
                    "--utxo-hd-flavor".to_string(),
                    utxo_hd_flavor.clone(),
                ];
                if *commit {
                    arguments.push("--commit".to_string());
                }
                arguments
            }
        }
    }
}

#[derive(Debug)]
pub enum ClientCommand {
    MithrilStakeDistribution(MithrilStakeDistributionCommand),
    CardanoTransaction(CardanoTransactionCommand),
    CardanoTransactionV2(CardanoTransactionV2Command),
    CardanoStakeDistribution(CardanoStakeDistributionCommand),
    CardanoDbV2(CardanoDbV2Command),
    CardanoBlock(CardanoBlockCommand),
    Tools(ToolsCommand),
}

impl ClientCommand {
    fn name(&self) -> String {
        match self {
            ClientCommand::MithrilStakeDistribution(cmd) => {
                format!("msd-{}", cmd.name())
            }
            ClientCommand::CardanoTransaction(cmd) => {
                format!("ctx-{}", cmd.name())
            }
            ClientCommand::CardanoTransactionV2(cmd) => {
                format!("ctxv2-{}", cmd.name())
            }
            ClientCommand::CardanoBlock(cmd) => {
                format!("cblock-{}", cmd.name())
            }
            ClientCommand::CardanoStakeDistribution(cmd) => {
                format!("csd-{}", cmd.name())
            }
            ClientCommand::CardanoDbV2(cmd) => {
                format!("cdbv2-{}", cmd.name())
            }
            ClientCommand::Tools(cmd) => {
                format!("tools-{}", cmd.name())
            }
        }
    }

    fn cli_arg(&self, client_version: &NodeVersion) -> Vec<String> {
        let mut args = match self {
            ClientCommand::MithrilStakeDistribution(cmd) => [
                vec!["mithril-stake-distribution".to_string()],
                cmd.cli_arg(client_version),
            ]
            .concat(),
            ClientCommand::CardanoTransaction(cmd) => {
                if client_version.is_below("0.13.1") {
                    warn!(
                        "client version is below 0.13.1, skip unsupported `--backend` flag for `cardano-transaction`"
                    );
                    [vec!["cardano-transaction".to_string()], cmd.cli_arg(client_version)].concat()
                } else {
                    [
                        vec!["cardano-transaction".to_string()],
                        cmd.cli_arg(client_version),
                        vec!["--backend".to_string(), "v1".to_string()],
                    ]
                    .concat()
                }
            }
            ClientCommand::CardanoTransactionV2(cmd) => [
                vec!["cardano-transaction".to_string()],
                cmd.cli_arg(client_version),
                vec!["--backend".to_string(), "v2".to_string()],
                vec!["--unstable".to_string()],
            ]
            .concat(),
            ClientCommand::CardanoBlock(cmd) => [
                vec!["cardano-block".to_string()],
                cmd.cli_arg(client_version),
                vec!["--unstable".to_string()],
            ]
            .concat(),
            ClientCommand::CardanoStakeDistribution(cmd) => [
                vec!["cardano-stake-distribution".to_string()],
                cmd.cli_arg(client_version),
            ]
            .concat(),
            ClientCommand::CardanoDbV2(cmd) => {
                if client_version.is_below("0.12.11") {
                    warn!(
                        "client version is below 0.12.11, fallback to `cardano-db-v2` command instead of unsupported `cardano-db --backend v2`"
                    );
                    [vec!["cardano-db-v2".to_string()], cmd.cli_arg(client_version)].concat()
                } else {
                    [
                        vec!["cardano-db".to_string()],
                        cmd.cli_arg(client_version),
                        vec!["--backend".to_string(), "v2".to_string()],
                    ]
                    .concat()
                }
            }
            ClientCommand::Tools(cmd) => {
                [vec!["tools".to_string()], cmd.cli_arg(client_version)].concat()
            }
        };
        args.push("--json".to_string());

        args
    }
}

impl Client {
    pub const BIN_NAME: &'static str = "mithril-client";

    pub fn new(aggregator_endpoint: String, work_dir: &Path, bin_dir: &Path) -> StdResult<Self> {
        let env = HashMap::from([
            ("GENESIS_VERIFICATION_KEY", GENESIS_VERIFICATION_KEY),
            ("AGGREGATOR_ENDPOINT", &aggregator_endpoint),
            (
                "ANCILLARY_VERIFICATION_KEY",
                ANCILLARY_MANIFEST_VERIFICATION_KEY,
            ),
        ]);
        let version = NodeVersion::fetch(Self::BIN_NAME, bin_dir)?;

        // Always use the unstable flag as the e2e tests are not meant to check the coherence of the client commands
        let mut args = vec!["-vvv", "--unstable"];
        if version.is_above_or_equal("0.11.13") {
            args.extend_from_slice(&["--origin-tag", "E2E"]);
        } else {
            warn!("client version is below 0.11.13, skip unsupported `--origin-tag` flag");
        }

        let command = MithrilCommand::new(Self::BIN_NAME, work_dir, bin_dir, env, &args)?;

        Ok(Self { command, version })
    }

    pub async fn run(&mut self, command: ClientCommand) -> StdResult<PathBuf> {
        let output_path = self
            .command
            .set_output_filename(&format!("mithril-client-{}", command.name()));
        let args = command.cli_arg(self.version());

        let exit_status = self
            .command
            .start(&args)?
            .wait()
            .await
            .with_context(|| "mithril-client crashed")?;

        if exit_status.success() {
            Ok(output_path)
        } else {
            self.command
                .tail_logs(Some(format!("mithril-client {args:?}").as_str()), 40)
                .await?;

            Err(match exit_status.code() {
                Some(c) => anyhow!("mithril-client exited with code: {c}"),
                None => anyhow!("mithril-client was terminated with a signal"),
            })
        }
    }

    /// Get the version of the mithril-client binary.
    pub fn version(&self) -> &NodeVersion {
        &self.version
    }
}
