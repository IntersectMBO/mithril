use std::{collections::HashMap, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use slog::{Logger, debug};

use mithril_common::StdResult;
use mithril_doc::StructDoc;

use crate::{extract_all, tools::KeypairTools};

/// List of commands to generate a new keypair
#[derive(Parser, Debug, Clone)]
pub struct GenerateKeypairCommand {
    /// Keypair type
    #[clap(subcommand)]
    pub subcommand: GenerateKeypairSubCommand,
}

/// Keypair type subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum GenerateKeypairSubCommand {
    /// Generate an Ed25519 keypair
    Ed25519(Ed25519SubCommand),
}

impl GenerateKeypairCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        match &self.subcommand {
            GenerateKeypairSubCommand::Ed25519(cmd) => cmd.execute(root_logger).await,
        }
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            GenerateKeypairSubCommand,
            Ed25519 = { Ed25519SubCommand },
        )
    }
}

/// Ed25519 keypair generation command.
#[derive(clap::Args, Debug, Clone)]
pub struct Ed25519SubCommand {
    /// Target path for the generated keypair
    #[clap(long)]
    target_path: PathBuf,
}

impl Ed25519SubCommand {
    pub async fn execute(&self, root_logger: Logger) -> StdResult<()> {
        debug!(root_logger, "GENERATE KEYPAIR ED25519 command");
        println!(
            "tools generate keypair ed25519 to {}",
            self.target_path.display()
        );
        KeypairTools::create_and_save_ed25519_keypair(&self.target_path)
            .with_context(|| "tools: keypair generation error")?;

        Ok(())
    }

    pub fn extract_config(_command_path: String) -> HashMap<String, StructDoc> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use crate::test::TestLogger;

    use super::super::{ToolsCommand, ToolsSubCommand};
    use super::*;

    #[test]
    fn generate_keypair_subcommand_parses_target_path() {
        let cmd = ToolsCommand::try_parse_from([
            "tools",
            "generate-keypair",
            "ed25519",
            "--target-path",
            "/tmp/keys",
        ])
        .expect("CLI parse should succeed");
        assert!(matches!(
            cmd.subcommand,
            ToolsSubCommand::GenerateKeypair(GenerateKeypairCommand {
                subcommand: GenerateKeypairSubCommand::Ed25519(_)
            })
        ));
    }

    #[tokio::test]
    async fn generate_ed25519_keypair_subcommand_writes_key_files() {
        let target = temp_dir_create!();
        let cmd = Ed25519SubCommand {
            target_path: target.clone(),
        };

        cmd.execute(TestLogger::stdout())
            .await
            .expect("generate-keypair ed25519 should succeed");
        assert!(target.join("ed25519_keypair.sk").exists());
        assert!(target.join("ed25519_keypair.vk").exists());
    }
}
