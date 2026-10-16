//! Command to setup a Mithril signer

use clap::Parser;
use slog::info;

use crate::CommandContext;

/// Clap command to setup a Mithril signer
#[derive(Parser, Debug, Clone)]
pub struct SignerCommand {}

impl SignerCommand {
    /// Main command execution
    pub async fn execute(&self, context: CommandContext) -> anyhow::Result<()> {
        info!(context.logger(), "signer command");
        Ok(())
    }
}
