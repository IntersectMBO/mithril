//! Tools commands
//!
//! Provides utility subcommands such as converting restored InMemory UTxO-HD ledger snapshot
//! to different flavors (Legacy, LMDB) or resetting the certificate chain cache.

mod aggregator_discovery;
mod cache;
mod utxo_hd;

pub use aggregator_discovery::*;
pub use cache::*;
pub use utxo_hd::*;

use clap::Subcommand;

use mithril_client::MithrilResult;

use crate::CommandContext;

/// Tools commands
#[derive(Subcommand, Debug, Clone)]
#[command(about = "Tools commands")]
pub enum ToolsCommands {
    /// UTxO-HD related commands
    #[clap(subcommand, name = "utxo-hd")]
    UTxOHD(UTxOHDCommands),
    /// Aggregator discovery command (unstable)
    #[clap(name = "discover-aggregator")]
    AggregatorDiscovery(AggregatorDiscoveryCommand),
    /// Cache related commands (unstable)
    #[clap(subcommand)]
    Cache(CacheCommands),
}

impl ToolsCommands {
    /// Execute Tools command
    pub async fn execute(&self, context: CommandContext) -> MithrilResult<()> {
        match self {
            Self::UTxOHD(cmd) => cmd.execute(context).await,
            Self::AggregatorDiscovery(cmd) => {
                context.require_unstable("tools discover-aggregator", Some("release-mainnet"))?;

                cmd.execute(context).await
            }
            Self::Cache(cmd) => {
                context.require_unstable("tools cache", Some("reset"))?;

                cmd.execute(context).await
            }
        }
    }
}
