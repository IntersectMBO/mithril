mod clear_immutables_archives_cache;
mod generate_keypair;
mod recompute_certificates_hash;

pub use clear_immutables_archives_cache::*;
pub use generate_keypair::*;
pub use recompute_certificates_hash::*;

use clap::{Parser, Subcommand};
use config::{ConfigBuilder, builder::DefaultState};
use slog::Logger;
use std::collections::HashMap;

use mithril_common::StdResult;
use mithril_doc::StructDoc;

use crate::extract_all;

/// List of tools to upkeep the aggregator
#[derive(Parser, Debug, Clone)]
pub struct ToolsCommand {
    /// commands
    #[clap(subcommand)]
    pub subcommand: ToolsSubCommand,
}

impl ToolsCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        self.subcommand.execute(root_logger, config_builder).await
    }

    pub fn extract_config(command_path: String) -> HashMap<String, StructDoc> {
        extract_all!(
            command_path,
            ToolsSubCommand,
            RecomputeCertificatesHash = { RecomputeCertificatesHashCommand },
            GenerateKeypair = { GenerateKeypairCommand },
            ClearImmutablesArchivesCache = { ClearImmutablesArchivesCacheCommand },
        )
    }
}

/// Tools subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum ToolsSubCommand {
    /// Load all certificates in the database to recompute their hash and update all related
    /// entities.
    ///
    /// Since it will modify the aggregator sqlite database it's strongly recommended to backup it
    /// before running this command.
    RecomputeCertificatesHash(RecomputeCertificatesHashCommand),

    /// Generate a new keypair
    GenerateKeypair(GenerateKeypairCommand),

    /// Clear the cache directory of the immutable files compressed archives.
    ///
    /// Must not be run while the aggregator is running.
    ClearImmutablesArchivesCache(ClearImmutablesArchivesCacheCommand),
}

impl ToolsSubCommand {
    pub async fn execute(
        &self,
        root_logger: Logger,
        config_builder: ConfigBuilder<DefaultState>,
    ) -> StdResult<()> {
        match self {
            Self::RecomputeCertificatesHash(cmd) => cmd.execute(root_logger, config_builder).await,
            Self::GenerateKeypair(cmd) => cmd.execute(root_logger).await,
            Self::ClearImmutablesArchivesCache(cmd) => {
                cmd.execute(root_logger, config_builder).await
            }
        }
    }
}
