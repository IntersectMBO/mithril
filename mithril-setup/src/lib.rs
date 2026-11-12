#![warn(missing_docs)]

//! A command line interface helping to setup Mithril environments.
//!
mod command_context;
mod commands;
mod config;
pub mod discovery;
mod orchestrator;
pub mod setups;
pub mod tui;

pub use command_context::*;
pub use commands::*;
pub use config::*;
pub use orchestrator::*;
