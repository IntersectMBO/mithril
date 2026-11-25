//! Guessing of the configuration values that are deduced from the discovered facts
//!
//! The guessing is pure: it takes the facts already read from the environment and does no I/O.

mod network;

pub use network::*;
