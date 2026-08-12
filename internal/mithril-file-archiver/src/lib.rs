#![warn(missing_docs)]

//! # Mithril-file-archiver
//!
//! An API to generate tar archives from files, directories, or serializable data (leveraging serde).
//!
//! Produced archives are byte-stable across systems as long as the following invariants do not change:
//! * The version of the zstandard compression library
//! * The parameters of the zstandard compression
//!

mod api;
pub mod appender;
mod entities;
pub mod test;
pub mod tools;

pub use api::*;
pub use entities::*;
