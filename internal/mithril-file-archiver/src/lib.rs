#![warn(missing_docs)]

//! # Mithril-file-archiver
//!
//! An API to generate tar archives from files, directories, or serializable data (leveraging serde).
//!
//! Produced archives are byte-stable across systems as long as the following invariants do not change:
//! * Archive entry paths and contents
//! * The versions and behavior of the TAR and Zstandard libraries
//! * The Zstandard compression parameters, including the compression level and number of workers
//! * TAR header generation and metadata normalization
//! * JSON serialization output when using `AppenderData::from_json`
//!
//! One exception: owner-executable files, because Windows cannot represent the Unix owner-execute
//! bit, archives containing such files may differ between Windows and Unix.
//!

mod api;
pub mod appender;
mod entities;
pub mod test;
pub mod tools;

pub use api::*;
pub use entities::*;
