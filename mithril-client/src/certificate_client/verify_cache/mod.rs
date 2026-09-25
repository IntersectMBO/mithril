#[cfg(feature = "fs")]
mod file_cache;
mod memory_cache;

#[cfg(feature = "fs")]
pub use file_cache::*;
pub use memory_cache::*;
