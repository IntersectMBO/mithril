mod circuit_breaker;
mod immutable_trio;
mod staging_dir;
mod task;

pub(super) use circuit_breaker::*;
pub(super) use staging_dir::*;
pub(super) use task::*;

#[cfg(test)]
mod test_utils {
    use std::path::Path;

    use mithril_cardano_node_internal_database::IMMUTABLE_DIR;

    /// The names of the immutable trio of the immutable file number 1
    pub const FULL_TRIO: [&str; 3] = ["00001.chunk", "00001.primary", "00001.secondary"];

    /// Create the given files in the immutable directory of the given directory, creating both
    /// directories when they do not exist.
    pub fn create_immutable_trio(dir: &Path, names: &[&str]) {
        let immutable_dir = dir.join(IMMUTABLE_DIR);
        std::fs::create_dir_all(&immutable_dir).unwrap();
        for name in names {
            std::fs::File::create(immutable_dir.join(name)).unwrap();
        }
    }

    /// Create an empty file in the given directory, creating the directory when it does not exist.
    pub fn create_file(parent_dir: &Path, name: &str) {
        std::fs::create_dir_all(parent_dir).unwrap();
        std::fs::File::create(parent_dir.join(name)).unwrap();
    }
}
