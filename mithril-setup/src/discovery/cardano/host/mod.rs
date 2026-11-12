//! Probes observing the Linux host the setup runs on

mod cgroup;
mod procfs;
mod tools;

pub use cgroup::*;
pub use procfs::*;
pub use tools::*;

/// Fixtures for the host probe tests, which run against fake `/proc` trees and search paths
#[cfg(test)]
pub(crate) mod test_tools {
    use std::path::{Path, PathBuf};

    /// Create an empty directory dedicated to a test, removing any leftover of a previous run
    pub fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("mithril-setup-tests").join(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write a file, creating its parent directories
    pub fn write_file(path: &Path, content: impl AsRef<[u8]>) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Write an empty file with the execute permissions, creating its parent directories
    ///
    /// The file is not meant to be run: running a file written by the test process could fail
    /// with `ETXTBSY` when a process forked concurrently by another test inherits its descriptor.
    pub fn write_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        write_file(path, "");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
