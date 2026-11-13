//! Inspects the Cardano binaries installed on the host

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use tokio::fs;
use tokio::process::Command;

use crate::discovery::cardano::{ProcessOwner, ToolProbe};

/// Runs the node binary and looks for `cardano-cli` beside it, then in the search path
pub struct HostToolProbe {
    search_path: Vec<PathBuf>,
}

impl HostToolProbe {
    /// Create a probe looking for the binaries in the given directories
    pub fn new(search_path: Vec<PathBuf>) -> Self {
        Self { search_path }
    }

    /// Create a probe looking for the binaries in the directories of the `PATH` environment variable
    pub fn from_env() -> Self {
        let search_path = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();

        Self::new(search_path)
    }
}

#[async_trait]
impl ToolProbe for HostToolProbe {
    async fn node_version_output(
        &self,
        node_executable: &Path,
        run_as: ProcessOwner,
    ) -> anyhow::Result<String> {
        // Dropping to the node identity also clears the supplementary groups when the setup
        // runs as root, so that the node binary can't do more than the node itself
        let output = Command::new(node_executable)
            .arg("--version")
            .uid(run_as.uid)
            .gid(run_as.gid)
            .output()
            .await
            .with_context(|| format!("Could not run '{} --version'", node_executable.display()))?;

        if !output.status.success() {
            return Err(anyhow!(
                "'{} --version' failed with {}: {}",
                node_executable.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn find_cardano_cli(
        &self,
        node_executable: Option<&Path>,
    ) -> anyhow::Result<Option<PathBuf>> {
        let candidates = node_executable
            .and_then(Path::parent)
            .into_iter()
            .chain(self.search_path.iter().map(PathBuf::as_path))
            .map(|dir| dir.join(CARDANO_CLI));

        for candidate in candidates {
            if is_executable_file(&candidate).await {
                return Ok(Some(candidate));
            }
        }

        Ok(None)
    }
}

const CARDANO_CLI: &str = "cardano-cli";

async fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .await
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use crate::discovery::cardano::host::test_tools::{test_dir, write_executable, write_file};

    use super::*;

    // System binaries stand for the node: running a script written by the test could fail with
    // `ETXTBSY` when a process forked concurrently by another test inherits its write descriptor
    mod node_version_output {
        use std::os::unix::fs::MetadataExt;

        use super::*;

        /// Identity of the test process: switching to it is allowed without privileges
        fn current_owner() -> ProcessOwner {
            let metadata = std::fs::metadata("/proc/self").unwrap();
            ProcessOwner {
                uid: metadata.uid(),
                gid: metadata.gid(),
            }
        }

        #[tokio::test]
        async fn succeeds_when_the_version_command_succeeds() {
            // The output of `true --version` depends on the platform (GNU coreutils, BusyBox, …)
            let result = HostToolProbe::new(vec![])
                .node_version_output(Path::new("true"), current_owner())
                .await;

            assert!(result.is_ok(), "Expected Ok, got {result:?}");
        }

        #[tokio::test]
        async fn fails_when_the_version_command_fails() {
            let result = HostToolProbe::new(vec![])
                .node_version_output(Path::new("false"), current_owner())
                .await;

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[tokio::test]
        async fn fails_when_the_executable_does_not_exist() {
            let result = HostToolProbe::new(vec![])
                .node_version_output(
                    Path::new("/this/does/not/exist/cardano-node"),
                    current_owner(),
                )
                .await;

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }

        #[tokio::test]
        async fn fails_when_the_identity_of_the_node_can_not_be_taken() {
            let mut owner = current_owner();
            if owner.uid == 0 {
                // Root can take any identity
                return;
            }
            owner.uid = 0;

            let result = HostToolProbe::new(vec![])
                .node_version_output(Path::new("true"), owner)
                .await;

            assert!(result.is_err(), "Expected Err, got {result:?}");
        }
    }

    mod find_cardano_cli {
        use super::*;

        #[tokio::test]
        async fn finds_the_cli_beside_the_node_executable_first() {
            let dir = test_dir("tools_finds_the_cli_beside_the_node");
            write_executable(&dir.join("node/cardano-cli"));
            write_executable(&dir.join("path/cardano-cli"));

            let cli = HostToolProbe::new(vec![dir.join("path")])
                .find_cardano_cli(Some(&dir.join("node/cardano-node")))
                .await
                .unwrap();

            assert_eq!(Some(dir.join("node/cardano-cli")), cli);
        }

        #[tokio::test]
        async fn finds_the_cli_in_the_search_path() {
            let dir = test_dir("tools_finds_the_cli_in_the_search_path");
            write_executable(&dir.join("path2/cardano-cli"));

            let cli = HostToolProbe::new(vec![dir.join("path1"), dir.join("path2")])
                .find_cardano_cli(Some(&dir.join("node/cardano-node")))
                .await
                .unwrap();

            assert_eq!(Some(dir.join("path2/cardano-cli")), cli);
        }

        #[tokio::test]
        async fn finds_the_cli_in_the_search_path_when_the_node_executable_is_unknown() {
            let dir = test_dir("tools_finds_the_cli_without_node_executable");
            write_executable(&dir.join("path/cardano-cli"));

            let cli = HostToolProbe::new(vec![dir.join("path")])
                .find_cardano_cli(None)
                .await
                .unwrap();

            assert_eq!(Some(dir.join("path/cardano-cli")), cli);
        }

        #[tokio::test]
        async fn ignores_a_cli_that_is_not_executable() {
            let dir = test_dir("tools_ignores_a_non_executable_cli");
            write_file(&dir.join("node/cardano-cli"), "");

            let cli = HostToolProbe::new(vec![])
                .find_cardano_cli(Some(&dir.join("node/cardano-node")))
                .await
                .unwrap();

            assert_eq!(None, cli);
        }

        #[tokio::test]
        async fn finds_no_cli_when_not_installed() {
            let dir = test_dir("tools_finds_no_cli");

            let cli = HostToolProbe::new(vec![dir.join("path")])
                .find_cardano_cli(Some(&dir.join("node/cardano-node")))
                .await
                .unwrap();

            assert_eq!(None, cli);
        }
    }
}
