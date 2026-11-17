//! Reads the files of the Cardano node from the host filesystem

use std::path::Path;

use anyhow::Context;
use async_trait::async_trait;
use tokio::fs;

use crate::discovery::cardano::FileProbe;

/// Reads the files of the Cardano node from the host filesystem
#[derive(Default)]
pub struct HostFileProbe;

#[async_trait]
impl FileProbe for HostFileProbe {
    async fn read_to_string(&self, path: &Path) -> anyhow::Result<String> {
        fs::read_to_string(path)
            .await
            .with_context(|| format!("Could not read the file '{}'", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use crate::discovery::cardano::host::test_tools::{test_dir, write_file};

    use super::*;

    #[tokio::test]
    async fn reads_the_content_of_an_existing_file() {
        let path = test_dir("files_reads_an_existing_file").join("configuration.yml");
        write_file(&path, "Protocol: Cardano");

        let content = HostFileProbe.read_to_string(&path).await.unwrap();

        assert_eq!("Protocol: Cardano", content);
    }

    #[tokio::test]
    async fn fails_on_a_missing_file_naming_its_path() {
        let path = test_dir("files_fails_on_a_missing_file").join("configuration.yml");

        let error = HostFileProbe.read_to_string(&path).await.unwrap_err();

        assert!(
            format!("{error:#}").contains(&path.display().to_string()),
            "Expected the error to name the path, got: {error:#}"
        );
    }
}
