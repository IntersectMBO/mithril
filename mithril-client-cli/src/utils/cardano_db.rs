use anyhow::anyhow;
use futures::Future;
use indicatif::{MultiProgress, ProgressBar};
use std::path::Path;
use std::time::Duration;

use super::CardanoDbDownloadCheckerError;
use mithril_client::{MithrilError, MithrilResult};

/// Utility functions for to the CardanoDb commands
pub struct CardanoDbUtils;

/// Known formats of a ledger state snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerFormat {
    /// Legacy in-memory format (maximum supported by cardano-node `10.3.0`)
    Legacy,
    /// UTxO-HD in-memory format (since cardano-node `10.4.1`)
    InMemory,
    /// UTxO-HD LMDB format (since cardano-node `10.4.1`)
    Lmdb,
    /// UTxO-HD LSM format (since cardano-node `10.7.1`)
    Lsm,
}

impl CardanoDbUtils {
    /// Maximum length of a network code or a node version in the node start command
    const NODE_START_COMMAND_VALUE_MAX_LENGTH: usize = 32;

    /// Handle the error return by `check_prerequisites`
    pub fn check_disk_space_error(error: MithrilError) -> MithrilResult<String> {
        match error.downcast_ref::<CardanoDbDownloadCheckerError>() {
            Some(CardanoDbDownloadCheckerError::NotEnoughSpaceForUncompressedData { .. }) => {
                Ok(format!("Warning: {error}"))
            }
            _ => Err(error),
        }
    }

    /// Display a spinner while waiting for the result of a future
    pub async fn wait_spinner<T, E>(
        progress_bar: &MultiProgress,
        future: impl Future<Output = Result<T, E>>,
    ) -> MithrilResult<T>
    where
        MithrilError: From<E>,
    {
        let pb = progress_bar.add(ProgressBar::new_spinner());
        let spinner = async move {
            loop {
                pb.tick();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };

        tokio::select! {
            _ = spinner => Err(anyhow!("timeout")),
            res = future => res.map_err(Into::into),
        }
    }

    pub fn format_bytes_to_gigabytes(bytes: u64) -> String {
        let size_in_giga = bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        format!("{size_in_giga:.2} GiB")
    }

    /// Returns the docker run command to run cardano-node with the given ledger format.
    ///
    /// If the ledger format is [legacy](LedgerFormat::Legacy), the cardano node version will
    /// be forced to `10.3.1`.
    pub fn get_docker_run_command<P: AsRef<Path>>(
        canonical_db_filepath: P,
        cardano_network: &str,
        cardano_node_version: &str,
        ledger_format: LedgerFormat,
    ) -> MithrilResult<String> {
        Self::check_node_start_command_values(cardano_network, cardano_node_version)?;

        let db_path = canonical_db_filepath.as_ref();
        let cardano_node_version = if matches!(ledger_format, LedgerFormat::Legacy) {
            "10.3.1"
        } else {
            cardano_node_version
        };
        let cardano_node_config = match ledger_format {
            LedgerFormat::Lmdb => {
                r#" -e CARDANO_CONFIG_JSON_MERGE='{"LedgerDB": { "Backend": "V1LMDB" }}'"#
            }
            LedgerFormat::Lsm => {
                r#" -e CARDANO_CONFIG_JSON_MERGE='{"LedgerDB": { "Backend": "V2LSM" }}'"#
            }
            _ => "",
        };

        let security_opt = if matches!(ledger_format, LedgerFormat::Lsm) {
            // The LSM backend requires `seccomp=unconfined` to work properly, as it uses io_uring syscalls which is blocked by default in Docker.
            " --security-opt seccomp=unconfined"
        } else {
            ""
        };

        Ok(format!(
            "docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source=\"{db_path}\",target=/data/db/ -e NETWORK={cardano_network}{cardano_node_config}{security_opt} ghcr.io/intersectmbo/cardano-node:{cardano_node_version}",
            db_path = db_path.display(),
        ))
    }

    /// Check that the network and the node version can be used to build the node start command
    pub fn check_node_start_command_values(
        cardano_network: &str,
        cardano_node_version: &str,
    ) -> MithrilResult<()> {
        if !Self::is_safe_node_start_command_value(cardano_network) {
            return Err(anyhow!(
                "Refusing to build the node start command for an invalid network '{cardano_network}'"
            ));
        }
        if !Self::is_safe_node_start_command_value(cardano_node_version) {
            return Err(anyhow!(
                "Refusing to build the node start command for an invalid node version '{cardano_node_version}'"
            ));
        }

        Ok(())
    }

    /// Check that a value is a non empty and bounded string of lowercase letters, digits, dots and hyphens
    fn is_safe_node_start_command_value(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= Self::NODE_START_COMMAND_VALUE_MAX_LENGTH
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn check_disk_space_error_should_return_warning_message_if_error_is_not_enough_space_for_uncompressed_data()
     {
        let not_enough_space_error =
            CardanoDbDownloadCheckerError::NotEnoughSpaceForUncompressedData {
                left_space: 1_f64,
                pathdir: PathBuf::new(),
                db_size: 2_f64,
            };
        let expected = format!("Warning: {not_enough_space_error}");

        let result = CardanoDbUtils::check_disk_space_error(anyhow!(not_enough_space_error))
            .expect("check_disk_space_error should not error");

        assert!(result.contains(&expected));
    }

    #[test]
    fn check_disk_space_error_should_return_error_if_error_is_not_error_not_enough_space() {
        let error = CardanoDbDownloadCheckerError::UnpackDirectoryNotEmpty(PathBuf::new());

        let error = CardanoDbUtils::check_disk_space_error(anyhow!(error))
            .expect_err("check_disk_space_error should fail");

        assert!(
            matches!(
                error.downcast_ref::<CardanoDbDownloadCheckerError>(),
                Some(CardanoDbDownloadCheckerError::UnpackDirectoryNotEmpty(_))
            ),
            "Unexpected error: {error:?}"
        );
    }

    #[test]
    fn format_bytes_to_gigabytes_zero() {
        let one_gigabyte = 1024 * 1024 * 1024;

        assert_eq!(CardanoDbUtils::format_bytes_to_gigabytes(0), "0.00 GiB");

        assert_eq!(
            CardanoDbUtils::format_bytes_to_gigabytes(one_gigabyte),
            "1.00 GiB"
        );

        assert_eq!(
            CardanoDbUtils::format_bytes_to_gigabytes(one_gigabyte / 2),
            "0.50 GiB"
        );

        assert_eq!(
            CardanoDbUtils::format_bytes_to_gigabytes(one_gigabyte * 10),
            "10.00 GiB"
        );
    }

    #[test]
    fn get_docker_run_command_for_legacy_ledger() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "whatever",
            LedgerFormat::Legacy,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=mainnet ghcr.io/intersectmbo/cardano-node:10.3.1"#
        )
    }

    #[test]
    fn get_docker_run_command_for_in_memory_ledger() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=mainnet ghcr.io/intersectmbo/cardano-node:10.5.4"#
        )
    }

    #[test]
    fn get_docker_run_command_for_lmdb_ledger() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "10.6.2",
            LedgerFormat::Lmdb,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=mainnet -e CARDANO_CONFIG_JSON_MERGE='{"LedgerDB": { "Backend": "V1LMDB" }}' ghcr.io/intersectmbo/cardano-node:10.6.2"#
        )
    }

    #[test]
    fn get_docker_run_command_for_lsm_ledger() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "10.7.1",
            LedgerFormat::Lsm,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=mainnet -e CARDANO_CONFIG_JSON_MERGE='{"LedgerDB": { "Backend": "V2LSM" }}' --security-opt seccomp=unconfined ghcr.io/intersectmbo/cardano-node:10.7.1"#
        )
    }

    #[test]
    fn get_docker_run_command_for_private_network() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "private",
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=private ghcr.io/intersectmbo/cardano-node:10.5.4"#
        )
    }

    #[test]
    fn get_docker_run_command_for_latest_node_version() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "latest",
            LedgerFormat::Lsm,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=mainnet -e CARDANO_CONFIG_JSON_MERGE='{"LedgerDB": { "Backend": "V2LSM" }}' --security-opt seccomp=unconfined ghcr.io/intersectmbo/cardano-node:latest"#
        )
    }

    #[test]
    fn get_docker_run_command_for_pre_release_node_version() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "preview",
            "pre-release",
            LedgerFormat::InMemory,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=preview ghcr.io/intersectmbo/cardano-node:pre-release"#
        )
    }

    #[test]
    fn get_docker_run_command_for_network_and_node_version_unknown_to_the_client() {
        let run_command = CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "sanchonet",
            "10.6.0-pre",
            LedgerFormat::InMemory,
        )
        .unwrap();

        assert_eq!(
            run_command,
            r#"docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/path/to/db",target=/data/db/ -e NETWORK=sanchonet ghcr.io/intersectmbo/cardano-node:10.6.0-pre"#
        )
    }

    #[test]
    fn get_docker_run_command_accepts_values_of_maximum_length() {
        let value = "a".repeat(CardanoDbUtils::NODE_START_COMMAND_VALUE_MAX_LENGTH);

        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            &value,
            &value,
            LedgerFormat::InMemory,
        )
        .expect("values of maximum length must be accepted");
    }

    #[test]
    fn get_docker_run_command_rejects_network_with_forbidden_character() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet|whatever",
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .expect_err("a network with a forbidden character must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_network_not_in_lowercase() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "MAINNET",
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .expect_err("a network not in lowercase must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_empty_network() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "",
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .expect_err("an empty network must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_network_longer_than_maximum_length() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            &"a".repeat(CardanoDbUtils::NODE_START_COMMAND_VALUE_MAX_LENGTH + 1),
            "10.5.4",
            LedgerFormat::InMemory,
        )
        .expect_err("a network longer than the maximum length must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_node_version_with_forbidden_character() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "10.5.4; whatever",
            LedgerFormat::InMemory,
        )
        .expect_err("a node version with a forbidden character must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_node_version_longer_than_maximum_length() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            &"1".repeat(CardanoDbUtils::NODE_START_COMMAND_VALUE_MAX_LENGTH + 1),
            LedgerFormat::InMemory,
        )
        .expect_err("a node version longer than the maximum length must be rejected");
    }

    #[test]
    fn get_docker_run_command_rejects_invalid_node_version_for_legacy_ledger() {
        CardanoDbUtils::get_docker_run_command(
            Path::new("/path/to/db"),
            "mainnet",
            "10.5.4; whatever",
            LedgerFormat::Legacy,
        )
        .expect_err("an invalid node version must be rejected even when it is overridden");
    }

    #[test]
    fn check_node_start_command_values_accepts_valid_network_and_node_version() {
        CardanoDbUtils::check_node_start_command_values("mainnet", "10.5.4")
            .expect("a valid network and node version must be accepted");
    }

    #[test]
    fn check_node_start_command_values_rejects_invalid_network() {
        let error = CardanoDbUtils::check_node_start_command_values("mainnet|whatever", "10.5.4")
            .expect_err("an invalid network must be rejected");

        assert!(
            error.to_string().contains("invalid network 'mainnet|whatever'"),
            "Unexpected error: {error:?}"
        );
    }

    #[test]
    fn check_node_start_command_values_rejects_invalid_node_version() {
        let error = CardanoDbUtils::check_node_start_command_values("mainnet", "10.5.4; whatever")
            .expect_err("an invalid node version must be rejected");

        assert!(
            error.to_string().contains("invalid node version '10.5.4; whatever'"),
            "Unexpected error: {error:?}"
        );
    }
}
