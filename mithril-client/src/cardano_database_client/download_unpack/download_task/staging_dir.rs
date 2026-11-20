use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context;
use slog::Logger;
use uuid::Uuid;

use mithril_common::entities::ImmutableFileNumber;

use crate::MithrilResult;

/// A directory where one download is unpacked, removed when dropped so that a cancelled or failed
/// download leaves nothing behind.
pub struct StagingDirectory {
    /// Path of the directory
    path: PathBuf,
    /// Logger used to report a failed removal
    logger: Logger,
    /// Set once the asynchronous removal ran, so that the drop does not remove the directory again
    removed: bool,
}

impl StagingDirectory {
    /// Prefix of the name of the staging directory of an immutable archive
    const IMMUTABLE_STAGING_DIRECTORY_PREFIX: &str = "immutable-";

    /// Prefix of the name of the staging directory of the ancillary archive
    const ANCILLARY_STAGING_DIRECTORY_PREFIX: &str = "ancillary-";

    /// Run an operation in a new staging directory.
    ///
    /// The directory is removed once the operation completes, whatever its result, and when the
    /// operation panics or is cancelled.
    pub async fn run_in<T>(
        path: PathBuf,
        logger: &Logger,
        operation: impl AsyncFnOnce(&StagingDirectory) -> MithrilResult<T>,
    ) -> MithrilResult<T> {
        let staging_directory = Self::create(path, logger)?;
        let result = operation(&staging_directory).await;
        staging_directory.remove().await;

        result
    }

    /// Create the directory synchronously so that no cancellation point exists between its
    /// creation and the guard that removes it.
    fn create(path: PathBuf, logger: &Logger) -> MithrilResult<Self> {
        std::fs::create_dir(&path).with_context(|| {
            format!(
                "can not create download staging directory '{}'",
                path.display()
            )
        })?;

        Ok(Self {
            path,
            logger: logger.clone(),
            removed: false,
        })
    }

    /// Path of the staging directory
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory without blocking the runtime, in one attempt: the sweep of the download
    /// is the backstop. The synchronous removal of the drop is kept for a cancellation.
    async fn remove(mut self) {
        if let Err(error) = tokio::fs::remove_dir_all(&self.path).await
            && error.kind() != io::ErrorKind::NotFound
        {
            slog::warn!(
                self.logger, "Failed to remove download staging directory '{}'", self.path.display();
                "error" => ?error
            );
        }
        self.removed = true;
    }

    /// Remove the content left by a previous location attempt, keeping the directory itself so that
    /// nothing has to recreate it after a cancellation.
    pub async fn reset(&self) -> MithrilResult<()> {
        let mut entries = tokio::fs::read_dir(&self.path).await.with_context(|| {
            format!(
                "can not read download staging directory '{}'",
                self.path.display()
            )
        })?;
        while let Some(entry) = entries.next_entry().await.with_context(|| {
            format!(
                "can not read an entry of download staging directory '{}'",
                self.path.display()
            )
        })? {
            let entry_path = entry.path();
            let entry_type = entry.file_type().await.with_context(|| {
                format!(
                    "can not read the type of '{}' in the download staging directory",
                    entry_path.display()
                )
            })?;
            let removed = if entry_type.is_dir() {
                tokio::fs::remove_dir_all(&entry_path).await
            } else {
                tokio::fs::remove_file(&entry_path).await
            };
            removed.with_context(|| {
                format!(
                    "can not remove '{}' from the download staging directory",
                    entry_path.display()
                )
            })?;
        }

        Ok(())
    }

    /// The staging directory of an immutable archive, a sibling of the immutable directory under
    /// the target directory so that the promoted files are renamed on the same filesystem.
    pub fn immutable_staging_directory_path(
        target_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
        download_id: &str,
    ) -> PathBuf {
        target_dir.join(format!(
            "{}{immutable_file_number:05}-{download_id}",
            Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX
        ))
    }

    /// The staging directory of the ancillary archive, a sibling of its final location under the
    /// target directory.
    pub fn ancillary_staging_directory_path(target_dir: &Path, download_id: &str) -> PathBuf {
        target_dir.join(format!(
            "{}{download_id}",
            Self::ANCILLARY_STAGING_DIRECTORY_PREFIX
        ))
    }

    /// Tell if a name is the one of a staging directory of the given download.
    pub fn is_staging_directory_name(name: &str, download_id: &str) -> bool {
        name.ends_with(&format!("-{download_id}"))
            && (name.starts_with(Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX)
                || name.starts_with(Self::ANCILLARY_STAGING_DIRECTORY_PREFIX))
    }

    /// Tell if a name is the one of a staging directory, whatever the download it belongs to.
    pub fn is_staging_directory_name_of_any_download(name: &str) -> bool {
        let download_id = match name.strip_prefix(Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX) {
            Some(immutable_suffix) => {
                immutable_suffix
                    .split_once('-')
                    .and_then(|(file_number, download_id)| {
                        let is_file_number = !file_number.is_empty()
                            && file_number.chars().all(|character| character.is_ascii_digit());
                        is_file_number.then_some(download_id)
                    })
            }
            None => name.strip_prefix(Self::ANCILLARY_STAGING_DIRECTORY_PREFIX),
        };

        download_id.is_some_and(|download_id| Uuid::parse_str(download_id).is_ok())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if !self.removed
            && let Err(error) = std::fs::remove_dir_all(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            slog::warn!(
                self.logger, "Failed to remove download staging directory '{}'", self.path.display();
                "error" => ?error
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use crate::test_utils::TestLogger;

    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn removing_the_staging_directory_warns_once_when_the_removal_fails() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = temp_dir_create!();
        let (logger, log_inspector) = TestLogger::memory();
        let staging_directory =
            StagingDirectory::create(temp_dir.join("staging"), &logger).unwrap();
        let locked_dir = staging_directory.path().join("locked");
        std::fs::create_dir(&locked_dir).unwrap();
        std::fs::File::create(locked_dir.join("file")).unwrap();
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        staging_directory.remove().await;

        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            1,
            log_inspector
                .search_logs("Failed to remove download staging directory")
                .len(),
            "one asynchronous removal attempt must warn once"
        );
    }

    mod run_in {
        use std::future::pending;

        use anyhow::anyhow;

        use super::*;

        const MAX_YIELDS_WAITING_FOR_A_PATH: usize = 1_000_000;

        async fn wait_until_exists(path: &Path) {
            for _ in 0..MAX_YIELDS_WAITING_FOR_A_PATH {
                if path.exists() {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("'{}' was never created", path.display());
        }

        #[tokio::test]
        async fn runs_the_operation_in_the_created_staging_directory() {
            let staging_path = temp_dir_create!().join("staging");

            let operation_path = StagingDirectory::run_in(
                staging_path.clone(),
                &TestLogger::stdout(),
                async |staging_directory| {
                    assert!(staging_directory.path().is_dir());
                    Ok(staging_directory.path().to_path_buf())
                },
            )
            .await
            .unwrap();

            assert_eq!(staging_path, operation_path);
        }

        #[tokio::test]
        async fn returns_the_error_of_the_operation() {
            let staging_path = temp_dir_create!().join("staging");

            let error = StagingDirectory::run_in(
                staging_path,
                &TestLogger::stdout(),
                async |_| -> MithrilResult<()> { Err(anyhow!("operation failure")) },
            )
            .await
            .expect_err("the error of the operation must be returned");

            assert_eq!("operation failure", error.to_string());
        }

        #[tokio::test]
        async fn removes_the_staging_directory_once_the_operation_succeeds() {
            let staging_path = temp_dir_create!().join("staging");

            StagingDirectory::run_in(
                staging_path.clone(),
                &TestLogger::stdout(),
                async |_| Ok(()),
            )
            .await
            .unwrap();

            assert!(!staging_path.exists());
        }

        #[tokio::test]
        async fn removes_the_staging_directory_once_the_operation_fails() {
            let staging_path = temp_dir_create!().join("staging");

            StagingDirectory::run_in(
                staging_path.clone(),
                &TestLogger::stdout(),
                async |_| -> MithrilResult<()> { Err(anyhow!("operation failure")) },
            )
            .await
            .expect_err("the operation fails");

            assert!(!staging_path.exists());
        }

        #[tokio::test]
        async fn removes_the_staging_directory_when_the_operation_is_cancelled() {
            let staging_path = temp_dir_create!().join("staging");
            let operation_staging_path = staging_path.clone();
            let handle = tokio::spawn(async move {
                StagingDirectory::run_in(
                    operation_staging_path,
                    &TestLogger::stdout(),
                    async |_| pending::<MithrilResult<()>>().await,
                )
                .await
            });
            wait_until_exists(&staging_path).await;

            handle.abort();
            handle.await.expect_err("the operation is cancelled");

            assert!(!staging_path.exists());
        }

        #[tokio::test]
        async fn removes_the_staging_directory_when_the_operation_panics() {
            let staging_path = temp_dir_create!().join("staging");
            let operation_staging_path = staging_path.clone();

            let join_error = tokio::spawn(async move {
                StagingDirectory::run_in(
                    operation_staging_path,
                    &TestLogger::stdout(),
                    async |_| -> MithrilResult<()> { panic!("the operation panics") },
                )
                .await
            })
            .await
            .expect_err("the operation panics");

            assert!(join_error.is_panic());
            assert!(!staging_path.exists());
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn removing_the_staging_directory_does_not_follow_its_symlinks() {
            let temp_dir = temp_dir_create!();
            let outside_file = temp_dir.join("outside_file");
            std::fs::File::create(&outside_file).unwrap();

            StagingDirectory::run_in(
                temp_dir.join("staging"),
                &TestLogger::stdout(),
                async |staging_directory| {
                    std::os::unix::fs::symlink(
                        &outside_file,
                        staging_directory.path().join("link"),
                    )
                    .unwrap();
                    Ok(())
                },
            )
            .await
            .unwrap();

            assert!(
                outside_file.exists(),
                "the target of a symlink of the staging directory must be kept"
            );
        }

        #[tokio::test]
        async fn fails_without_running_the_operation_when_the_staging_directory_can_not_be_created()
        {
            let staging_path = temp_dir_create!().join("staging");
            std::fs::create_dir(&staging_path).unwrap();

            StagingDirectory::run_in(
                staging_path,
                &TestLogger::stdout(),
                async |_| -> MithrilResult<()> { panic!("the operation must not run") },
            )
            .await
            .expect_err("an existing directory can not be created again");
        }
    }

    mod staging_directory_name {
        use mithril_cardano_node_internal_database::IMMUTABLE_DIR;

        use super::*;

        const DOWNLOAD_ID: &str = "0c8d8ea5-7b0c-4d7d-9d7f-5a4a3b1f2e10";

        #[test]
        fn an_immutable_staging_directory_name_is_recognized() {
            assert!(StagingDirectory::is_staging_directory_name_of_any_download(
                &format!("immutable-00001-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_immutable_staging_directory_name_with_a_long_file_number_is_recognized() {
            assert!(StagingDirectory::is_staging_directory_name_of_any_download(
                &format!("immutable-123456-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_ancillary_staging_directory_name_is_recognized() {
            assert!(StagingDirectory::is_staging_directory_name_of_any_download(
                &format!("ancillary-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn the_immutable_directory_name_is_not_a_staging_directory_name() {
            assert!(!StagingDirectory::is_staging_directory_name_of_any_download(IMMUTABLE_DIR));
        }

        #[test]
        fn an_immutable_name_without_a_download_id_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download("immutable-00001")
            );
        }

        #[test]
        fn an_immutable_name_with_an_invalid_download_id_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download(
                    "immutable-00001-notes"
                )
            );
        }

        #[test]
        fn an_immutable_name_with_an_invalid_file_number_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download(&format!(
                    "immutable-notes-{DOWNLOAD_ID}"
                ))
            );
        }

        #[test]
        fn an_immutable_name_without_a_file_number_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download(&format!(
                    "immutable--{DOWNLOAD_ID}"
                ))
            );
        }

        #[test]
        fn an_ancillary_name_with_an_invalid_download_id_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download("ancillary-notes")
            );
        }

        #[test]
        fn a_name_with_another_prefix_is_not_a_staging_directory_name() {
            assert!(
                !StagingDirectory::is_staging_directory_name_of_any_download(&format!(
                    "notes-{DOWNLOAD_ID}"
                ))
            );
        }
    }
}
