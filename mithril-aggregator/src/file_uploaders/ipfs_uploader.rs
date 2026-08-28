use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use slog::{Logger, trace};

use mithril_common::StdResult;
use mithril_common::entities::FileUri;
use mithril_common::logging::LoggerExtensions;

use crate::FileUploader;
use crate::file_uploaders::FileUploadRetryPolicy;
use crate::file_uploaders::interface::retry;
use crate::tools::kubo_rpc_client::query::{
    IpfsAddQuery, IpfsFilesLsQuery, IpfsFilesMkdirQuery, IpfsFilesStatQuery,
};
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcClient};

/// IPFS Content Identifier (CID)
pub type Cid = String;

/// File uploader that stores files to IPFS
pub struct IpfsUploader {
    rpc_client: Arc<dyn IpfsBackendUploader>,
    ipfs_dir_path: IpfsMfsDirPath,
    retry_policy: FileUploadRetryPolicy,
    logger: Logger,
}

impl IpfsUploader {
    /// Create a new IPFS uploader
    pub fn new(
        rpc_client: Arc<dyn IpfsBackendUploader>,
        ipfs_dir_path: IpfsMfsDirPath,
        retry_policy: FileUploadRetryPolicy,
        logger: &Logger,
    ) -> Self {
        Self {
            rpc_client,
            ipfs_dir_path,
            retry_policy,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Upload a batch of files at once to the target IPFS MFS directory, returning the updated CID
    /// of the directory
    ///
    /// Compared to uploading the files one by one:
    /// - it checks if the target directory exists in IPFS only once
    /// - it batches the existence checks of the files by listing them using one `files ls` query
    pub async fn batch_upload_to_dir(&self, files: &[PathBuf]) -> StdResult<Cid> {
        self.ensure_directory_exists().await?;

        let existing_entries = self
            .rpc_client
            .list_directory_files(&self.ipfs_dir_path)
            .await
            .with_context(|| "listing files in IPFS MFS directory")?;

        for file_path in files {
            let filename =
                file_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .with_context(|| {
                        format!(
                            "File path '{}' has no valid UTF-8 filename",
                            file_path.display()
                        )
                    })?;

            if existing_entries.contains_key(filename) {
                continue;
            }

            // We are bypassing retry-capable [FileUploader::upload] to avoid already batched checks, so we need to retry manually
            retry(
                || async { self.upload_missing_file_once(file_path).await },
                self.retry_policy(),
                format!(" Uploaded file path: {}", file_path.display()),
            )
            .await?;
        }

        self.get_current_directory_cid().await
    }

    /// Get the current directory CID, reflecting the latest state of the directory
    pub async fn get_current_directory_cid(&self) -> StdResult<Cid> {
        self.rpc_client.get_dir_cid(&self.ipfs_dir_path).await
    }

    async fn ensure_directory_exists(&self) -> StdResult<()> {
        self.rpc_client
            .create_dir(&self.ipfs_dir_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to create directory '{}' in IPFS",
                    self.ipfs_dir_path
                )
            })
    }

    async fn upload_file_once(&self, filepath: &Path) -> StdResult<FileUri> {
        self.ensure_directory_exists().await?;

        if let Some(cid) = self
            .rpc_client
            .file_exists(&self.ipfs_dir_path, filepath)
            .await
            .with_context(|| {
                format!(
                    "Failed to check if file '{}' exists in IPFS",
                    filepath.display()
                )
            })?
        {
            trace!(self.logger, "File already exists in IPFS"; "cid" => %cid);
            return Ok(FileUri(cid));
        }

        self.upload_missing_file_once(filepath).await
    }

    // Note: this method assumes that the target directory exists and the file does not exist in IPFS
    async fn upload_missing_file_once(&self, filepath: &Path) -> StdResult<FileUri> {
        trace!(self.logger, "Uploading file to IPFS"; "file_path" => %filepath.display());

        let cid = self
            .rpc_client
            .upload_file(filepath, &self.ipfs_dir_path)
            .await
            .with_context(|| format!("Failed to upload file '{}' to IPFS", filepath.display()))?;
        trace!(
            self.logger, "File upload to IPFS finished";
            "file_path" => %filepath.display(), "cid" => %cid
        );

        Ok(FileUri(cid))
    }
}

#[async_trait::async_trait]
impl FileUploader for IpfsUploader {
    async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri> {
        self.upload_file_once(filepath).await
    }

    fn retry_policy(&self) -> FileUploadRetryPolicy {
        self.retry_policy.clone()
    }
}

/// Backend trait for IPFS operations
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait IpfsBackendUploader: Sync + Send {
    /// Create a directory in IPFS
    async fn create_dir(&self, dir_path: &IpfsMfsDirPath) -> StdResult<()>;

    /// List all paths in an MFS directory
    async fn list_directory_files(
        &self,
        dir_path: &IpfsMfsDirPath,
    ) -> StdResult<HashMap<String, Cid>>;

    /// Get the CID of a directory
    async fn get_dir_cid(&self, dir_path: &IpfsMfsDirPath) -> StdResult<Cid>;

    /// Upload a file to IPFS and return its CID
    async fn upload_file(&self, file_path: &Path, mfs_path: &IpfsMfsDirPath) -> StdResult<Cid>;

    /// Check if a file exists in a given MFS directory and return its CID if it does
    async fn file_exists(
        &self,
        mfs_dir_path: &IpfsMfsDirPath,
        file_path: &Path,
    ) -> StdResult<Option<Cid>>;
}

#[async_trait::async_trait]
impl IpfsBackendUploader for KuboRpcClient {
    async fn create_dir(&self, dir_path: &IpfsMfsDirPath) -> StdResult<()> {
        self.send(IpfsFilesMkdirQuery::create_mfs_directory(dir_path)).await
    }

    async fn list_directory_files(
        &self,
        dir_path: &IpfsMfsDirPath,
    ) -> StdResult<HashMap<String, Cid>> {
        self.send(IpfsFilesLsQuery::new(dir_path)).await
    }

    async fn get_dir_cid(&self, dir_path: &IpfsMfsDirPath) -> StdResult<Cid> {
        let stat = self
            .send(IpfsFilesStatQuery::new(dir_path.as_ref()))
            .await?
            .with_context(|| format!("Directory {dir_path} does not exist in IPFS node",))?;
        Ok(stat.hash)
    }

    async fn upload_file(&self, file_path: &Path, mfs_path: &IpfsMfsDirPath) -> StdResult<Cid> {
        let res = self
            .send(IpfsAddQuery::new_with_mfs_reference(file_path, mfs_path))
            .await?;
        Ok(res.hash)
    }

    async fn file_exists(
        &self,
        mfs_dir_path: &IpfsMfsDirPath,
        file_path: &Path,
    ) -> StdResult<Option<Cid>> {
        let stat = self
            .send(IpfsFilesStatQuery::new(
                mfs_dir_path.join_file_name_from(file_path)?,
            ))
            .await?;
        Ok(stat.map(|stat| stat.hash))
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use mithril_common::test::mock_extensions::MockBuilder;

    use crate::test::TestLogger;

    use super::*;

    impl IpfsUploader {
        fn new_for_test<P: Into<IpfsMfsDirPath>>(
            mfs_dir: P,
            mock_config: impl FnOnce(&mut MockIpfsBackendUploader),
        ) -> Self {
            Self::new(
                MockBuilder::configure(mock_config),
                mfs_dir.into(),
                FileUploadRetryPolicy::never(),
                &TestLogger::stdout(),
            )
        }
    }

    #[tokio::test]
    async fn existing_file_is_not_uploaded_and_its_cid_is_returned() {
        let uploader = IpfsUploader::new_for_test(IpfsMfsDirPath::from("/test/dir"), |mock| {
            mock.expect_create_dir().returning(|_| Ok(()));
            mock.expect_file_exists()
                .with(
                    eq(IpfsMfsDirPath::from("/test/dir")),
                    eq(Path::new("/a/dummy-file.txt")),
                )
                .returning(|_, _| Ok(Some("existing".to_string())));
            mock.expect_upload_file().never();
        });

        let result = uploader
            .upload_without_retry(Path::new("/a/dummy-file.txt"))
            .await
            .unwrap();

        assert_eq!(FileUri("existing".to_string()), result);
    }

    #[tokio::test]
    async fn non_existing_file_is_uploaded_and_its_cid_is_returned() {
        let uploader = IpfsUploader::new_for_test(IpfsMfsDirPath::from("/test/dir"), |mock| {
            mock.expect_create_dir()
                .with(eq(IpfsMfsDirPath::from("/test/dir")))
                .returning(|_| Ok(()));
            mock.expect_file_exists()
                .with(
                    eq(IpfsMfsDirPath::from("/test/dir")),
                    eq(Path::new("/a/dummy-file.txt")),
                )
                .returning(|_, _| Ok(None));
            mock.expect_upload_file()
                .with(
                    eq(Path::new("/a/dummy-file.txt")),
                    eq(IpfsMfsDirPath::from("/test/dir")),
                )
                .returning(|_, _| Ok("test_cid".to_string()));
        });

        uploader
            .upload_without_retry(Path::new("/a/dummy-file.txt"))
            .await
            .unwrap();
    }

    mod batch_upload {
        use std::time::Duration;

        use anyhow::anyhow;

        use super::*;

        const MFS_DIR: &str = "/test/dir";

        #[tokio::test]
        async fn uploads_only_missing_files_and_returns_directory_cid() {
            let existing_files = HashMap::from([(
                "already-uploaded.txt".to_string(),
                "existing-cid".to_string(),
            )]);

            let uploader = IpfsUploader::new_for_test(MFS_DIR, move |mock| {
                mock.expect_create_dir()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok(()))
                    .once();
                mock.expect_list_directory_files()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(move |_| Ok(existing_files))
                    .once();
                mock.expect_file_exists().never();
                mock.expect_upload_file()
                    .with(
                        eq(PathBuf::from("/local/new-file-1.txt")),
                        eq(IpfsMfsDirPath::from(MFS_DIR)),
                    )
                    .return_once(|_, _| Ok("file-1-cid".to_string()))
                    .once();
                mock.expect_upload_file()
                    .with(
                        eq(PathBuf::from("/other/new-file-2.txt")),
                        eq(IpfsMfsDirPath::from(MFS_DIR)),
                    )
                    .return_once(|_, _| Ok("file-2-cid".to_string()))
                    .once();
                mock.expect_get_dir_cid()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok("directory-cid".to_string()))
                    .once();
            });

            let directory_cid = uploader
                .batch_upload_to_dir(&[
                    PathBuf::from("/local/already-uploaded.txt"),
                    PathBuf::from("/local/new-file-1.txt"),
                    PathBuf::from("/other/new-file-2.txt"),
                ])
                .await
                .unwrap();

            assert_eq!("directory-cid", directory_cid);
        }

        #[tokio::test]
        async fn support_retry() {
            let mut uploader = IpfsUploader::new_for_test(MFS_DIR, move |mock| {
                mock.expect_create_dir()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok(()))
                    .once();
                mock.expect_list_directory_files()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(move |_| Ok(HashMap::new()))
                    .once();
                mock.expect_upload_file()
                    .with(
                        eq(PathBuf::from("/local/new-file.txt")),
                        eq(IpfsMfsDirPath::from(MFS_DIR)),
                    )
                    .return_once(|_, _| Err(anyhow!("first upload failed")))
                    .once();
                mock.expect_upload_file()
                    .with(
                        eq(PathBuf::from("/local/new-file.txt")),
                        eq(IpfsMfsDirPath::from(MFS_DIR)),
                    )
                    .return_once(|_, _| Ok("file-cid".to_string()))
                    .once();
                mock.expect_get_dir_cid()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok("directory-cid".to_string()))
                    .once();
            });
            uploader.retry_policy = FileUploadRetryPolicy {
                attempts: 2,
                delay_between_attempts: Duration::from_millis(5),
            };

            let directory_cid = uploader
                .batch_upload_to_dir(&[PathBuf::from("/local/new-file.txt")])
                .await
                .unwrap();

            assert_eq!("directory-cid", directory_cid);
        }

        #[tokio::test]
        async fn empty_batch_returns_current_directory_cid_without_uploading_files() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok(()))
                    .once();
                mock.expect_list_directory_files()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok(HashMap::new()))
                    .once();
                mock.expect_file_exists().never();
                mock.expect_upload_file().never();
                mock.expect_get_dir_cid()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Ok("directory-cid".to_string()))
                    .once();
            });

            let directory_cid = uploader.batch_upload_to_dir(&[]).await.unwrap();

            assert_eq!("directory-cid", directory_cid);
        }

        #[tokio::test]
        async fn returns_error_when_a_file_path_has_no_filename() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir().return_once(|_| Ok(())).once();
                mock.expect_list_directory_files()
                    .return_once(|_| Ok(HashMap::new()))
                    .once();
                mock.expect_file_exists().never();
                mock.expect_upload_file().never();
                mock.expect_get_dir_cid().never();
            });

            uploader
                .batch_upload_to_dir(&[PathBuf::new()])
                .await
                .expect_err("a path without a filename should fail");
        }

        #[tokio::test]
        async fn returns_error_when_directory_creation_fails() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Err(anyhow!("create directory failure")))
                    .once();
                mock.expect_list_directory_files().never();
                mock.expect_upload_file().never();
                mock.expect_get_dir_cid().never();
            });

            uploader
                .batch_upload_to_dir(&[PathBuf::from("new-file.txt")])
                .await
                .expect_err("directory creation failure should be returned");
        }

        #[tokio::test]
        async fn returns_error_when_listing_directory_files_fails() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir().return_once(|_| Ok(())).once();
                mock.expect_list_directory_files()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Err(anyhow!("list directory failure")))
                    .once();
                mock.expect_upload_file().never();
                mock.expect_get_dir_cid().never();
            });

            uploader
                .batch_upload_to_dir(&[PathBuf::from("new-file.txt")])
                .await
                .expect_err("directory listing failure should be returned");
        }

        #[tokio::test]
        async fn returns_error_when_uploading_a_missing_file_fails() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir().return_once(|_| Ok(())).once();
                mock.expect_list_directory_files()
                    .return_once(|_| Ok(HashMap::new()))
                    .once();
                mock.expect_file_exists().never();
                mock.expect_upload_file()
                    .with(
                        eq(PathBuf::from("/local/new-file.txt")),
                        eq(IpfsMfsDirPath::from(MFS_DIR)),
                    )
                    .return_once(|_, _| Err(anyhow!("upload failure")))
                    .once();
                mock.expect_get_dir_cid().never();
            });

            uploader
                .batch_upload_to_dir(&[PathBuf::from("/local/new-file.txt")])
                .await
                .expect_err("file upload failure should be returned");
        }

        #[tokio::test]
        async fn returns_error_when_retrieving_directory_cid_fails() {
            let uploader = IpfsUploader::new_for_test(MFS_DIR, |mock| {
                mock.expect_create_dir().return_once(|_| Ok(())).once();
                mock.expect_list_directory_files()
                    .return_once(|_| Ok(HashMap::new()))
                    .once();
                mock.expect_upload_file().never();
                mock.expect_get_dir_cid()
                    .with(eq(IpfsMfsDirPath::from(MFS_DIR)))
                    .return_once(|_| Err(anyhow!("get directory CID failure")))
                    .once();
            });

            uploader
                .batch_upload_to_dir(&[])
                .await
                .expect_err("directory CID retrieval failure should be returned");
        }
    }
}
