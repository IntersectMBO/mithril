use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use slog::{Logger, trace};
use tokio::sync::OnceCell;

use mithril_common::StdResult;
use mithril_common::entities::FileUri;
use mithril_common::logging::LoggerExtensions;

use crate::FileUploader;
use crate::tools::kubo_rpc_client::query::{IpfsAddQuery, IpfsFilesMkdirQuery, IpfsFilesStatQuery};
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcClient};

/// IPFS Content Identifier (CID)
pub type Cid = String;

/// File uploader that stores files to IPFS
pub struct IpfsUploader {
    rpc_client: Arc<dyn IpfsBackendUploader>,
    ipfs_dir_path: IpfsMfsDirPath,
    directory_created: OnceCell<()>,
    logger: Logger,
}

impl IpfsUploader {
    /// Create a new IPFS uploader
    pub fn new(
        rpc_client: Arc<dyn IpfsBackendUploader>,
        ipfs_dir_path: IpfsMfsDirPath,
        logger: &Logger,
    ) -> Self {
        Self {
            rpc_client,
            ipfs_dir_path,
            directory_created: OnceCell::new(),
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn ensure_directory_exists(&self) -> StdResult<()> {
        self.directory_created
            .get_or_try_init(|| async {
                self.rpc_client
                    .create_dir(&self.ipfs_dir_path)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to create directory '{}' in IPFS",
                            self.ipfs_dir_path
                        )
                    })
            })
            .await?;
        Ok(())
    }

    /// Get the current directory CID, reflecting the latest state of the directory
    pub async fn get_current_directory_cid(&self) -> StdResult<Cid> {
        self.rpc_client.get_dir_cid(&self.ipfs_dir_path).await
    }
}

#[async_trait::async_trait]
impl FileUploader for IpfsUploader {
    async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri> {
        trace!(self.logger, "Uploading file to IPFS"; "file_path" => %filepath.display());
        self.ensure_directory_exists().await?;

        match self
            .rpc_client
            .file_exists(&self.ipfs_dir_path, filepath)
            .await
            .with_context(|| {
                format!(
                    "Failed to check if file '{}' exists in IPFS",
                    filepath.display()
                )
            })? {
            Some(cid) => {
                trace!(self.logger, "File already exists in IPFS"; "cid" => %cid);
                Ok(FileUri(cid))
            }
            None => {
                let cid = self
                    .rpc_client
                    .upload_file(filepath, &self.ipfs_dir_path)
                    .await
                    .with_context(|| {
                        format!("Failed to upload file '{}' to IPFS", filepath.display())
                    })?;
                trace!(
                    self.logger, "File upload to IPFS finished";
                    "file_path" => %filepath.display(), "cid" => %cid
                );

                Ok(FileUri(cid))
            }
        }
    }
}

/// Backend trait for IPFS operations
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait IpfsBackendUploader: Sync + Send {
    /// Create a directory in IPFS
    async fn create_dir(&self, dir_path: &IpfsMfsDirPath) -> StdResult<()>;

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
            .send(IpfsFilesStatQuery::for_file_in_dir(
                mfs_dir_path,
                file_path,
            )?)
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

    #[tokio::test]
    async fn create_dir_only_once_when_uploading_multiple_time() {
        let uploader = IpfsUploader::new(
            MockBuilder::configure(|mock: &mut MockIpfsBackendUploader| {
                mock.expect_create_dir()
                    .with(eq(IpfsMfsDirPath::from("/test/dir")))
                    .returning(|_| Ok(()))
                    .once();
                mock.expect_file_exists().returning(|_, _| Ok(None));
                mock.expect_upload_file().returning(|_, _| Ok(String::new()));
            }),
            IpfsMfsDirPath::from("/test/dir"),
            &TestLogger::stdout(),
        );

        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
    }

    #[tokio::test]
    async fn existing_file_is_not_uploaded_and_its_cid_is_returned() {
        let uploader = IpfsUploader::new(
            MockBuilder::configure(|mock: &mut MockIpfsBackendUploader| {
                mock.expect_create_dir().returning(|_| Ok(()));
                mock.expect_file_exists()
                    .with(
                        eq(IpfsMfsDirPath::from("/test/dir")),
                        eq(Path::new("/a/dummy-file.txt")),
                    )
                    .returning(|_, _| Ok(Some("existing".to_string())));
                mock.expect_upload_file().never();
            }),
            IpfsMfsDirPath::from("/test/dir"),
            &TestLogger::stdout(),
        );

        let result = uploader
            .upload_without_retry(Path::new("/a/dummy-file.txt"))
            .await
            .unwrap();

        assert_eq!(FileUri("existing".to_string()), result);
    }

    #[tokio::test]
    async fn non_existing_file_is_uploaded_and_its_cid_is_returned() {
        let uploader = IpfsUploader::new(
            MockBuilder::configure(|mock: &mut MockIpfsBackendUploader| {
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
            }),
            IpfsMfsDirPath::from("/test/dir"),
            &TestLogger::stdout(),
        );

        uploader
            .upload_without_retry(Path::new("/a/dummy-file.txt"))
            .await
            .unwrap();
    }
}
