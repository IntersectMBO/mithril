use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, anyhow};
use slog::{Logger, trace};
use tokio::sync::OnceCell;

use mithril_common::StdResult;
use mithril_common::entities::FileUri;
use mithril_common::logging::LoggerExtensions;

use crate::FileUploader;
use crate::tools::kubo_rpc_client::query::{
    IpfsAddQuery, IpfsFilesLsQuery, IpfsFilesMkdirQuery, IpfsFilesStatQuery,
};
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcClient};

/// IPFS Content Identifier (CID)
pub type Cid = String;

/// File uploader that stores files to IPFS
///
/// #### Cache policy
/// The integrated cache is designed to work with batch uploads only, as it relies on the assumption
/// that all files are uploaded at once.
/// Consequently, items are not cached individually, and the cache is designed to be reset before
/// each batch using [IpfsUploader::refresh_existing_files_path_cache].
pub struct IpfsUploader {
    rpc_client: Arc<dyn IpfsBackendUploader>,
    ipfs_dir_path: IpfsMfsDirPath,
    directory_created: OnceCell<()>,
    existing_files_cache: Mutex<HashMap<String, Cid>>,
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
            existing_files_cache: Mutex::new(HashMap::new()),
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

    /// Refresh the cache of files paths from the cloud backend
    pub async fn refresh_existing_files_path_cache(&self) -> StdResult<()> {
        self.ensure_directory_exists().await?;

        let files = self
            .rpc_client
            .list_directory_files(&self.ipfs_dir_path)
            .await
            .with_context(|| "listing files in IPFS MFS directory")?;

        let mut cache = self
            .existing_files_cache
            .lock()
            .map_err(|_| anyhow!("Failed to acquire lock on existing_files_path_cache"))?;
        *cache = files;
        Ok(())
    }

    fn find_file_in_cache(&self, file_path: &Path) -> StdResult<Option<Cid>> {
        let filename = file_path
            .file_name()
            .with_context(|| format!("Failed to get filename from path: {}", file_path.display()))?
            .to_string_lossy();
        let cache = self
            .existing_files_cache
            .lock()
            .map_err(|_| anyhow!("Failed to acquire lock on existing_files_path_cache"))?;

        Ok(cache.get(filename.as_ref()).cloned())
    }
}

#[async_trait::async_trait]
impl FileUploader for IpfsUploader {
    async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri> {
        trace!(self.logger, "Uploading file to IPFS"; "file_path" => %filepath.display());
        self.ensure_directory_exists().await?;

        if let Some(cid) = self
            .find_file_in_cache(filepath)
            .with_context(|| format!("Failed to find file '{}' in cache", filepath.display()))?
        {
            return Ok(FileUri(cid));
        }

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
                &TestLogger::stdout(),
            )
        }

        fn with_initial_cache<K: Into<String>, V: Into<Cid>>(
            mut self,
            initial_cache: HashMap<K, V>,
        ) -> Self {
            self.existing_files_cache =
                Mutex::new(initial_cache.into_iter().map(|(k, v)| (k.into(), v.into())).collect());
            self
        }

        fn cache_content(&self) -> HashMap<String, Cid> {
            self.existing_files_cache.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn create_dir_only_once_when_uploading_multiple_time() {
        let uploader = IpfsUploader::new_for_test(IpfsMfsDirPath::from("/test/dir"), |mock| {
            mock.expect_create_dir()
                .with(eq(IpfsMfsDirPath::from("/test/dir")))
                .returning(|_| Ok(()))
                .once();
            mock.expect_file_exists().returning(|_, _| Ok(None));
            mock.expect_upload_file().returning(|_, _| Ok(String::new()));
        });

        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
        uploader.upload_without_retry(Path::new("whatever")).await.unwrap();
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

    mod file_caching {
        use super::*;

        #[track_caller]
        fn assert_cache_eq<K: Into<String>, V: Into<Cid>>(
            uploader: &IpfsUploader,
            expected: HashMap<K, V>,
        ) {
            assert_eq!(
                expected
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect::<HashMap<String, Cid>>(),
                uploader.cache_content()
            );
        }

        #[tokio::test]
        async fn refresh_list_only_once() {
            let uploader =
                IpfsUploader::new_for_test("/test/dir", |mock: &mut MockIpfsBackendUploader| {
                    mock.expect_create_dir().returning(|_| Ok(()));
                    mock.expect_list_dir()
                        .with(eq(IpfsMfsDirPath::from("/test/dir")))
                        .return_once(move |_| Ok(HashMap::from([("key".into(), "value".into())])))
                        .once();
                });

            uploader.refresh_existing_files_path_cache().await.unwrap();

            assert_cache_eq(&uploader, HashMap::from([("key", "value")]));
        }

        #[tokio::test]
        async fn failed_refresh_does_not_overwrite_cache() {
            let uploader =
                IpfsUploader::new_for_test("/test/dir", |mock: &mut MockIpfsBackendUploader| {
                    mock.expect_create_dir().returning(|_| Ok(()));
                    mock.expect_list_dir()
                        .return_once(move |_| Err(anyhow!("error")))
                        .once();
                })
                .with_initial_cache(HashMap::from([("initial", "content")]));

            uploader.refresh_existing_files_path_cache().await.unwrap_err();

            assert_cache_eq(&uploader, HashMap::from([("initial", "content")]));
        }

        #[tokio::test]
        async fn cached_files_are_not_stat_nor_uploaded() {
            let uploader =
                IpfsUploader::new_for_test("/test/dir", |mock: &mut MockIpfsBackendUploader| {
                    mock.expect_create_dir().returning(|_| Ok(()));
                    mock.expect_file_exists().never();
                    mock.expect_upload_file().never();
                })
                .with_initial_cache(HashMap::from([("dummy-file.txt", "FileCid")]));

            let uri = uploader.upload(Path::new("/my/dummy-file.txt")).await.unwrap();

            assert_eq!(FileUri("FileCid".to_string()), uri);
        }

        #[tokio::test]
        async fn check_file_exist_if_not_in_cache() {
            let uploader =
                IpfsUploader::new_for_test("/test/dir", |mock: &mut MockIpfsBackendUploader| {
                    mock.expect_create_dir().returning(|_| Ok(()));
                    mock.expect_file_exists()
                        .with(
                            eq(IpfsMfsDirPath::from("/test/dir")),
                            eq(Path::new("/my/dummy-file.txt")),
                        )
                        .returning(|_, _| Ok(Some("FileCid".to_string())));
                    mock.expect_upload_file().never();
                });

            let uri = uploader.upload(Path::new("/my/dummy-file.txt")).await.unwrap();

            assert_eq!(FileUri("FileCid".to_string()), uri);
        }
    }
}
