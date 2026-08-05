use std::fmt::Display;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::FileUri;

/// CloudRemotePath represents a cloud remote path
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct CloudRemotePath(PathBuf);

impl CloudRemotePath {
    /// CloudRemotePath factory
    pub fn new(file_path: &str) -> Self {
        Self(PathBuf::from(file_path))
    }

    /// Join a file path to the current remote path
    pub fn join(&self, file_path: &str) -> Self {
        Self(self.0.join(file_path))
    }

    /// Transform this cloud remote path to file uri hosted in Google Cloud storage
    pub fn to_gcloud_storage_location(&self, bucket: &str, use_cdn_domain: bool) -> FileUri {
        let mut uri = vec![];
        if !use_cdn_domain {
            uri.push("storage.googleapis.com");
        }
        uri.push(bucket);
        let file_path = self.to_string();
        uri.push(&file_path);

        FileUri(format!("https://{}", uri.join("/")))
    }
}

impl Display for CloudRemotePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_string_lossy())
    }
}

impl From<&Path> for CloudRemotePath {
    fn from(path: &Path) -> Self {
        CloudRemotePath(path.to_path_buf())
    }
}

/// CloudBackendUploader represents a cloud backend uploader
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CloudBackendUploader: Send + Sync {
    /// Check if a file exists in the cloud backend
    async fn file_exists(&self, remote_file_path: &CloudRemotePath) -> StdResult<Option<FileUri>>;

    /// List files URI from remote folder of cloud backend
    async fn list_files(
        &self,
        remote_folder_path: &CloudRemotePath,
    ) -> StdResult<Vec<CloudRemotePath>>;

    /// Get the file URI for a given remote file path in the cloud backend
    fn get_file_uri(&self, remote_file_path: &CloudRemotePath) -> FileUri;

    /// Upload a file to the cloud backend
    async fn upload_file(
        &self,
        local_file_path: &Path,
        remote_file_path: &CloudRemotePath,
    ) -> StdResult<FileUri>;

    /// Make a file public in the cloud backend
    async fn make_file_public(&self, remote_file_path: &CloudRemotePath) -> StdResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_location_not_using_cdn_domain_return_google_api_uri() {
        let use_cdn_domain = false;
        let bucket = "cdn.mithril.network".to_string();
        let remote_file_path = CloudRemotePath::new("remote_folder").join("snapshot.xxx.tar.zst");

        let location = remote_file_path.to_gcloud_storage_location(&bucket, use_cdn_domain);

        assert_eq!(
            FileUri("https://storage.googleapis.com/cdn.mithril.network/remote_folder/snapshot.xxx.tar.zst".to_string()),
            location
        );
    }

    #[tokio::test]
    async fn get_location_using_cdn_domain_return_cdn_in_uri() {
        let use_cdn_domain = true;
        let bucket = "cdn.mithril.network".to_string();
        let remote_file_path = CloudRemotePath::new("remote_folder").join("snapshot.xxx.tar.zst");

        let location = remote_file_path.to_gcloud_storage_location(&bucket, use_cdn_domain);

        assert_eq!(
            FileUri("https://cdn.mithril.network/remote_folder/snapshot.xxx.tar.zst".to_string()),
            location
        );
    }
}
