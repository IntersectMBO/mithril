use std::path::Path;

use anyhow::Context;
use reqwest::{RequestBuilder, Response};
use serde::Deserialize;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::api::format_response_error;
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcQuery};

/// Query to display file status in an MFS (Mutable File System) in IPFS via the Kubo RPC API.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-stat
#[derive(Debug)]
pub struct IpfsFilesStatQuery {
    path_in_ipfs: String,
}

/// Response from the IPFS files stat operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IpfsStatResponse {
    /// Hash (CID) of the file
    pub hash: String,
    /// Size of the file in bytes
    pub size: u64,
    /// Cumulative size including blocks
    pub cumulative_size: u64,
    /// Type of the IPFS object
    pub r#type: MfsStatType,
}

/// Type of MFS (Mutable File System) entry in IPFS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MfsStatType {
    /// A file entry
    File,
    /// A directory entry
    Directory,
}

impl IpfsFilesStatQuery {
    /// Create a query that will get the status of a file in the MFS.
    pub fn new<P: AsRef<str>>(path_in_ipfs: P) -> Self {
        Self {
            path_in_ipfs: path_in_ipfs.as_ref().to_string(),
        }
    }

    /// Creates a query for the file in `mfs_dir` whose name is taken from `file_path`.
    ///
    /// Only the final component of `file_path` is used. Returns an error if the path
    /// has no file name.
    pub fn for_file_in_dir<P: AsRef<Path>>(
        mfs_dir: &IpfsMfsDirPath,
        file_path: P,
    ) -> StdResult<Self> {
        let filename = file_path
            .as_ref()
            .file_name()
            .with_context(|| {
                format!(
                    "Failed to get filename from path: {}",
                    file_path.as_ref().display()
                )
            })?
            .to_string_lossy();
        Ok(Self::new(format!("{mfs_dir}{filename}")))
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsFilesStatQuery {
    type Response = Option<IpfsStatResponse>;

    fn route(&self) -> String {
        "api/v0/files/stat".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder.query(&[("arg", &self.path_in_ipfs)]))
    }

    async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
        response
            .json()
            .await
            .map(Some)
            .with_context(|| "Failed to deserialize IPFS stat response")
    }

    async fn handle_error(&self, response: Response) -> StdResult<Self::Response> {
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| "Failed to read IPFS files stat error response")?;

        if body.contains("file does not exist") {
            Ok(None)
        } else {
            Err(format_response_error(status, &body))
        }
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[test]
    fn for_file_in_dir_builds_mfs_path_from_directory_and_file_name() {
        let query = IpfsFilesStatQuery::for_file_in_dir(
            &IpfsMfsDirPath::from("/test/dir"),
            "/local/archive/dummy-file.txt",
        )
        .unwrap();

        assert_eq!("/test/dir/dummy-file.txt", query.path_in_ipfs);
    }

    #[test]
    fn for_file_in_dir_returns_error_when_path_has_no_file_name() {
        let error =
            IpfsFilesStatQuery::for_file_in_dir(&IpfsMfsDirPath::from("/test/dir"), Path::new(""))
                .unwrap_err();

        assert!(error.to_string().contains("Failed to get filename from path"));
    }

    #[tokio::test]
    async fn return_stat_data_if_request_succeeds() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/stat").query_param("arg", "/test");
            then.status(200).json_body(serde_json::json!({"Hash": "QmHash", "Size": 1, "CumulativeSize": 2, "Type": "file"}));
        });

        let response = client.send(IpfsFilesStatQuery::new("/test")).await.unwrap();
        assert_eq!(
            Some(IpfsStatResponse {
                hash: "QmHash".to_string(),
                size: 1,
                cumulative_size: 2,
                r#type: MfsStatType::File
            }),
            response
        );
    }

    #[tokio::test]
    async fn return_none_if_request_fails_with_not_exist_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/stat")
                .query_param("arg", "/test");
            then.status(500).json_body(
                serde_json::json!({"Message":"file does not exist","Code":0,"Type":"error"}),
            );
        });

        let response = client.send(IpfsFilesStatQuery::new("/test")).await.unwrap();
        assert_eq!(None, response);
    }

    #[tokio::test]
    async fn return_error_if_request_fails_with_other_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/stat").query_param("arg", "/test");
            then.status(500).json_body(
                serde_json::json!({"Message":"paths must start with a leading slash","Code":0,"Type":"error"}),
            );
        });

        let err = client.send(IpfsFilesStatQuery::new("/test")).await.unwrap_err();
        assert!(err.to_string().contains("paths must start with a leading slash"));
    }
}
