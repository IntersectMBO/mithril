use anyhow::Context;
use reqwest::{RequestBuilder, Response};
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::api::handle_file_not_exist_error;
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcQuery};

/// Query to list directories in an MFS (Mutable File System) in IPFS via the Kubo RPC API.
///
/// Returns the names of the directory entries.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-ls
#[derive(Debug)]
pub struct IpfsFilesLsQuery {
    dir: IpfsMfsDirPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsLsResponse {
    entries: Option<Vec<IpfsLsResponseItem>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsLsResponseItem {
    /// Name of the entry
    name: String,
}

impl IpfsFilesLsQuery {
    /// Create a query that will get the list a directory in the MFS.
    pub fn new(mfs_dir: &IpfsMfsDirPath) -> Self {
        Self {
            dir: mfs_dir.clone(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsFilesLsQuery {
    type Response = Option<HashSet<String>>;

    fn route(&self) -> String {
        "api/v0/files/ls".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder
            .query(&[("arg", &self.dir)])
            // disable sorting (handled rust-side)
            .query(&[("U", "true")]))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
        let response: IpfsLsResponse = response
            .json()
            .await
            .with_context(|| "Failed to deserialize IPFS ls response")?;

        match response.entries {
            Some(entries) => Ok(Some(entries.into_iter().map(|item| item.name).collect())),
            // If entries are null, the directory exists but is empty
            None => Ok(Some(HashSet::new())),
        }
    }

    async fn handle_error(&self, response: Response) -> StdResult<Self::Response> {
        handle_file_not_exist_error("files ls", response).await
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[tokio::test]
    async fn return_empty_list_when_directory_is_empty() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/ls")
                .query_param("arg", "/test/")
                .query_param_missing("long")
                .query_param("U", "true");
            // Kubo returns null if the directory exists but is empty
            then.status(200).json_body(serde_json::json!({ "Entries": null }));
        });

        let response = client
            .send(IpfsFilesLsQuery::new(&IpfsMfsDirPath::from("/test")))
            .await
            .unwrap();
        assert_eq!(Some(HashSet::new()), response);
    }

    #[tokio::test]
    async fn return_items_list_if_request_succeeds() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/ls")
                .query_param("arg", "/test/")
                .query_param_missing("long")
                .query_param("U", "true");
            then.status(200).json_body(serde_json::json!({
                "Entries":[
                    {"Name":"00000.tar.zst","Type":0,"Size":0,"Hash":""},
                    {"Name":"00001.tar.zst","Type":0,"Size":0,"Hash":""},
                    {"Name":"00002.tar.zst","Type":0,"Size":0,"Hash":""},
                    {"Name":"00003.tar.zst","Type":0,"Size":0,"Hash":""},
                    {"Name":"sub-dir","Type":0,"Size":0,"Hash":""}
                ]
            }));
        });

        let response = client
            .send(IpfsFilesLsQuery::new(&IpfsMfsDirPath::from("/test")))
            .await
            .unwrap();

        assert_eq!(
            Some(HashSet::from([
                "00000.tar.zst".to_string(),
                "00001.tar.zst".to_string(),
                "00002.tar.zst".to_string(),
                "00003.tar.zst".to_string(),
                "sub-dir".to_string(),
            ])),
            response
        );
    }

    #[tokio::test]
    async fn return_none_if_request_fails_with_not_exist_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/ls")
                .query_param("arg", "/test/");
            then.status(500).json_body(
                serde_json::json!({"Message":"file does not exist","Code":0,"Type":"error"}),
            );
        });

        let response = client
            .send(IpfsFilesLsQuery::new(&IpfsMfsDirPath::from("/test")))
            .await
            .unwrap();
        assert_eq!(None, response);
    }

    #[tokio::test]
    async fn return_error_if_request_fails_with_other_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/ls").query_param("arg", "/test/");
            then.status(500).json_body(
                serde_json::json!({"Message":"paths must start with a leading slash","Code":0,"Type":"error"}),
            );
        });

        let err = client
            .send(IpfsFilesLsQuery::new(&IpfsMfsDirPath::from("/test")))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("paths must start with a leading slash"));
    }
}
