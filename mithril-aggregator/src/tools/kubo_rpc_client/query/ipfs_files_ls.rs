use anyhow::Context;
use reqwest::{RequestBuilder, Response};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcQuery};

/// Query to list directories in an MFS (Mutable File System) in IPFS via the Kubo RPC API.
///
/// Returns a map of file names to their hashes / CIDs.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-ls
#[derive(Debug)]
pub struct IpfsFilesLsQuery {
    dir: IpfsMfsDirPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsLsResponse {
    entries: Vec<IpfsLsResponseItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsLsResponseItem {
    /// Name of the added file
    name: String,
    /// Hash of the added file (CID)
    hash: String,
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
    type Response = HashMap<String, String>;

    fn route(&self) -> String {
        "api/v0/files/ls".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder
            .query(&[("arg", &self.dir)])
            // enable long listing (else hashes are empty) and disable sorting (handled rust-side)
            .query(&[("long", "true"), ("U", "true")]))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
        let response: IpfsLsResponse = response
            .json()
            .await
            .with_context(|| "Failed to deserialize IPFS ls response")?;

        Ok(response
            .entries
            .into_iter()
            .map(|item| (item.name, item.hash))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[tokio::test]
    async fn return_items_list_if_request_succeeds() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/ls")
                .query_param("arg", "/test/")
                .query_param("long", "true")
                .query_param("U", "true");
            then.status(200).json_body(serde_json::json!({
                "Entries":[
                    {"Name":"00000.tar.zst","Type":0,"Size":28486,"Hash":"QmePDH8sb7dux6VEvACJYS3m76D4Cc8eyfhejs7wcDFwWi"},
                    {"Name":"00001.tar.zst","Type":0,"Size":28557,"Hash":"QmXtTUpZervXkza1KmmmnfkxqJmLxZAsRXUfVKQHPBBkFA"},
                    {"Name":"00002.tar.zst","Type":0,"Size":29518,"Hash":"QmYd4yX3ms9jeLcDd9r3DZaMYuKb7TNX5dL1VD1wyNgKac"},
                    {"Name":"00003.tar.zst","Type":0,"Size":28951,"Hash":"Qmbh4AHrNT8GMrJYLAyku88zhoZAyJcsRRyXNFbDJsbCp9"},
                    {"Name":"sub-dir","Type":1,"Size":0,"Hash":"QmX5UvqhAYnEqAGx41SCovCg4x6NTF5XEVBMLarqk8J4x7"}
                ]
            }));
        });

        let response = client
            .send(IpfsFilesLsQuery::new(&IpfsMfsDirPath::from("/test")))
            .await
            .unwrap();
        assert_eq!(
            HashMap::<String, String>::from([
                (
                    "00000.tar.zst".to_string(),
                    "QmePDH8sb7dux6VEvACJYS3m76D4Cc8eyfhejs7wcDFwWi".to_string(),
                ),
                (
                    "00001.tar.zst".to_string(),
                    "QmXtTUpZervXkza1KmmmnfkxqJmLxZAsRXUfVKQHPBBkFA".to_string(),
                ),
                (
                    "00002.tar.zst".to_string(),
                    "QmYd4yX3ms9jeLcDd9r3DZaMYuKb7TNX5dL1VD1wyNgKac".to_string(),
                ),
                (
                    "00003.tar.zst".to_string(),
                    "Qmbh4AHrNT8GMrJYLAyku88zhoZAyJcsRRyXNFbDJsbCp9".to_string(),
                ),
                (
                    "sub-dir".to_string(),
                    "QmX5UvqhAYnEqAGx41SCovCg4x6NTF5XEVBMLarqk8J4x7".to_string(),
                ),
            ]),
            response
        );
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
