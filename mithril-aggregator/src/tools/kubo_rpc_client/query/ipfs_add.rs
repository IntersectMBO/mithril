use std::path::{Path, PathBuf};

use anyhow::Context;
use reqwest::{RequestBuilder, Response};
use serde::Deserialize;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

/// Query to add a file to IPFS via the Kubo RPC API.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-add
// TODO: Enforce most add parameters to make CID deterministic.
pub struct IpfsAddQuery {
    file_path: PathBuf,
}

/// Response from the IPFS add operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IpfsAddResponse {
    /// Name of the added file
    pub name: String,
    /// Hash of the added file (CID)
    pub hash: String,
}

impl IpfsAddQuery {
    /// Create a query that will add the given file to IPFS.
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsAddQuery {
    type Response = IpfsAddResponse;

    fn route(&self) -> String {
        "api/v0/add".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        let form = reqwest::multipart::Form::new().file("file", &self.file_path).await?;
        Ok(request_builder.multipart(form))
    }

    async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
        response
            .json()
            .await
            .with_context(|| "Failed to deserialize IPFS add response")
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use mithril_common::temp_dir_create;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[tokio::test]
    async fn return_add_data_if_request_succeeds() {
        let test_dir = temp_dir_create!();
        let file = test_dir.join("test.txt");
        std::fs::File::create(&file).unwrap();

        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/add");
            then.status(200).json_body(serde_json::json!({"Name":"test.txt","Hash":"QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR","Size":"23"}));
        });

        let response = client.send(IpfsAddQuery::new(file)).await.unwrap();
        assert_eq!(
            IpfsAddResponse {
                name: "test.txt".to_string(),
                hash: "QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR".to_string(),
            },
            response
        );
    }

    #[tokio::test]
    async fn return_error_if_request_fails() {
        let test_dir = temp_dir_create!();
        let file = test_dir.join("test.txt");
        std::fs::File::create(&file).unwrap();

        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/add");
            then.status(500).json_body(
                serde_json::json!({"Message":"paths must start with a leading slash","Code":0,"Type":"error"}),
            );
        });

        let err = client.send(IpfsAddQuery::new(file)).await.unwrap_err();
        assert!(
            err.to_string().contains("paths must start with a leading slash"),
            "unexpected error: {err}"
        );
    }
}
