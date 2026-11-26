use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

/// Query to remove a file from an MFS (Mutable File System) in IPFS via the Kubo RPC API.
///
/// Note: only the MFS entry is removed, the content stays available until garbage collected.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-rm
#[derive(Debug)]
pub struct IpfsFilesRmQuery {
    path_in_ipfs: String,
}

impl IpfsFilesRmQuery {
    /// Create a query that will remove the given file from the MFS.
    pub fn new<P: AsRef<str>>(path_in_ipfs: P) -> Self {
        Self {
            path_in_ipfs: path_in_ipfs.as_ref().to_string(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsFilesRmQuery {
    type Response = ();

    fn route(&self) -> String {
        "api/v0/files/rm".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder.query(&[("arg", &self.path_in_ipfs)]))
    }

    async fn handle_success(&self, _response: Response) -> StdResult<Self::Response> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[tokio::test]
    async fn succeeds_when_server_returns_200() {
        let (server, client) = setup_server_and_client();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/rm")
                .query_param("arg", "/test/file.txt");
            then.status(200);
        });

        client.send(IpfsFilesRmQuery::new("/test/file.txt")).await.unwrap();
        mock.assert();
    }

    #[tokio::test]
    async fn return_error_if_request_fails() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/rm");
            then.status(500).json_body(
                serde_json::json!({"Message":"file does not exist","Code":0,"Type":"error"}),
            );
        });

        let err = client
            .send(IpfsFilesRmQuery::new("/test/file.txt"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("file does not exist"));
    }
}
