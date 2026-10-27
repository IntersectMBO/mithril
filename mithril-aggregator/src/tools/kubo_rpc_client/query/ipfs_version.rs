use std::time::Duration;

use anyhow::Context;
use reqwest::Response;
use serde::Deserialize;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

const IPFS_VERSION_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Query to get the version of the Kubo node behind the RPC API.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-version
#[derive(Debug, Default)]
pub struct IpfsVersionQuery;

/// Response from the Kubo version operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IpfsVersionResponse {
    /// Version of the Kubo node
    pub version: String,
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsVersionQuery {
    type Response = IpfsVersionResponse;

    fn route(&self) -> String {
        "api/v0/version".to_string()
    }

    fn timeout(&self) -> Duration {
        IPFS_VERSION_QUERY_TIMEOUT
    }

    async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
        response
            .json()
            .await
            .with_context(|| "Failed to deserialize Kubo version response")
    }
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    #[tokio::test]
    async fn returns_the_kubo_version_when_server_returns_200() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.status(200).json_body(serde_json::json!({
                "Version": "0.43.1",
                "Commit": "",
                "Repo": "18",
                "System": "amd64/linux",
                "Golang": "go1.25.1"
            }));
        });

        let response = client.send(IpfsVersionQuery).await.unwrap();

        assert_eq!(
            IpfsVersionResponse {
                version: "0.43.1".to_string()
            },
            response
        );
    }

    #[tokio::test]
    async fn return_error_if_server_is_not_a_kubo_rpc_api() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.status(200).body("<html><body>IPFS gateway</body></html>");
        });

        client.send(IpfsVersionQuery).await.unwrap_err();
    }
}
