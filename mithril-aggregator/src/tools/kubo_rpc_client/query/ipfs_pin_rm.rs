use anyhow::Context;
use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;
use crate::tools::kubo_rpc_client::api::format_response_error;

/// Query to unpin an object in IPFS via the Kubo RPC API, allowing it to be garbage collected.
///
/// Note: unpinning an object that is not pinned (or that does not exist) is considered a success.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-pin-rm
#[derive(Debug)]
pub struct IpfsPinRmQuery {
    cid: String,
}

impl IpfsPinRmQuery {
    /// Create a query that will unpin the given CID.
    pub fn new<C: AsRef<str>>(cid: C) -> Self {
        Self {
            cid: cid.as_ref().to_string(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsPinRmQuery {
    type Response = ();

    fn route(&self) -> String {
        "api/v0/pin/rm".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder.query(&[("arg", &self.cid)]))
    }

    async fn handle_success(&self, _response: Response) -> StdResult<Self::Response> {
        Ok(())
    }

    async fn handle_error(&self, response: Response) -> StdResult<Self::Response> {
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| "Failed to read IPFS pin rm error response")?;

        if body.contains("not pinned") {
            Ok(())
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

    #[tokio::test]
    async fn succeeds_when_server_returns_200() {
        let (server, client) = setup_server_and_client();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/api/v0/pin/rm").query_param("arg", "QmHash");
            then.status(200).json_body(serde_json::json!({"Pins": ["QmHash"]}));
        });

        client.send(IpfsPinRmQuery::new("QmHash")).await.unwrap();
        mock.assert();
    }

    #[tokio::test]
    async fn succeeds_if_request_fails_with_not_pinned_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/pin/rm");
            then.status(500).json_body(serde_json::json!({"Message":"not pinned or pinned indirectly","Code":0,"Type":"error"}));
        });

        client.send(IpfsPinRmQuery::new("QmHash")).await.unwrap();
    }

    #[tokio::test]
    async fn return_error_if_request_fails_with_other_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/pin/rm");
            then.status(500).json_body(
                serde_json::json!({"Message":"invalid path \"QmHash\"","Code":0,"Type":"error"}),
            );
        });

        let err = client.send(IpfsPinRmQuery::new("QmHash")).await.unwrap_err();
        assert!(err.to_string().contains("invalid path"));
    }
}
