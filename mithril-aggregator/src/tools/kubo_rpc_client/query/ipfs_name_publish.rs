use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

/// Query to publish an IPFS object to IPNS
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-name-publish
#[derive(Debug)]
pub struct IpfsNamePublishQuery {
    ipfs_object_path: String,
    ipfs_key: String,
    ttl_seconds: u64,
}

impl IpfsNamePublishQuery {
    /// Lifetime in hours of the IPNS record in the DHT (using kubo default: 48 hours).
    const BASE_LIFETIME_HOURS: u64 = 48;
    /// Cache TTL in seconds of the IPNS record in the Kubo node (using kubo default: 5 minutes).
    // Todo: check if the default TTL raise issues, notably when used in the E2E suite, if yes make it configurable.
    const BASE_TTL_SECONDS: u64 = 60 * 5;

    /// Create a query that will publish the given IPFS object to IPNS.
    pub fn publish_to_ipns<P: Into<String>, K: Into<String>>(
        ipfs_object_path: P,
        ipfs_key: K,
    ) -> Self {
        Self {
            ipfs_object_path: ipfs_object_path.into(),
            ipfs_key: ipfs_key.into(),
            ttl_seconds: Self::BASE_TTL_SECONDS,
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsNamePublishQuery {
    type Response = ();

    fn route(&self) -> String {
        "api/v0/name/publish".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder
            .query(&[("arg", &self.ipfs_object_path), ("key", &self.ipfs_key)])
            .query(&[
                ("lifetime", &format!("{}h", Self::BASE_LIFETIME_HOURS)),
                ("ttl", &format!("{}s", self.ttl_seconds)),
            ]))
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
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/name/publish")
                .query_param(
                    "arg",
                    "/ipfs/QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR",
                )
                .query_param("key", "my-key-name")
                .query_param("lifetime", "48h")
                .query_param("ttl", "300s");
            then.status(200);
        });

        client
            .send(IpfsNamePublishQuery::publish_to_ipns(
                "/ipfs/QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR",
                "my-key-name",
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn return_error_if_request_fails_with_other_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/name/publish");
            then.status(500).json_body(
                serde_json::json!({"Message":"no key by the given name was found","Code":0,"Type":"error"}),
            );
        });

        let err = client
            .send(IpfsNamePublishQuery::publish_to_ipns(
                "/ipfs/QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR",
                "my-key-name",
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no key by the given name was found"));
    }
}
