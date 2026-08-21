use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcQuery};

/// Query to make an MFS (Mutable File System) directory in IPFS via the Kubo RPC API.
///
/// Note: `parents` flag is set to true by default; this has two effects:
/// - parent directories will be created if they do not exist.
/// - the command will succeed even if the directory already exists.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-mkdir
pub struct IpfsFilesMkdirQuery {
    ipfs_absolute_path: IpfsMfsDirPath,
}

impl IpfsFilesMkdirQuery {
    /// Create a query that will create the given IPFS absolute path as an MFS directory.
    pub fn create_mfs_directory(ipfs_absolute_path: &IpfsMfsDirPath) -> Self {
        Self {
            ipfs_absolute_path: ipfs_absolute_path.clone(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsFilesMkdirQuery {
    type Response = ();

    fn route(&self) -> String {
        "api/v0/files/mkdir".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder
            .query(&[("arg", &self.ipfs_absolute_path)])
            .query(&[("parents", true)]))
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
                .path("/api/v0/files/mkdir")
                .query_param("arg", "/test/")
                .query_param("parents", "true");
            then.status(200);
        });

        client
            .send(IpfsFilesMkdirQuery::create_mfs_directory(
                &IpfsMfsDirPath::from("/test"),
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn return_error_if_request_fails_with_other_message() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/mkdir");
            then.status(500).json_body(
                serde_json::json!({"Message":"paths must start with a leading slash","Code":0,"Type":"error"}),
            );
        });

        let err = client
            .send(IpfsFilesMkdirQuery::create_mfs_directory(
                &IpfsMfsDirPath::from("/test"),
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("paths must start with a leading slash"));
    }
}
