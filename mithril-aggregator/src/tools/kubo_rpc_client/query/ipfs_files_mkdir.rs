use std::path::{Path, PathBuf};

use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

/// Query to make an MFS (Mutable File System) directory in IPFS via the Kubo RPC API.
///
/// Note: `parents` flag is set to true by default, this have two effects:
/// - parent directories will be created if they do not exist.
/// - the command will succeed even if the directory already exists.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-mkdir
pub struct IpfsFilesMkdirQuery {
    ipfs_absolute_path: PathBuf,
}

impl IpfsFilesMkdirQuery {
    /// Create a query that will create the given IPFS absolute path as an MFS directory.
    pub fn create_mfs_directory<P: AsRef<Path>>(ipfs_absolute_path: P) -> Self {
        Self {
            ipfs_absolute_path: ipfs_absolute_path.as_ref().to_path_buf(),
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
