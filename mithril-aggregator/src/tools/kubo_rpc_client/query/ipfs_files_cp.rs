use std::path::{Path, PathBuf};

use reqwest::{RequestBuilder, Response};

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::KuboRpcQuery;

/// Query to reference IPFS files in an MFS (Mutable File System) in IPFS via the Kubo RPC API.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-cp
pub struct IpfsFilesCpQuery {
    source_cid: String,
    dest_directory: PathBuf,
}

impl IpfsFilesCpQuery {
    /// Create a query that will reference the given IPFS CID in the given MFS directory.
    pub fn reference_file_in_mfs_dir<P: AsRef<Path>>(
        source_cid: String,
        dest_directory: P,
    ) -> Self {
        Self {
            source_cid,
            dest_directory: dest_directory.as_ref().to_path_buf(),
        }
    }
}

#[async_trait::async_trait]
impl KuboRpcQuery for IpfsFilesCpQuery {
    type Response = ();

    fn route(&self) -> String {
        "api/v0/files/cp".to_string()
    }

    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder
            .query(&[("arg", &self.source_cid)])
            .query(&[("arg", &self.dest_directory)]))
    }

    async fn handle_success(&self, _response: Response) -> StdResult<Self::Response> {
        Ok(())
    }
}
