use std::path::{Path, PathBuf};

use anyhow::Context;
use reqwest::{RequestBuilder, Response};
use serde::Deserialize;

use mithril_common::StdResult;

use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcQuery};

/// Query to add a file to IPFS via the Kubo RPC API.
///
/// see: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-add
#[derive(Debug)]
pub struct IpfsAddQuery {
    file_path: PathBuf,
    to_files: Option<IpfsMfsDirPath>,
    enable_no_copy: bool,
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
    #[cfg(test)]
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
            to_files: None,
            enable_no_copy: false,
        }
    }

    /// Create a query that will add the given file to IPFS and reference it in the MFS.
    pub fn new_with_mfs_reference<P1: AsRef<Path>>(
        file_path: P1,
        mfs_path: &IpfsMfsDirPath,
    ) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
            to_files: Some(mfs_path.clone()),
            enable_no_copy: false,
        }
    }

    /// Tells IPFS to not copy the file to its internal storage, but instead to reference it directly.
    ///
    /// **Test only** until we properly implement this feature (we must symlink the file into the
    /// IPFS root directory and set the `abspath` multipart header to the symlinked path, else the
    /// request will be rejected).
    #[cfg(test)]
    pub fn no_copy(mut self) -> Self {
        self.enable_no_copy = true;
        self
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
        mut request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        let mut part = reqwest::multipart::Part::file(&self.file_path).await?;

        if let Some(mfs_path) = &self.to_files {
            request_builder = request_builder.query(&[("to-files", mfs_path)]);
        }

        if self.enable_no_copy {
            request_builder = request_builder.query(&[("nocopy", true)]);

            // Add the "abspath" header to the file part
            // It sets the absolute path of the file being added to IPFS and MUST point to a path
            // inside the IPFS root directory.
            //
            // It may be different from the file path provided, e.g.: file_path could point to the
            // real location of the file to be added while `abspath` points to the symlinked path of
            // the same file but inside the IPFS root directory.
            let mut part_headers = reqwest::header::HeaderMap::new();
            let abspath = std::path::absolute(&self.file_path)
                .with_context(|| "Failed to get absolute path of file")?;
            part_headers.insert(
                "abspath",
                abspath
                    .to_str()
                    .with_context(|| "Failed to convert absolute file path to string")?
                    .try_into()?,
            );
            part = part.headers(part_headers);
        }

        let request_builder = request_builder
            .multipart(reqwest::multipart::Form::new().part("file", part))
            .query(&[("pin", true)])
            // Parameters below ensure deterministic CID.
            .query(&[
                ("inline", false),
                ("preserve-mode", false),
                ("preserve-mtime", false),
                ("raw-leaves", true),
                ("trickle", false),
                ("wrap-with-directory", false),
            ])
            .query(&[("cid-version", 1)])
            .query(&[("hash", "sha2-256"), ("chunker", "size-262144")]);

        Ok(request_builder)
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
            when.method(POST).path("/api/v0/add").query_param("pin", "true");
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

    #[tokio::test]
    async fn make_produced_cid_more_deterministic_by_enforcing_parameters_that_may_affect_cid() {
        let test_dir = temp_dir_create!();
        let file = test_dir.join("test.txt");
        std::fs::File::create(&file).unwrap();

        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/add")
                .query_param("cid-version", "1")
                .query_param("hash", "sha2-256")
                .query_param("raw-leaves", "true")
                .query_param("chunker", "size-262144")
                .query_param("inline", "false")
                .query_param("trickle", "false")
                .query_param("preserve-mode", "false")
                .query_param("preserve-mtime", "false")
                .query_param("wrap-with-directory", "false");
            then.status(200).json_body(serde_json::json!({"Name":"test.txt","Hash":"QmYi7wrRFKVCcTB56A6Pep2j31Q5mHfmmu21RzHXu25RVR","Size":"23"}));
        });

        client.send(IpfsAddQuery::new(file)).await.unwrap();
    }

    #[tokio::test]
    async fn no_copy_adds_query_parameter_and_abspath_multipart_header() {
        let test_dir = temp_dir_create!();
        let file = test_dir.join("test.txt");
        std::fs::File::create(&file).unwrap();

        let abs_filepath = file.canonicalize().unwrap().to_string_lossy().to_string();

        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/add")
                .query_param("nocopy", "true")
                .body_includes(format!("abspath: {abs_filepath}"));
            then.status(200)
                .json_body(serde_json::json!({"Name":"test.txt","Hash":"whatever"}));
        });

        client.send(IpfsAddQuery::new(file).no_copy()).await.unwrap();
    }
}
