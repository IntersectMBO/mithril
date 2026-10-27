use std::path::Path;
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use futures::stream::StreamExt;
use reqwest::{Response, Url};
use serde::Deserialize;
use slog::{Logger, debug};

use mithril_common::{StdError, StdResult, logging::LoggerExtensions};

use crate::common::CompressionAlgorithm;
use crate::feedback::FeedbackSender;
use crate::file_downloader::interface::FileDownloaderUnreachable;
use crate::utils::url;

use super::streaming::{self, DownloadedStream};
use super::{FileDownloader, FileDownloaderUri, interface::DownloadEvent};

const EXISTENCE_CHECK_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const KUBO_RPC_API_CHECK_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A file downloader that downloads content from IPFS through a Kubo node's RPC API.
///
/// Handled Kubo RPC api specifics:
/// - requests are `POST`s.
/// - a missing block is reported as a `500` response whose *body* explains the failure, not as a `404`.
/// - Kubo does not set `content-length`, so the size must be retrieved with a separate RPC call.
/// - the RPC base URL is checked with a `version` call, as any HTTP server accepts the other calls.
pub struct IpfsFileDownloader {
    http_client: reqwest::Client,
    /// Base URL of the Kubo node's RPC API, e.g. `http://127.0.0.1:5001/`.
    rpc_base_url: Url,
    feedback_sender: FeedbackSender,
    existence_check_timeout: Duration,
    /// Timeout of the check that the RPC base URL answers as a Kubo RPC API.
    kubo_rpc_api_check_timeout: Duration,
    logger: Logger,
}

/// Response body of a Kubo `files/stat` call.
///
/// See: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-stat
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FilesStatResponse {
    size: u64,
}

/// Response body of a Kubo `version` call.
///
/// See: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-version
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VersionResponse {
    version: String,
}

impl IpfsFileDownloader {
    /// Constructs a new `IpfsFileDownloader`.
    pub fn new(
        rpc_base_url: Url,
        feedback_sender: FeedbackSender,
        logger: Logger,
    ) -> StdResult<Self> {
        let http_client = reqwest::ClientBuilder::new()
            .build()
            .with_context(|| "Building http client for IpfsFileDownloader failed")?;

        Ok(Self {
            http_client,
            rpc_base_url: url::enforce_trailing_slash(rpc_base_url),
            feedback_sender,
            existence_check_timeout: EXISTENCE_CHECK_DEFAULT_TIMEOUT,
            kubo_rpc_api_check_timeout: KUBO_RPC_API_CHECK_DEFAULT_TIMEOUT,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_existence_check_timeout(mut self, timeout: Duration) -> Self {
        self.existence_check_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_kubo_rpc_api_check_timeout(mut self, timeout: Duration) -> Self {
        self.kubo_rpc_api_check_timeout = timeout;
        self
    }

    fn endpoint(&self, route: &str) -> StdResult<Url> {
        self.rpc_base_url
            .join(route)
            .with_context(|| format!("Could not build Kubo RPC endpoint for route '{route}'"))
    }

    /// POST to a Kubo RPC `route` with the given IPFS path (`ipfs://<directory-CID>/<filename>`) as
    /// its `arg` query parameter.
    async fn post(
        &self,
        route: &str,
        ipfs_path: &str,
        timeout: Option<Duration>,
    ) -> StdResult<Response> {
        let endpoint = self.endpoint(route)?;
        debug!(self.logger, "POST Kubo RPC"; "route" => route, "ipfs_path" => ipfs_path);
        let mut response_builder = self.http_client.post(endpoint).query(&[("arg", ipfs_path)]);

        if let Some(timeout) = timeout {
            response_builder = response_builder.timeout(timeout);
        }

        let response = response_builder.send().await.map_err(|err| {
            if err.is_connect() || err.is_timeout() {
                anyhow!(FileDownloaderUnreachable {
                    source: "IPFS",
                    uri: ipfs_path.to_string()
                })
            } else {
                anyhow!(err)
            }
            .context(format!(
                "Cannot perform a POST to Kubo route '{route}' for arg='{ipfs_path}'"
            ))
        })?;

        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Self::kubo_error(ipfs_path, response).await)
        }
    }

    /// Kubo reports a missing block through a `500` response whose *body* carries the error,
    /// not through a `404` status code, so we need to inspect the body text to tell "not found"
    /// apart from any other failure.
    ///
    /// Note: a `"context deadline exceeded"` body (Kubo timing out while resolving the path over
    /// the network) is deliberately *not* treated as "not found": it can also happen for content
    /// that does exist but is slow to resolve, so misclassifying it would be misleading.
    async fn kubo_error(ipfs_path: &str, response: Response) -> StdError {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|e| e.to_string());

        if body.contains("no link named") {
            anyhow!("Location='{ipfs_path}' not found")
        } else {
            anyhow!("Unhandled error {status}: {body}")
        }
    }

    /// Check that the RPC base URL answers as a Kubo RPC API.
    pub async fn check_kubo_rpc_api(&self) -> StdResult<()> {
        let rpc_base_url = self.rpc_base_url_without_credentials();
        match self.fetch_kubo_version().await {
            Ok(version) => {
                debug!(self.logger, "Kubo RPC API available"; "version" => version);
                Ok(())
            }
            Err(error) => match error.downcast_ref::<reqwest::Error>() {
                Some(error) if error.is_connect() => Err(anyhow!(
                    "Cannot reach the Kubo RPC API at '{rpc_base_url}'"
                )),
                Some(error) if error.is_timeout() => Err(anyhow!(
                    "Kubo RPC API at '{rpc_base_url}' did not answer within {:?}",
                    self.kubo_rpc_api_check_timeout
                )),
                _ => Err(anyhow!(
                    "IPFS RPC URL '{rpc_base_url}' does not answer as a Kubo RPC API: {error:#}"
                )),
            },
        }
    }

    fn rpc_base_url_without_credentials(&self) -> Url {
        let mut rpc_base_url = self.rpc_base_url.clone();
        let _ = rpc_base_url.set_username("");
        let _ = rpc_base_url.set_password(None);

        rpc_base_url
    }

    async fn fetch_kubo_version(&self) -> StdResult<String> {
        let response = self
            .http_client
            .post(self.endpoint("api/v0/version")?)
            .timeout(self.kubo_rpc_api_check_timeout)
            .send()
            .await?
            .error_for_status()?;
        let version: VersionResponse = response
            .json()
            .await
            .with_context(|| "Failed to deserialize Kubo version response")?;

        Ok(version.version)
    }

    async fn file_size(&self, ipfs_path: &str) -> StdResult<u64> {
        let response = self
            .post(
                "api/v0/files/stat",
                ipfs_path,
                Some(self.existence_check_timeout),
            )
            .await?;
        let stat: FilesStatResponse = response
            .json()
            .await
            .with_context(|| "Failed to deserialize Kubo files/stat response")?;

        Ok(stat.size)
    }

    /// Open the `ipfs_path` as a byte stream fetched from Kubo.
    ///
    /// The preliminary `files/stat` call both resolves the size (there is no `content-length`
    /// header to rely on) and acts as the existence check.
    async fn open_stream(&self, ipfs_path: &str) -> StdResult<DownloadedStream> {
        let size = self.file_size(ipfs_path).await?;
        let response = self.post("api/v0/cat", ipfs_path, None).await?;
        let stream = response
            .bytes_stream()
            .map(|item| item.map(|chunk| chunk.to_vec()).map_err(Into::into))
            .boxed();

        Ok(DownloadedStream { stream, size })
    }
}

#[async_trait]
impl FileDownloader for IpfsFileDownloader {
    async fn download_unpack(
        &self,
        location: &FileDownloaderUri,
        _file_size: u64,
        target_dir: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
        download_event_type: DownloadEvent,
    ) -> StdResult<()> {
        // `location` is expected a path in the form `ipfs://<directory-CID>/<filename>`.
        let ipfs_path = location.as_str();
        let downloaded = self.open_stream(ipfs_path).await?;

        streaming::download_unpack(
            &self.feedback_sender,
            downloaded,
            target_dir,
            compression_algorithm,
            download_event_type,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;

    use httpmock::Method::POST;
    use httpmock::MockServer;

    use mithril_common::{entities::FileUri, temp_dir_create};

    use crate::feedback::{
        FeedbackReceiver, MithrilEvent, MithrilEventCardanoDatabase, StackFeedbackReceiver,
    };
    use crate::test_utils::TestLogger;

    use super::*;

    fn downloader(server: &MockServer, feedback_sender: FeedbackSender) -> IpfsFileDownloader {
        IpfsFileDownloader::new(
            Url::parse(&server.base_url()).unwrap(),
            feedback_sender,
            TestLogger::stdout(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn downloading_ipfs_file_send_feedback() {
        let target_dir = temp_dir_create!();
        let content = "Hello, world!";
        let size = content.len() as u64;
        let ipfs_path = "ipfs://QmDummyDirCid/00006.tar.zst";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/stat")
                .query_param("arg", ipfs_path);
            then.status(200)
                .json_body(serde_json::json!({"Key": "bafkreidummy", "Size": size}));
        });
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/cat").query_param("arg", ipfs_path);
            then.status(200).body(content);
        });
        let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
        let feedback_receiver_clone = feedback_receiver.clone() as Arc<dyn FeedbackReceiver>;
        let ipfs_file_downloader =
            downloader(&server, FeedbackSender::new(&[feedback_receiver_clone]));
        let download_id = "id".to_string();

        ipfs_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(ipfs_path.to_string())),
                0,
                &target_dir,
                None,
                DownloadEvent::Digest {
                    download_id: download_id.clone(),
                },
            )
            .await
            .unwrap();

        let expected_events = vec![
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadStarted {
                download_id: download_id.clone(),
                size,
            }),
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadProgress {
                download_id: download_id.clone(),
                downloaded_bytes: size,
                size,
            }),
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadCompleted {
                download_id: download_id.clone(),
            }),
        ];
        assert_eq!(expected_events, feedback_receiver.stacked_events());
    }

    #[tokio::test]
    async fn missing_block_reported_through_500_body_is_turned_into_a_not_found_error() {
        let target_dir = temp_dir_create!();
        let ipfs_path = "ipfs://QmRoiDvkuGRg4tjWabNp4Y5jxbUS8FFNFn9pDopqfbtfW2/00007.tar.zst";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/files/stat").query_param("arg", ipfs_path);
            then.status(500).json_body(serde_json::json!({
                "Message": "no link named \"00007.tar.zst\" under QmRoiDvkuGRg4tjWabNp4Y5jxbUS8FFNFn9pDopqfbtfW2",
                "Code": 0,
                "Type": "error"
            }));
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]));

        let error = ipfs_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(ipfs_path.to_string())),
                0,
                &target_dir,
                None,
                DownloadEvent::Digest {
                    download_id: "id".to_string(),
                },
            )
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains(&format!("Location='{ipfs_path}' not found")),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn files_stat_timeout_raise_unreachable_file_downloader_error() {
        let target_dir = temp_dir_create!();
        let ipfs_path = "ipfs://QmRoiDvkuGRg4tjWabNp4Y5jxbUS8FFNFn9pDopqfbtfW2/00007.tar.zst";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/stat")
                .query_param("arg", ipfs_path);
            then.delay(Duration::from_millis(100));
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]))
            .with_existence_check_timeout(Duration::from_millis(10));

        let error = ipfs_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(ipfs_path.to_string())),
                0,
                &target_dir,
                None,
                DownloadEvent::Digest {
                    download_id: "id".to_string(),
                },
            )
            .await
            .unwrap_err();

        assert_eq!(
            Some(&FileDownloaderUnreachable {
                source: "IPFS",
                uri: ipfs_path.to_string(),
            }),
            error.downcast_ref::<FileDownloaderUnreachable>()
        );
    }

    #[tokio::test]
    async fn kubo_rpc_api_check_succeeds_when_rpc_url_answers_as_a_kubo_rpc_api() {
        let server = MockServer::start();
        let version_mock = server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.status(200)
                .json_body(serde_json::json!({"Version": "0.43.1", "Commit": "", "Repo": "18"}));
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]));

        ipfs_file_downloader.check_kubo_rpc_api().await.unwrap();

        version_mock.assert();
    }

    #[tokio::test]
    async fn kubo_rpc_api_check_fails_when_rpc_url_does_not_answer_as_a_kubo_rpc_api() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.status(401).body("<html><body>Unauthorized</body></html>");
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]));

        let error = ipfs_file_downloader.check_kubo_rpc_api().await.unwrap_err();

        assert!(
            error.to_string().contains("does not answer as a Kubo RPC API"),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn kubo_rpc_api_check_fails_without_credentials_when_rpc_url_answers_a_non_kubo_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.status(200).body("<html><body>IPFS gateway</body></html>");
        });
        let mut rpc_base_url = Url::parse(&server.base_url()).unwrap();
        rpc_base_url.set_username("user").unwrap();
        rpc_base_url.set_password(Some("secret-password")).unwrap();
        let ipfs_file_downloader =
            IpfsFileDownloader::new(rpc_base_url, FeedbackSender::new(&[]), TestLogger::stdout())
                .unwrap();

        let error = ipfs_file_downloader.check_kubo_rpc_api().await.unwrap_err();

        assert!(
            error.to_string().contains("does not answer as a Kubo RPC API"),
            "unexpected error: {error:?}"
        );
        assert!(
            !format!("{error:?}").contains("secret-password"),
            "credentials leaked: {error:?}"
        );
    }

    #[tokio::test]
    async fn kubo_rpc_api_check_fails_without_credentials_when_kubo_rpc_api_is_unreachable() {
        let closed_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ipfs_file_downloader = IpfsFileDownloader::new(
            Url::parse(&format!("http://user:secret-password@127.0.0.1:{closed_port}/")).unwrap(),
            FeedbackSender::new(&[]),
            TestLogger::stdout(),
        )
        .unwrap();

        let error = ipfs_file_downloader.check_kubo_rpc_api().await.unwrap_err();

        assert!(
            error.to_string().contains("Cannot reach the Kubo RPC API"),
            "unexpected error: {error:?}"
        );
        assert!(
            !format!("{error:?}").contains("secret-password"),
            "credentials leaked: {error:?}"
        );
    }

    #[tokio::test]
    async fn kubo_rpc_api_check_fails_when_kubo_rpc_api_does_not_answer_in_time() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/version");
            then.delay(Duration::from_millis(100))
                .status(200)
                .json_body(serde_json::json!({"Version": "0.43.1"}));
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]))
            .with_kubo_rpc_api_check_timeout(Duration::from_millis(10));

        let error = ipfs_file_downloader.check_kubo_rpc_api().await.unwrap_err();

        assert!(
            error.to_string().contains("did not answer within"),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn cat_does_not_apply_timeout() {
        let target_dir = temp_dir_create!();
        let ipfs_path = "ipfs://QmRoiDvkuGRg4tjWabNp4Y5jxbUS8FFNFn9pDopqfbtfW2/00007.tar.zst";

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/stat")
                .query_param("arg", ipfs_path);
            then.status(200)
                .json_body(serde_json::json!({"Key": "bafkreidummy", "Size": 1}));
        });
        server.mock(|when, then| {
            when.method(POST).path("/api/v0/cat").query_param("arg", ipfs_path);
            then.delay(Duration::from_millis(100)).body(b"Hello, world!");
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]))
            .with_existence_check_timeout(Duration::from_millis(10));

        ipfs_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(ipfs_path.to_string())),
                0,
                &target_dir,
                None,
                DownloadEvent::Digest {
                    download_id: "id".to_string(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn context_deadline_exceeded_is_not_mistaken_for_a_missing_file() {
        let target_dir = temp_dir_create!();
        let ipfs_path = "ipfs://QmRoiDvkuGRg4tjWabNp4Y5jxbUS8FFNFn9pDopqfbtfW2/fake-cardano-cli.sh";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/api/v0/files/stat")
                .query_param("arg", ipfs_path);
            then.status(500).json_body(serde_json::json!({
                "Message": "context deadline exceeded",
                "Code": 0,
                "Type": "error"
            }));
        });
        let ipfs_file_downloader = downloader(&server, FeedbackSender::new(&[]));

        let error = ipfs_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(ipfs_path.to_string())),
                0,
                &target_dir,
                None,
                DownloadEvent::Digest {
                    download_id: "id".to_string(),
                },
            )
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("Unhandled error"),
            "unexpected error: {error:?}"
        );
    }
}
