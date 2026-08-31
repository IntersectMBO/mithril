use std::path::Path;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use futures::stream::StreamExt;
use reqwest::{Response, StatusCode, Url};
use slog::{Logger, debug};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use mithril_common::{StdResult, logging::LoggerExtensions};

use crate::common::CompressionAlgorithm;
use crate::feedback::FeedbackSender;

use super::streaming::{self, DownloadedStream};
use super::{FileDownloader, FileDownloaderUri, interface::DownloadEvent};

/// A file downloader that only handles download through HTTP.
pub struct HttpFileDownloader {
    http_client: reqwest::Client,
    feedback_sender: FeedbackSender,
    logger: Logger,
}

impl HttpFileDownloader {
    /// Constructs a new `HttpFileDownloader`.
    pub fn new(feedback_sender: FeedbackSender, logger: Logger) -> StdResult<Self> {
        let http_client = reqwest::ClientBuilder::new()
            .build()
            .with_context(|| "Building http client for HttpFileDownloader failed")?;

        Ok(Self {
            http_client,
            feedback_sender,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    async fn get(&self, location: &str) -> StdResult<Response> {
        debug!(self.logger, "GET Snapshot location='{location}'.");
        let request_builder = self.http_client.get(location);
        let response = request_builder.send().await.with_context(|| {
            format!("Cannot perform a GET for the snapshot (location='{location}')")
        })?;

        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(anyhow!("Location='{location} not found")),
            status_code => Err(anyhow!("Unhandled error {status_code}")),
        }
    }

    fn file_scheme_to_local_path(file_url: &str) -> Option<String> {
        Url::parse(file_url)
            .ok()
            .filter(|url| url.scheme() == "file")
            .and_then(|url| url.to_file_path().ok())
            .map(|path| path.to_string_lossy().into_owned())
    }

    /// Open the `location` as a byte stream read directly from the local filesystem.
    async fn open_local_stream(
        &self,
        local_path: &str,
        file_size: u64,
    ) -> StdResult<DownloadedStream> {
        let file = File::open(local_path).await?;
        let size = match file.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(_) => file_size,
        };

        // We can either allocate here each time or clone a shared buffer into the stream.
        // A larger read buffer is faster, fewer context switches:
        const CHUNK_SIZE: usize = 16 * 1024 * 1024;
        let stream = futures::stream::unfold(Some(file), |state| async move {
            let mut file = state?;
            let mut buffer = vec![0; CHUNK_SIZE];
            match file.read(&mut buffer).await {
                Ok(0) => None,
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);
                    Some((Ok(buffer), Some(file)))
                }
                // Yield the error once, then end the stream instead of looping on the same read.
                Err(e) => Some((Err(e.into()), None)),
            }
        })
        .boxed();

        Ok(DownloadedStream { stream, size })
    }

    /// Open the `location` as a byte stream fetched remotely over HTTP.
    async fn open_remote_stream(
        &self,
        location: &str,
        file_size: u64,
    ) -> StdResult<DownloadedStream> {
        let response = self.get(location).await?;
        let size = response.content_length().unwrap_or(file_size);
        let stream = response
            .bytes_stream()
            .map(|item| item.map(|chunk| chunk.to_vec()).map_err(Into::into))
            .boxed();

        Ok(DownloadedStream { stream, size })
    }
}

#[async_trait]
impl FileDownloader for HttpFileDownloader {
    async fn download_unpack(
        &self,
        location: &FileDownloaderUri,
        file_size: u64,
        target_dir: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
        download_event_type: DownloadEvent,
    ) -> StdResult<()> {
        let downloaded =
            if let Some(local_path) = Self::file_scheme_to_local_path(location.as_str()) {
                self.open_local_stream(&local_path, file_size).await?
            } else {
                self.open_remote_stream(location.as_str(), file_size).await?
            };

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
    use std::io::Write;
    use std::sync::Arc;

    use httpmock::MockServer;

    use mithril_common::{entities::FileUri, temp_dir_create};

    use crate::{
        feedback::{
            FeedbackReceiver, MithrilEvent, MithrilEventCardanoDatabase, StackFeedbackReceiver,
        },
        test_utils::TestLogger,
    };

    use super::*;

    #[cfg(not(target_family = "windows"))]
    fn local_file_uri(path: &Path) -> FileDownloaderUri {
        FileDownloaderUri::FileUri(FileUri(format!(
            "file://{}",
            path.canonicalize().unwrap().to_string_lossy()
        )))
    }

    #[cfg(target_family = "windows")]
    fn local_file_uri(path: &Path) -> FileDownloaderUri {
        // We need to transform `\\?\C:\data\Temp\mithril_test\snapshot.txt` to `file://C:/data/Temp/mithril_test/snapshot.txt`
        FileDownloaderUri::FileUri(FileUri(format!(
            "file:/{}",
            path.canonicalize()
                .unwrap()
                .to_string_lossy()
                .replace("\\", "/")
                .replace("?/", ""),
        )))
    }

    #[tokio::test]
    async fn downloading_http_file_send_feedback() {
        let target_dir = temp_dir_create!();
        let content = "Hello, world!";
        let size = content.len() as u64;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/snapshot.tar");
            then.status(200)
                .body(content)
                .header(reqwest::header::CONTENT_LENGTH.as_str(), size.to_string());
        });
        let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
        let feedback_receiver_clone = feedback_receiver.clone() as Arc<dyn FeedbackReceiver>;
        let http_file_downloader = HttpFileDownloader::new(
            FeedbackSender::new(&[feedback_receiver_clone]),
            TestLogger::stdout(),
        )
        .unwrap();
        let download_id = "id".to_string();

        http_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri(server.url("/snapshot.tar"))),
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
    async fn downloading_local_file_send_feedback() {
        let target_dir = temp_dir_create!();
        let content = "Hello, world!";
        let size = content.len() as u64;

        let source_file_path = target_dir.join("snapshot.txt");
        let mut file = std::fs::File::create(&source_file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
        let feedback_receiver_clone = feedback_receiver.clone() as Arc<dyn FeedbackReceiver>;
        let http_file_downloader = HttpFileDownloader::new(
            FeedbackSender::new(&[feedback_receiver_clone]),
            TestLogger::stdout(),
        )
        .unwrap();
        let download_id = "id".to_string();

        http_file_downloader
            .download_unpack(
                &local_file_uri(&source_file_path),
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
}
