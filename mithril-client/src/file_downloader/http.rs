use std::{
    io::{self, BufReader, Write},
    path::Path,
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use flume::{Receiver, Sender};
use futures::StreamExt;
use reqwest::{Response, StatusCode, Url};
use slog::{Logger, debug};
use tar::Archive;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use mithril_common::{StdResult, logging::LoggerExtensions};

use crate::common::CompressionAlgorithm;
use crate::feedback::FeedbackSender;
use crate::utils::StreamReader;

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

    /// Stream the `location` directly from the local filesystem
    async fn download_local_file(
        &self,
        local_path: &str,
        sender: &Sender<Vec<u8>>,
        download_event_type: DownloadEvent,
        file_size: u64,
    ) -> StdResult<()> {
        let mut downloaded_bytes: u64 = 0;
        let mut file = File::open(local_path).await?;
        let size = match file.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(_) => file_size,
        };

        self.feedback_sender
            .send_event(download_event_type.build_download_started_event(size))
            .await;

        loop {
            // We can either allocate here each time, or clone a shared buffer into sender.
            // A larger read buffer is faster, less context switches:
            let mut buffer = vec![0; 16 * 1024 * 1024];
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            buffer.truncate(bytes_read);
            sender.send_async(buffer).await.with_context(|| {
                format!("Local file read: could not write {bytes_read} bytes to stream.")
            })?;
            downloaded_bytes += bytes_read as u64;
            let event = download_event_type.build_download_progress_event(downloaded_bytes, size);
            self.feedback_sender.send_event(event).await;
        }

        self.feedback_sender
            .send_event(download_event_type.build_download_completed_event())
            .await;

        Ok(())
    }

    /// Stream the `location` remotely
    async fn download_remote_file(
        &self,
        location: &str,
        sender: &Sender<Vec<u8>>,
        download_event_type: DownloadEvent,
        file_size: u64,
    ) -> StdResult<()> {
        let mut downloaded_bytes: u64 = 0;
        let response = self.get(location).await?;
        let size = response.content_length().unwrap_or(file_size);
        let mut remote_stream = response.bytes_stream();

        self.feedback_sender
            .send_event(download_event_type.build_download_started_event(size))
            .await;

        while let Some(item) = remote_stream.next().await {
            let chunk = item.with_context(|| "Download: Could not read from byte stream")?;

            if chunk.is_empty() {
                break;
            }

            if sender.is_disconnected() {
                anyhow::bail!(
                    "Download: unpack finished but `{}` bytes were remaining",
                    chunk.len()
                );
            }

            sender.send_async(chunk.to_vec()).await.with_context(|| {
                format!("Download: could not write {} bytes to stream.", chunk.len())
            })?;
            downloaded_bytes += chunk.len() as u64;
            let event = download_event_type.build_download_progress_event(downloaded_bytes, size);
            self.feedback_sender.send_event(event).await;
        }

        self.feedback_sender
            .send_event(download_event_type.build_download_completed_event())
            .await;

        Ok(())
    }

    fn unpack_file(
        stream: Receiver<Vec<u8>>,
        compression_algorithm: Option<CompressionAlgorithm>,
        unpack_dir: &Path,
        download_id: String,
    ) -> StdResult<()> {
        let input = StreamReader::new(stream);
        match compression_algorithm {
            Some(CompressionAlgorithm::Zstandard) => {
                let zstandard_decoder = zstd::Decoder::new(input)
                    .with_context(|| "Unpack failed: Create Zstandard decoder error")?;
                let mut file_archive = Archive::new(zstandard_decoder);
                file_archive.unpack(unpack_dir).with_context(|| {
                    format!(
                        "Could not unpack with 'Zstd' from streamed data to directory '{}'",
                        unpack_dir.display()
                    )
                })?;
            }
            None => {
                let file_path = unpack_dir.join(download_id);
                if file_path.exists() {
                    std::fs::remove_file(file_path.clone())?;
                }
                let mut file = std::fs::File::create(file_path)?;
                let mut input_buffered = BufReader::new(input);
                io::copy(&mut input_buffered, &mut file)?;
                file.flush()?;
            }
        };

        Ok(())
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
        if !target_dir.is_dir() {
            Err(
                anyhow!("target path is not a directory or does not exist: `{target_dir:?}`")
                    .context("Download-Unpack: prerequisite error"),
            )?;
        }

        let (sender, receiver) = flume::bounded(32);
        let dest_dir = target_dir.to_path_buf();
        let download_id = download_event_type.download_id().to_owned();
        let unpack_thread = tokio::task::spawn_blocking(move || -> StdResult<()> {
            Self::unpack_file(receiver, compression_algorithm, &dest_dir, download_id)
        });
        if let Some(local_path) = Self::file_scheme_to_local_path(location.as_str()) {
            self.download_local_file(&local_path, &sender, download_event_type, file_size)
                .await?;
        } else {
            self.download_remote_file(location.as_str(), &sender, download_event_type, file_size)
                .await?;
        }
        drop(sender);
        unpack_thread
            .await
            .with_context(|| {
                format!(
                    "Unpack: panic while unpacking to dir '{}'",
                    target_dir.display()
                )
            })?
            .with_context(|| {
                format!("Unpack: could not unpack to dir '{}'", target_dir.display())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn downloading_http_file_handle_early_unpack_receiver_closure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/snapshot.tar");
            then.status(200).body("a");
        });
        let http_file_downloader =
            HttpFileDownloader::new(FeedbackSender::new(&[]), TestLogger::stdout()).unwrap();
        let download_id = "id".to_string();
        let (tx, rx) = flume::bounded(1);

        // Simulate an unpack task end by dropping the receiver immediately, the download task should stop without error
        drop(rx);

        let error = http_file_downloader
            .download_remote_file(
                &server.url("/snapshot.tar"),
                &tx,
                DownloadEvent::Digest {
                    download_id: download_id.clone(),
                },
                0,
            )
            .await
            .unwrap_err();

        let expected_error = "Download: unpack finished but `1` bytes were remaining";
        assert!(
            error.to_string().contains(expected_error),
            "Expected error to contains `{expected_error}` but got: `{error:?}`"
        );
    }

    #[tokio::test]
    async fn downloading_local_file_handle_early_unpack_receiver_closure() {
        let target_dir = temp_dir_create!();
        let source_file_path = target_dir.join("snapshot.txt");
        let _file = std::fs::File::create(&source_file_path).unwrap();

        let http_file_downloader =
            HttpFileDownloader::new(FeedbackSender::new(&[]), TestLogger::stdout()).unwrap();
        let download_id = "id".to_string();
        let (tx, rx) = flume::bounded(1);

        // Simulate an unpack task end by dropping the receiver immediately, the download task should stop without error
        drop(rx);

        let download_result = http_file_downloader
            .download_local_file(
                &source_file_path.to_string_lossy(),
                &tx,
                DownloadEvent::Digest {
                    download_id: download_id.clone(),
                },
                0,
            )
            .await;

        assert!(
            download_result.is_ok(),
            "Remote download failed: {download_result:?}"
        );
    }
}
