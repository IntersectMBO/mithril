use std::{
    io::{self, BufReader, Write},
    path::Path,
};

use anyhow::Context;
use flume::{Receiver, Sender};
use futures::stream::{BoxStream, StreamExt};
use tar::Archive;

use mithril_common::StdResult;

use crate::common::CompressionAlgorithm;
use crate::feedback::FeedbackSender;
use crate::utils::StreamReader;

use super::interface::DownloadEvent;

/// A byte stream to download, together with its best-known total size.
///
/// The size is only used to report download progress through [feedback
/// events][crate::feedback::FeedbackReceiver]: an inaccurate value degrades the reported
/// progress but does not affect the download itself.
pub(super) struct DownloadedStream {
    pub stream: BoxStream<'static, StdResult<Vec<u8>>>,
    pub size: u64,
}

/// Stream an already opened [DownloadedStream] to `target_dir`, unpacking it on the fly and
/// reporting progress through `feedback_sender`.
///
/// This is the engine shared by every [FileDownloader][super::FileDownloader] implementation.
/// Each implementation is only responsible for opening a [DownloadedStream] for a given
/// location (an HTTP GET, a local file read, a Kubo `block/get` request…); this function takes
/// care of streaming it to disk, unpacking it if needed, and reporting progress along the way.
pub(super) async fn download_unpack(
    feedback_sender: &FeedbackSender,
    downloaded: DownloadedStream,
    target_dir: &Path,
    compression_algorithm: Option<CompressionAlgorithm>,
    download_event_type: DownloadEvent,
) -> StdResult<()> {
    if !target_dir.is_dir() {
        Err(
            anyhow::anyhow!("target path is not a directory or does not exist: `{target_dir:?}`")
                .context("Download-Unpack: prerequisite error"),
        )?;
    }

    let (sender, receiver) = flume::bounded(32);
    let dest_dir = target_dir.to_path_buf();
    let download_id = download_event_type.download_id().to_owned();
    let unpack_thread = tokio::task::spawn_blocking(move || -> StdResult<()> {
        unpack_file(receiver, compression_algorithm, &dest_dir, download_id)
    });

    stream_to_channel(feedback_sender, downloaded, &sender, download_event_type).await?;
    drop(sender);

    unpack_thread
        .await
        .with_context(|| {
            format!(
                "Unpack: panic while unpacking to dir '{}'",
                target_dir.display()
            )
        })?
        .with_context(|| format!("Unpack: could not unpack to dir '{}'", target_dir.display()))?;

    Ok(())
}

/// Drain `downloaded` into `sender`, reporting start/progress/completed feedback events.
async fn stream_to_channel(
    feedback_sender: &FeedbackSender,
    downloaded: DownloadedStream,
    sender: &Sender<Vec<u8>>,
    download_event_type: DownloadEvent,
) -> StdResult<()> {
    let DownloadedStream { mut stream, size } = downloaded;
    let mut downloaded_bytes: u64 = 0;

    feedback_sender
        .send_event(download_event_type.build_download_started_event(size))
        .await;

    while let Some(item) = stream.next().await {
        let chunk = item.with_context(|| "Download: could not read from byte stream")?;

        if chunk.is_empty() {
            break;
        }

        if sender.is_disconnected() {
            anyhow::bail!(
                "Download: unpack finished but `{}` bytes were remaining",
                chunk.len()
            );
        }

        let chunk_len = chunk.len();
        sender
            .send_async(chunk)
            .await
            .with_context(|| format!("Download: could not write {chunk_len} bytes to stream."))?;
        downloaded_bytes += chunk_len as u64;
        let event = download_event_type.build_download_progress_event(downloaded_bytes, size);
        feedback_sender.send_event(event).await;
    }

    feedback_sender
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::stream;
    use mithril_common::temp_dir_create;

    use crate::feedback::{FeedbackReceiver, StackFeedbackReceiver};

    use super::*;

    fn synthetic_stream(chunks: Vec<&'static [u8]>) -> BoxStream<'static, StdResult<Vec<u8>>> {
        stream::iter(chunks.into_iter().map(|c| Ok(c.to_vec()))).boxed()
    }

    #[tokio::test]
    async fn download_unpack_sends_feedback_and_unpacks_synthetic_stream() {
        let target_dir = temp_dir_create!();
        let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
        let feedback_receiver_clone = feedback_receiver.clone() as Arc<dyn FeedbackReceiver>;
        let feedback_sender = FeedbackSender::new(&[feedback_receiver_clone]);
        let download_id = "id".to_string();
        let content = b"Hello, world!";

        download_unpack(
            &feedback_sender,
            DownloadedStream {
                stream: synthetic_stream(vec![content]),
                size: content.len() as u64,
            },
            &target_dir,
            None,
            DownloadEvent::Digest {
                download_id: download_id.clone(),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            content.to_vec(),
            std::fs::read(target_dir.join(&download_id)).unwrap()
        );
        assert_eq!(3, feedback_receiver.stacked_events().len());
    }

    #[tokio::test]
    async fn download_unpack_fails_when_target_dir_does_not_exist() {
        let feedback_sender = FeedbackSender::new(&[]);

        let error = download_unpack(
            &feedback_sender,
            DownloadedStream {
                stream: synthetic_stream(vec![b"a"]),
                size: 1,
            },
            Path::new("/does/not/exist"),
            None,
            DownloadEvent::Digest {
                download_id: "id".to_string(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("Download-Unpack: prerequisite error"),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn stream_to_channel_handles_early_unpack_receiver_closure() {
        let feedback_sender = FeedbackSender::new(&[]);
        let (tx, rx) = flume::bounded(1);
        // Simulate the unpack thread ending early by dropping the receiver immediately: the
        // streaming loop should stop with an explicit error instead of hanging.
        drop(rx);

        let error = stream_to_channel(
            &feedback_sender,
            DownloadedStream {
                stream: synthetic_stream(vec![b"a"]),
                size: 1,
            },
            &tx,
            DownloadEvent::Digest {
                download_id: "id".to_string(),
            },
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
    async fn stream_to_channel_propagates_stream_errors() {
        let feedback_sender = FeedbackSender::new(&[]);
        let (tx, _rx) = flume::bounded(1);
        let failing_stream: BoxStream<'static, StdResult<Vec<u8>>> =
            stream::iter(vec![Err(anyhow::anyhow!("boom"))]).boxed();

        let error = stream_to_channel(
            &feedback_sender,
            DownloadedStream {
                stream: failing_stream,
                size: 1,
            },
            &tx,
            DownloadEvent::Digest {
                download_id: "id".to_string(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Download: could not read from byte stream"),
            "unexpected error: {error:?}"
        );
    }
}
