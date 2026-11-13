use std::{
    io::{self, BufReader, Write},
    path::Path,
};

use anyhow::Context;
use flume::{Receiver, Sender};
use futures::stream::{BoxStream, StreamExt};

use mithril_common::StdResult;

use crate::common::CompressionAlgorithm;
use crate::feedback::FeedbackSender;
use crate::utils::StreamReader;

use super::archive_unpacker::{TarArchiveUnpacker, UnpackedFilePermissions};
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

    let streamed =
        stream_to_channel(feedback_sender, downloaded, &sender, download_event_type).await;
    drop(sender);
    let unpacked = unpack_thread.await.with_context(|| {
        format!(
            "Unpack: panic while unpacking to dir '{}'",
            target_dir.display()
        )
    })?;

    match (streamed, unpacked) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(unpack_error)) => Err(unpack_error)
            .with_context(|| format!("Unpack: could not unpack to dir '{}'", target_dir.display())),
        (Err(stream_error), Ok(())) => Err(stream_error),
        (Err(stream_error), Err(unpack_error)) => Err(unpack_error).with_context(|| {
            format!(
                "Unpack: could not unpack to dir '{}', the download failed too: {stream_error:#}",
                target_dir.display()
            )
        }),
    }
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

/// Unpacker of the database archives: every unpacked file is a data file that its owner can read
/// and write, never executable, never writable by others.
const DATABASE_FILES_UNPACKER: TarArchiveUnpacker =
    TarArchiveUnpacker::new(UnpackedFilePermissions::Fixed(0o644));

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
            DATABASE_FILES_UNPACKER
                .unpack(zstandard_decoder, unpack_dir)
                .with_context(|| {
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
    use std::fs;
    use std::sync::Arc;

    use futures::stream;
    use tar::{Builder, EntryType, Header};

    use mithril_common::temp_dir_create;

    use crate::feedback::{FeedbackReceiver, StackFeedbackReceiver};
    use crate::file_downloader::archive_unpacker::ArchiveEntryRejection;

    use super::*;

    /// Payload size large enough to keep the stream longer than the channel between the download
    /// and the unpack thread.
    const STREAMED_PAYLOAD_SIZE: u32 = 1 << 20;

    /// Bytes that a compressor can not shrink, so that the compressed stream keeps its size.
    fn incompressible_payload(size_in_bytes: u32) -> Vec<u8> {
        const MULTIPLICATIVE_HASH_MULTIPLIER: u32 = 2_654_435_761;

        (0..size_in_bytes)
            .map(|index| (index.wrapping_mul(MULTIPLICATIVE_HASH_MULTIPLIER) >> 24) as u8)
            .collect()
    }

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

    #[tokio::test]
    async fn download_unpack_waits_for_the_unpack_thread_before_returning_a_stream_error() {
        let target_dir = temp_dir_create!();
        let feedback_sender = FeedbackSender::new(&[]);
        let failing_stream: BoxStream<'static, StdResult<Vec<u8>>> =
            stream::iter(vec![Ok(b"partial".to_vec()), Err(anyhow::anyhow!("boom"))]).boxed();

        let error = download_unpack(
            &feedback_sender,
            DownloadedStream {
                stream: failing_stream,
                size: 2,
            },
            &target_dir,
            None,
            DownloadEvent::Digest {
                download_id: "id".to_string(),
            },
        )
        .await
        .expect_err("the stream error must be returned");

        assert!(
            error
                .to_string()
                .contains("Download: could not read from byte stream"),
            "unexpected error: {error:?}"
        );
        assert_eq!(
            fs::read(target_dir.join("id")).unwrap(),
            b"partial",
            "the unpack thread must have written its input before the function returned"
        );
    }

    #[tokio::test]
    async fn download_unpack_reports_the_archive_rejection_reason_over_the_stream_error() {
        let target_dir = temp_dir_create!();
        let payload = incompressible_payload(STREAMED_PAYLOAD_SIZE);
        let mut archive_bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut archive_bytes);
            let mut link_header = Header::new_gnu();
            link_header.set_entry_type(EntryType::Symlink);
            link_header.set_size(0);
            link_header.set_mode(0o777);
            builder
                .append_link(&mut link_header, "link", "/outside/target")
                .unwrap();
            let mut payload_header = Header::new_gnu();
            payload_header.set_size(payload.len() as u64);
            payload_header.set_mode(0o644);
            builder
                .append_data(&mut payload_header, "payload", payload.as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let compressed = zstd::encode_all(archive_bytes.as_slice(), 1).unwrap();
        let chunks: Vec<StdResult<Vec<u8>>> =
            compressed.chunks(4096).map(|chunk| Ok(chunk.to_vec())).collect();
        let archive_stream: BoxStream<'static, StdResult<Vec<u8>>> = stream::iter(chunks).boxed();

        let error = download_unpack(
            &FeedbackSender::new(&[]),
            DownloadedStream {
                stream: archive_stream,
                size: compressed.len() as u64,
            },
            &target_dir,
            Some(CompressionAlgorithm::Zstandard),
            DownloadEvent::Digest {
                download_id: "id".to_string(),
            },
        )
        .await
        .expect_err("a rejected entry must fail the download");

        assert_eq!(
            Some(&ArchiveEntryRejection::UnexpectedEntryType(
                EntryType::Symlink
            )),
            error.downcast_ref::<ArchiveEntryRejection>(),
            "unexpected error: {error:?}"
        );
    }
}
