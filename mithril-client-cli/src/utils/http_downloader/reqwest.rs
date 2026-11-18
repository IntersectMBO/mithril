use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use reqwest::{Client, Url};

use mithril_client::MithrilResult;

use super::HttpDownloader;

/// Maximum duration to connect to the server
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum duration without receiving data from the server
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// [ReqwestHttpDownloader] is an implementation of the [HttpDownloader].
pub struct ReqwestHttpDownloader {
    client: Client,
}

impl ReqwestHttpDownloader {
    /// Creates a new instance of [ReqwestHttpDownloader].
    pub fn new() -> MithrilResult<Self> {
        Self::with_read_timeout(READ_TIMEOUT)
    }

    fn with_read_timeout(read_timeout: Duration) -> MithrilResult<Self> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(read_timeout)
            .build()
            .with_context(|| "Failed to build Reqwest HTTP client")?;

        Ok(Self { client })
    }
}

#[async_trait]
impl HttpDownloader for ReqwestHttpDownloader {
    async fn download_file(
        &self,
        url: Url,
        download_dir: &Path,
        filename: &str,
    ) -> MithrilResult<PathBuf> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to download file from URL: {url}"))?
            .error_for_status()
            .with_context(|| format!("Failed to download file from URL: {url}"))?;

        let bytes = response.bytes().await?;
        let download_filepath = download_dir.join(filename);
        let mut file = File::create(&download_filepath)?;
        file.write_all(&bytes)?;

        Ok(download_filepath)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use httpmock::MockServer;

    use mithril_common::temp_dir_create;

    use super::*;

    #[tokio::test]
    async fn downloads_the_file_content() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/file.bin");
            then.status(200).body("file content");
        });
        let download_dir = temp_dir_create!();

        let downloaded_file = ReqwestHttpDownloader::new()
            .unwrap()
            .download_file(
                Url::parse(&server.url("/file.bin")).unwrap(),
                &download_dir,
                "file.bin",
            )
            .await
            .unwrap();

        assert_eq!(download_dir.join("file.bin"), downloaded_file);
        assert_eq!("file content", fs::read_to_string(downloaded_file).unwrap());
    }

    #[tokio::test]
    async fn fails_without_writing_a_file_when_the_response_status_is_an_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/file.bin");
            then.status(404).body("not found page");
        });
        let download_dir = temp_dir_create!();

        let error = ReqwestHttpDownloader::new()
            .unwrap()
            .download_file(
                Url::parse(&server.url("/file.bin")).unwrap(),
                &download_dir,
                "file.bin",
            )
            .await
            .expect_err("Should fail on a 404 response");

        assert!(
            format!("{error:?}").contains("404"),
            "Unexpected error: {error:?}"
        );
        assert!(!download_dir.join("file.bin").exists());
    }

    #[tokio::test]
    async fn fails_when_the_server_does_not_send_data_within_the_read_timeout() {
        let server = MockServer::start();
        server.mock(|_, then| {
            then.delay(Duration::from_secs(2));
        });
        let download_dir = temp_dir_create!();

        let error = ReqwestHttpDownloader::with_read_timeout(Duration::from_millis(200))
            .unwrap()
            .download_file(
                Url::parse(&server.url("/file.bin")).unwrap(),
                &download_dir,
                "file.bin",
            )
            .await
            .expect_err("Should fail when the server stalls");

        assert!(
            format!("{error:?}").contains("timed out"),
            "Unexpected error: {error:?}"
        );
        assert!(!download_dir.join("file.bin").exists());
    }
}
