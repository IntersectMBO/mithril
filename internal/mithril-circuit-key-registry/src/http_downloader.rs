//! Bounded HTTP download of the documents involved in the circuit verification key registry
//! retrieval.

use std::error::Error;

use anyhow::{Context, anyhow};
use futures::{Stream, StreamExt};
use reqwest::Url;

use mithril_common::StdResult;

/// Maximum number of attempts of a download.
pub const DOWNLOAD_MAX_ATTEMPTS: usize = 3;

/// Maximum size in bytes of a downloaded document, the memory bound on the documents served by
/// the untrusted routing URLs.
pub const DOWNLOAD_MAX_BODY_SIZE_IN_BYTES: u64 = 1024 * 1024;

#[cfg(not(target_family = "wasm"))]
const DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS: u64 = 1000;

#[cfg(not(target_family = "wasm"))]
const DOWNLOAD_TIMEOUT_IN_SECONDS: u64 = 10;

/// HTTP downloader bounding the request duration and the response size, and retrying failed
/// attempts.
pub struct BoundedHttpDownloader {
    /// HTTP client of the downloads.
    client: reqwest::Client,

    /// Whether a response served over plain HTTP is refused.
    https_only: bool,
}

impl BoundedHttpDownloader {
    /// Build a downloader with a request timeout, so a hung download cannot stall certificate
    /// verification, restricted to HTTPS so a redirect cannot downgrade a download to plain HTTP.
    #[cfg(not(target_family = "wasm"))]
    pub fn new() -> StdResult<Self> {
        Self::build(true)
    }

    /// Build a downloader also accepting plain HTTP, for local development and tests served by a
    /// plain HTTP server: never use it in production.
    #[cfg(not(target_family = "wasm"))]
    pub fn new_allowing_plain_http() -> StdResult<Self> {
        Self::build(false)
    }

    /// Build a downloader with a request timeout, restricted to HTTPS when required.
    #[cfg(not(target_family = "wasm"))]
    fn build(https_only: bool) -> StdResult<Self> {
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_IN_SECONDS))
            .build()
            .with_context(|| "Failed to build the HTTP client of the registry downloader")?;

        Ok(Self { client, https_only })
    }

    /// Build a downloader relying on the browser to bound the request duration, as the request
    /// timeout builder is not available on WASM, and refusing a response served over plain HTTP,
    /// as the HTTPS only builder is not available either.
    #[cfg(target_family = "wasm")]
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            https_only: true,
        })
    }

    /// Download the document at the given URL, retrying failed attempts up to
    /// [DOWNLOAD_MAX_ATTEMPTS] times.
    pub async fn download_with_retry(&self, url: &str) -> StdResult<String> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.download(url).await {
                Ok(document) => return Ok(document),
                Err(_) if attempts < DOWNLOAD_MAX_ATTEMPTS => Self::wait_before_retry().await,
                Err(error) => {
                    return Err(error.context(format!(
                        "Failed to download '{url}' after {DOWNLOAD_MAX_ATTEMPTS} attempts"
                    )));
                }
            }
        }
    }

    /// Download the document at the given URL, failing on a non success status or a response
    /// exceeding the size limit, which is enforced while the body is read so an oversized body
    /// is never buffered.
    async fn download(&self, url: &str) -> StdResult<String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to download '{url}'"))?;
        if self.https_only {
            Self::check_response_url_is_https(url, response.url())?;
        }
        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download '{url}': status {}",
                response.status()
            ));
        }
        Self::check_size_limit(url, response.content_length().unwrap_or_default())?;
        let body = Self::read_body_within_size_limit(url, response.bytes_stream()).await?;

        String::from_utf8(body).with_context(|| format!("The response of '{url}' is not UTF-8"))
    }

    /// Read the body chunks of the response of the URL, failing as soon as the bytes read exceed
    /// [DOWNLOAD_MAX_BODY_SIZE_IN_BYTES].
    async fn read_body_within_size_limit<B: AsRef<[u8]>, E: Error + Send + Sync + 'static>(
        url: &str,
        mut chunks: impl Stream<Item = Result<B, E>> + Unpin,
    ) -> StdResult<Vec<u8>> {
        let mut body = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.with_context(|| format!("Failed to read the response of '{url}'"))?;
            Self::check_size_limit(url, (body.len() + chunk.as_ref().len()) as u64)?;
            body.extend_from_slice(chunk.as_ref());
        }

        Ok(body)
    }

    /// Fail when the response was served over plain HTTP, so a redirect cannot downgrade a
    /// download where the client cannot restrict the scheme itself.
    fn check_response_url_is_https(url: &str, response_url: &Url) -> StdResult<()> {
        if response_url.scheme() != "https" {
            return Err(anyhow!(
                "Failed to download '{url}': the response served from '{response_url}' is not over HTTPS"
            ));
        }

        Ok(())
    }

    /// Fail when the response size exceeds [DOWNLOAD_MAX_BODY_SIZE_IN_BYTES].
    fn check_size_limit(url: &str, size_in_bytes: u64) -> StdResult<()> {
        if size_in_bytes > DOWNLOAD_MAX_BODY_SIZE_IN_BYTES {
            return Err(anyhow!(
                "Failed to download '{url}': response of {size_in_bytes} bytes exceeds the {DOWNLOAD_MAX_BODY_SIZE_IN_BYTES} bytes limit"
            ));
        }

        Ok(())
    }

    /// Wait for [DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS] before the next download attempt.
    #[cfg(not(target_family = "wasm"))]
    async fn wait_before_retry() {
        tokio::time::sleep(std::time::Duration::from_millis(
            DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS,
        ))
        .await;
    }

    /// Retry immediately: no timer is available on WASM.
    #[cfg(target_family = "wasm")]
    async fn wait_before_retry() {}
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use futures::stream;
    use httpmock::{Method, MockServer};

    use super::*;

    #[tokio::test]
    async fn downloads_a_document() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::GET).path("/document");
            then.status(200).body("the document");
        });

        let document = BoundedHttpDownloader::new_allowing_plain_http()
            .unwrap()
            .download_with_retry(&server.url("/document"))
            .await
            .unwrap();

        assert_eq!("the document", document);
    }

    #[tokio::test]
    async fn refuses_to_download_over_plain_http() {
        let server = MockServer::start();
        let document = server.mock(|when, then| {
            when.method(Method::GET).path("/document");
            then.status(200).body("the document");
        });

        BoundedHttpDownloader::new()
            .unwrap()
            .download_with_retry(&server.url("/document"))
            .await
            .expect_err("a download over plain HTTP must be refused");

        assert_eq!(0, document.calls());
    }

    #[test]
    fn accepts_a_response_served_over_https() {
        BoundedHttpDownloader::check_response_url_is_https(
            "https://example.com/document",
            &Url::parse("https://example.com/redirected-document").unwrap(),
        )
        .expect("a response served over HTTPS must be accepted");
    }

    #[test]
    fn refuses_a_response_served_over_plain_http() {
        BoundedHttpDownloader::check_response_url_is_https(
            "https://example.com/document",
            &Url::parse("http://example.com/redirected-document").unwrap(),
        )
        .expect_err("a response served over plain HTTP must be refused");
    }

    #[tokio::test]
    async fn fails_on_a_response_declaring_a_length_exceeding_the_body_size_limit() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::GET).path("/document");
            then.status(200)
                .body(" ".repeat(DOWNLOAD_MAX_BODY_SIZE_IN_BYTES as usize + 1));
        });

        BoundedHttpDownloader::new_allowing_plain_http()
            .unwrap()
            .download_with_retry(&server.url("/document"))
            .await
            .expect_err("an oversized response must fail the download");
    }

    #[tokio::test]
    async fn reads_the_body_chunks_within_the_size_limit() {
        let chunks =
            stream::iter([Ok::<_, reqwest::Error>(b"the ".to_vec()), Ok(b"document".to_vec())]);

        let body = BoundedHttpDownloader::read_body_within_size_limit(
            "https://example.com/document",
            chunks,
        )
        .await
        .unwrap();

        assert_eq!(b"the document".to_vec(), body);
    }

    #[tokio::test]
    async fn fails_on_body_chunks_exceeding_the_size_limit_after_the_first_one() {
        let chunks = stream::iter([
            Ok::<_, reqwest::Error>(vec![b' '; DOWNLOAD_MAX_BODY_SIZE_IN_BYTES as usize]),
            Ok(vec![b' ']),
        ]);

        BoundedHttpDownloader::read_body_within_size_limit("https://example.com/document", chunks)
            .await
            .expect_err("body chunks exceeding the size limit must fail the download");
    }

    #[tokio::test]
    async fn retries_a_failed_download_up_to_the_maximum_attempts() {
        let server = MockServer::start();
        let failing_document = server.mock(|when, then| {
            when.method(Method::GET).path("/document");
            then.status(500);
        });

        BoundedHttpDownloader::new_allowing_plain_http()
            .unwrap()
            .download_with_retry(&server.url("/document"))
            .await
            .expect_err("a persistently failing download must fail");

        assert_eq!(DOWNLOAD_MAX_ATTEMPTS, failing_document.calls());
    }
}
