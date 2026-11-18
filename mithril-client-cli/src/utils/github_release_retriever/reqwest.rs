use anyhow::{Context, anyhow};
use async_trait::async_trait;
use reqwest::{Client, IntoUrl};
use serde::de::DeserializeOwned;

use mithril_client::MithrilResult;

use crate::utils::http_client_builder;

use super::{GitHubRelease, GitHubReleaseRetriever};

pub struct ReqwestGitHubApiClient {
    client: Client,
    github_token: Option<String>,
}

impl ReqwestGitHubApiClient {
    pub fn new(github_token: Option<String>) -> MithrilResult<Self> {
        let client = http_client_builder()
            .user_agent("mithril-client")
            .build()
            .context("Failed to build Reqwest GitHub API client")?;

        Ok(Self {
            client,
            github_token,
        })
    }

    async fn download<U: IntoUrl, T: DeserializeOwned>(&self, source_url: U) -> MithrilResult<T> {
        let url = source_url
            .into_url()
            .with_context(|| "Given `source_url` is not a valid Url")?;
        let mut request = self.client.get(url.clone());
        if let Some(token) = &self.github_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to send request to GitHub API: {url}"))?;
        match response.status() {
            reqwest::StatusCode::OK => {}
            status => {
                let body = response
                    .text()
                    .await
                    .with_context(|| "Failed to read response body")?;
                return Err(anyhow!(
                    "GitHub API request failed with status code '{status}': {body}",
                ));
            }
        }
        let body = response.text().await?;
        let parsed_body = serde_json::from_str::<T>(&body)
            .with_context(|| format!("Failed to parse response from GitHub API: {body:?}"))?;

        Ok(parsed_body)
    }
}

#[async_trait]
impl GitHubReleaseRetriever for ReqwestGitHubApiClient {
    async fn get_release_by_tag(
        &self,
        organization: &str,
        repository: &str,
        tag: &str,
    ) -> MithrilResult<GitHubRelease> {
        let url =
            format!("https://api.github.com/repos/{organization}/{repository}/releases/tags/{tag}");
        let release = self.download(url).await?;

        Ok(release)
    }

    async fn get_latest_release(
        &self,
        organization: &str,
        repository: &str,
    ) -> MithrilResult<GitHubRelease> {
        let url =
            format!("https://api.github.com/repos/{organization}/{repository}/releases/latest");
        let release = self.download(url).await?;

        Ok(release)
    }

    async fn get_prerelease(
        &self,
        organization: &str,
        repository: &str,
    ) -> MithrilResult<GitHubRelease> {
        let releases = self.get_all_releases(organization, repository).await?;
        let prerelease = releases
            .into_iter()
            .find(|release| release.prerelease)
            .with_context(|| "No pre-release found")?;

        Ok(prerelease)
    }

    async fn get_all_releases(
        &self,
        organization: &str,
        repository: &str,
    ) -> MithrilResult<Vec<GitHubRelease>> {
        let url = format!("https://api.github.com/repos/{organization}/{repository}/releases");
        let releases = self.download(url).await?;

        Ok(releases)
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method::GET, MockServer};
    use reqwest::StatusCode;
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct FakeApiResponse {
        key: String,
    }

    #[tokio::test]
    async fn download_succeeds_with_valid_json() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/endpoint");
            then.status(200).body(r#"{ "key": "value" }"#);
        });
        let client = ReqwestGitHubApiClient::new(None).unwrap();

        let result: FakeApiResponse = client
            .download(format!("{}/endpoint", server.base_url()))
            .await
            .unwrap();

        assert_eq!(
            result,
            FakeApiResponse {
                key: "value".into()
            }
        );
    }

    #[tokio::test]
    async fn download_fails_on_invalid_json() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/endpoint");
            then.status(200).body("this is not json");
        });
        let client = ReqwestGitHubApiClient::new(None).unwrap();

        let result: MithrilResult<FakeApiResponse> =
            client.download(format!("{}/endpoint", server.base_url())).await;

        assert!(
            result.is_err(),
            "Expected an error with invalid JSON response"
        );
    }

    #[tokio::test]
    async fn download_fails_on_invalid_url() {
        let client = ReqwestGitHubApiClient::new(None).unwrap();

        let result: MithrilResult<FakeApiResponse> = client.download("not a valid url").await;

        assert!(result.is_err(), "Expected an error for an invalid URL");
    }

    #[tokio::test]
    async fn download_fails_when_server_returns_error_and_includes_status_in_error() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/endpoint");
            then.status(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        });
        let client = ReqwestGitHubApiClient::new(None).unwrap();

        let result: MithrilResult<FakeApiResponse> =
            client.download(format!("{}/endpoint", server.base_url())).await;
        let error = result.expect_err("Expected an error due to 500 status");

        assert!(
            error
                .to_string()
                .contains(&StatusCode::INTERNAL_SERVER_ERROR.to_string())
        );
    }
}
