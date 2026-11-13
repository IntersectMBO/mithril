use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use reqwest::Url;
use sha2::{Digest, Sha256};

use mithril_client::MithrilResult;

use crate::utils::{ArchiveUnpacker, GitHubReleaseRetriever, HttpDownloader};

use super::{KUBO_GITHUB_OWNER, KUBO_GITHUB_REPOSITORY, KUBO_VERSION, KuboDistribution};

/// Provides the Kubo binary of a [KuboDistribution], downloading it from the Kubo GitHub release
/// if it is not already installed in the install directory.
pub struct KuboBinaryProvider {
    install_dir: PathBuf,
    distribution: KuboDistribution,
    github_release_retriever: Arc<dyn GitHubReleaseRetriever + Send + Sync>,
    http_downloader: Arc<dyn HttpDownloader + Send + Sync>,
}

impl KuboBinaryProvider {
    /// Constructs a new `KuboBinaryProvider`.
    pub fn new(
        install_dir: PathBuf,
        distribution: KuboDistribution,
        github_release_retriever: Arc<dyn GitHubReleaseRetriever + Send + Sync>,
        http_downloader: Arc<dyn HttpDownloader + Send + Sync>,
    ) -> Self {
        Self {
            install_dir,
            distribution,
            github_release_retriever,
            http_downloader,
        }
    }

    /// Default install directory of the Kubo binary, in the cache directory of the user.
    pub fn default_install_dir() -> MithrilResult<PathBuf> {
        let cache_dir =
            dirs::cache_dir().with_context(|| "Could not find the cache directory of the user")?;

        Ok(cache_dir.join("mithril").join("kubo").join(KUBO_VERSION))
    }

    /// Get the path of the Kubo binary, downloading and installing it if needed.
    ///
    /// The install is serialized between clients with a lock file next to the install
    /// directory. The release asset is downloaded and unpacked in a staging directory, also
    /// next to the install directory, that is renamed to the install directory once the
    /// checksum is verified, so the install directory never holds a partially installed binary.
    pub async fn provide(&self) -> MithrilResult<PathBuf> {
        let binary_path = self.install_dir.join(self.distribution.binary_path_in_archive);
        if binary_path.is_file() {
            return Ok(binary_path);
        }

        let _install_lock = self.acquire_install_lock().await?;
        // The binary may have been installed by another client while waiting for the lock
        if binary_path.is_file() {
            return Ok(binary_path);
        }

        let staging_dir = self.sibling_path("staging")?;
        // Leftovers of an interrupted install
        for dir in [&staging_dir, &self.install_dir] {
            if dir.exists() {
                fs::remove_dir_all(dir).with_context(|| {
                    format!(
                        "Could not remove the leftover Kubo directory '{}'",
                        dir.display()
                    )
                })?;
            }
        }

        let install_result = self.download_and_unpack(&staging_dir).await.and_then(|_| {
            fs::rename(&staging_dir, &self.install_dir).with_context(|| {
                format!(
                    "Could not move the Kubo staging directory '{}' to '{}'",
                    staging_dir.display(),
                    self.install_dir.display()
                )
            })
        });

        if let Err(error) = install_result {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }

        Ok(binary_path)
    }

    /// Path next to the install directory, named after it with the given suffix
    fn sibling_path(&self, suffix: &str) -> MithrilResult<PathBuf> {
        let install_dir_name = self
            .install_dir
            .file_name()
            .with_context(|| {
                format!(
                    "Invalid Kubo install directory '{}'",
                    self.install_dir.display()
                )
            })?
            .to_string_lossy();

        Ok(self
            .install_dir
            .with_file_name(format!("{install_dir_name}.{suffix}")))
    }

    /// Wait for the exclusive lock of the install, released when the returned file is dropped.
    async fn acquire_install_lock(&self) -> MithrilResult<File> {
        let lock_path = self.sibling_path("lock")?;
        if let Some(parent_dir) = lock_path.parent() {
            fs::create_dir_all(parent_dir).with_context(|| {
                format!(
                    "Could not create the Kubo cache directory '{}'",
                    parent_dir.display()
                )
            })?;
        }
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| {
                format!(
                    "Could not open the Kubo install lock file '{}'",
                    lock_path.display()
                )
            })?;

        tokio::task::spawn_blocking(move || lock_file.lock().map(|_| lock_file))
            .await?
            .with_context(|| {
                format!(
                    "Could not lock the Kubo install lock file '{}'",
                    lock_path.display()
                )
            })
    }

    async fn download_and_unpack(&self, staging_dir: &Path) -> MithrilResult<()> {
        fs::create_dir_all(staging_dir).with_context(|| {
            format!(
                "Could not create the Kubo staging directory '{}'",
                staging_dir.display()
            )
        })?;

        let release = self
            .github_release_retriever
            .get_release_by_tag(KUBO_GITHUB_OWNER, KUBO_GITHUB_REPOSITORY, KUBO_VERSION)
            .await
            .with_context(|| format!("Could not retrieve the Kubo {KUBO_VERSION} release"))?;
        let asset_name = &self.distribution.asset_name;
        let asset = release
            .assets
            .iter()
            .find(|asset| &asset.name == asset_name)
            .with_context(|| {
                format!("No asset '{asset_name}' in the Kubo {KUBO_VERSION} release")
            })?;
        let asset_url = Url::parse(&asset.browser_download_url).with_context(|| {
            format!(
                "Invalid download URL of the Kubo asset '{asset_name}': '{}'",
                asset.browser_download_url
            )
        })?;

        let archive_path = self
            .http_downloader
            .download_file(asset_url, staging_dir, asset_name)
            .await
            .with_context(|| format!("Could not download the Kubo asset '{asset_name}'"))?;
        Self::verify_sha256(&archive_path, &self.distribution.sha256)?;
        ArchiveUnpacker::default().unpack(&archive_path, staging_dir)?;
        fs::remove_file(&archive_path)?;

        Ok(())
    }

    fn verify_sha256(file_path: &Path, expected_sha256: &str) -> MithrilResult<()> {
        let content = fs::read(file_path)
            .with_context(|| format!("Could not read the file '{}'", file_path.display()))?;
        let actual_sha256 = hex::encode(Sha256::digest(content));

        if actual_sha256 != expected_sha256 {
            return Err(anyhow!(
                "Invalid checksum of '{}': expected SHA-256 '{expected_sha256}', got '{actual_sha256}'",
                file_path.display()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    use mithril_common::temp_dir_create;

    use crate::utils::{
        GitHubAsset, GitHubRelease, MockGitHubReleaseRetriever, MockHttpDownloader,
    };

    use super::*;

    const FAKE_BINARY_CONTENT: &[u8] = b"fake kubo binary";
    const INVALID_ARCHIVE: &[u8] = b"not an archive";
    const WRONG_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ASSET_NAME: &str = "kubo_v0.43.1_linux-amd64.tar.gz";
    const ASSET_URL: &str =
        "https://github.com/ipfs/kubo/releases/download/v0.43.1/kubo_v0.43.1_linux-amd64.tar.gz";

    /// Kubo like tar.gz archive holding an executable `kubo/ipfs`
    fn fake_kubo_archive() -> Vec<u8> {
        let mut tar_builder = Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut header = Header::new_gnu();
        header.set_size(FAKE_BINARY_CONTENT.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "kubo/ipfs", FAKE_BINARY_CONTENT)
            .unwrap();

        tar_builder.into_inner().unwrap().finish().unwrap()
    }

    fn sha256(content: &[u8]) -> String {
        hex::encode(Sha256::digest(content))
    }

    fn distribution(sha256: &str) -> KuboDistribution {
        KuboDistribution {
            asset_name: ASSET_NAME.to_string(),
            sha256: sha256.to_string(),
            binary_path_in_archive: "kubo/ipfs",
        }
    }

    fn github_release_retriever_returning(asset_names: &[&str]) -> MockGitHubReleaseRetriever {
        let release = GitHubRelease {
            assets: asset_names
                .iter()
                .map(|name| GitHubAsset {
                    name: name.to_string(),
                    browser_download_url: format!(
                        "https://github.com/ipfs/kubo/releases/download/v0.43.1/{name}"
                    ),
                })
                .collect(),
            ..GitHubRelease::default()
        };
        let mut retriever = MockGitHubReleaseRetriever::new();
        retriever
            .expect_get_release_by_tag()
            .withf(|owner, repo, tag| owner == "ipfs" && repo == "kubo" && tag == KUBO_VERSION)
            .returning(move |_, _, _| Ok(release.clone()))
            .once();
        retriever
    }

    /// Provider installing in `cache_dir`, whose download of the release asset serves
    /// `asset_content`, expecting the given `sha256`
    fn provider_downloading(
        cache_dir: &Path,
        asset_content: Vec<u8>,
        sha256: &str,
    ) -> KuboBinaryProvider {
        let mut http_downloader = MockHttpDownloader::new();
        http_downloader
            .expect_download_file()
            .withf(|url, _, filename| url.as_str() == ASSET_URL && filename == ASSET_NAME)
            .returning(move |_, download_dir, filename| {
                let downloaded_file = download_dir.join(filename);
                fs::File::create(&downloaded_file)?.write_all(&asset_content)?;
                Ok(downloaded_file)
            })
            .once();

        KuboBinaryProvider::new(
            cache_dir.join("v0.43.1"),
            distribution(sha256),
            Arc::new(github_release_retriever_returning(&[
                "kubo_v0.43.1_darwin-arm64.tar.gz",
                ASSET_NAME,
            ])),
            Arc::new(http_downloader),
        )
    }

    /// Provider installing in `cache_dir`, whose mocks fail the test if a download is attempted
    fn provider_without_download(cache_dir: &Path) -> KuboBinaryProvider {
        KuboBinaryProvider::new(
            cache_dir.join("v0.43.1"),
            distribution("whatever"),
            Arc::new(MockGitHubReleaseRetriever::new()),
            Arc::new(MockHttpDownloader::new()),
        )
    }

    fn install_binary(install_dir: &Path, content: &str) {
        fs::create_dir_all(install_dir.join("kubo")).unwrap();
        fs::write(install_dir.join("kubo/ipfs"), content).unwrap();
    }

    fn list_dir(dir: &Path) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        entries.sort();
        entries
    }

    #[test]
    fn default_install_dir_is_in_the_user_cache_dir() {
        let install_dir = KuboBinaryProvider::default_install_dir().unwrap();

        assert_eq!(
            dirs::cache_dir().unwrap().join("mithril/kubo/v0.43.1"),
            install_dir
        );
    }

    #[tokio::test]
    async fn returns_the_installed_binary_without_downloading_it() {
        let cache_dir = temp_dir_create!();
        install_binary(&cache_dir.join("v0.43.1"), "installed binary");
        let provider = provider_without_download(&cache_dir);

        let binary_path = provider.provide().await.unwrap();

        assert_eq!(cache_dir.join("v0.43.1/kubo/ipfs"), binary_path);
        assert_eq!("installed binary", fs::read_to_string(binary_path).unwrap());
    }

    #[tokio::test]
    async fn downloads_and_installs_the_binary_when_not_installed() {
        let cache_dir = temp_dir_create!();
        let archive = fake_kubo_archive();
        let provider = provider_downloading(&cache_dir, archive.clone(), &sha256(&archive));

        let binary_path = provider.provide().await.unwrap();

        assert_eq!(cache_dir.join("v0.43.1/kubo/ipfs"), binary_path);
        assert_eq!(FAKE_BINARY_CONTENT, fs::read(&binary_path).unwrap());
        assert_eq!(list_dir(&cache_dir), vec!["v0.43.1", "v0.43.1.lock"]);
        assert_eq!(list_dir(&cache_dir.join("v0.43.1")), vec!["kubo"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installed_binary_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let cache_dir = temp_dir_create!();
        let archive = fake_kubo_archive();
        let provider = provider_downloading(&cache_dir, archive.clone(), &sha256(&archive));

        let binary_path = provider.provide().await.unwrap();

        let mode = fs::metadata(binary_path).unwrap().permissions().mode();
        assert_eq!(
            0o100,
            mode & 0o100,
            "Binary should be executable, mode: {mode:o}"
        );
    }

    #[tokio::test]
    async fn removes_the_leftovers_of_an_interrupted_install() {
        let cache_dir = temp_dir_create!();
        fs::create_dir_all(cache_dir.join("v0.43.1.staging/kubo")).unwrap();
        fs::write(cache_dir.join("v0.43.1.staging/kubo/partial"), "partial").unwrap();
        fs::create_dir_all(cache_dir.join("v0.43.1/kubo")).unwrap();
        fs::write(cache_dir.join("v0.43.1/kubo/README.md"), "left over").unwrap();
        let archive = fake_kubo_archive();
        let provider = provider_downloading(&cache_dir, archive.clone(), &sha256(&archive));

        let binary_path = provider.provide().await.unwrap();

        assert_eq!(FAKE_BINARY_CONTENT, fs::read(&binary_path).unwrap());
        assert_eq!(list_dir(&cache_dir), vec!["v0.43.1", "v0.43.1.lock"]);
        assert_eq!(list_dir(&cache_dir.join("v0.43.1/kubo")), vec!["ipfs"]);
    }

    #[tokio::test]
    async fn verifies_the_checksum_before_unpacking_and_installs_nothing_on_mismatch() {
        let cache_dir = temp_dir_create!();
        let provider = provider_downloading(&cache_dir, INVALID_ARCHIVE.to_vec(), WRONG_SHA256);

        let error = provider
            .provide()
            .await
            .expect_err("Should fail on a checksum mismatch");

        // Unpacking first would have failed with an unpack error instead
        assert!(
            format!("{error:?}").contains("Invalid checksum"),
            "Unexpected error: {error:?}"
        );
        assert_eq!(list_dir(&cache_dir), vec!["v0.43.1.lock"]);
    }

    #[tokio::test]
    async fn cleans_up_and_installs_nothing_when_the_unpack_fails() {
        let cache_dir = temp_dir_create!();
        let provider = provider_downloading(
            &cache_dir,
            INVALID_ARCHIVE.to_vec(),
            &sha256(INVALID_ARCHIVE),
        );

        provider
            .provide()
            .await
            .expect_err("Should fail when the unpack fails");

        assert_eq!(list_dir(&cache_dir), vec!["v0.43.1.lock"]);
    }

    #[tokio::test]
    async fn cleans_up_and_installs_nothing_when_the_download_fails() {
        let cache_dir = temp_dir_create!();
        let mut http_downloader = MockHttpDownloader::new();
        http_downloader
            .expect_download_file()
            .returning(|_, _, _| Err(anyhow!("download failure")))
            .once();
        let provider = KuboBinaryProvider::new(
            cache_dir.join("v0.43.1"),
            distribution("whatever"),
            Arc::new(github_release_retriever_returning(&[ASSET_NAME])),
            Arc::new(http_downloader),
        );

        provider
            .provide()
            .await
            .expect_err("Should fail when the download fails");

        assert_eq!(list_dir(&cache_dir), vec!["v0.43.1.lock"]);
    }

    #[tokio::test]
    async fn fails_when_the_release_has_no_asset_for_the_distribution() {
        let cache_dir = temp_dir_create!();
        let provider = KuboBinaryProvider::new(
            cache_dir.join("v0.43.1"),
            distribution("whatever"),
            Arc::new(github_release_retriever_returning(&[
                "kubo_v0.43.1_darwin-arm64.tar.gz",
            ])),
            Arc::new(MockHttpDownloader::new()),
        );

        let error = provider
            .provide()
            .await
            .expect_err("Should fail when the asset is missing");

        assert!(
            format!("{error:?}").contains(ASSET_NAME),
            "Unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn waits_for_a_concurrent_install_and_returns_its_binary() {
        let cache_dir = temp_dir_create!();
        // Lock held by a concurrent client installing the binary
        let concurrent_lock = fs::File::create(cache_dir.join("v0.43.1.lock")).unwrap();
        concurrent_lock.lock().unwrap();
        let provider = provider_without_download(&cache_dir);

        let provide_task = tokio::spawn(async move { provider.provide().await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !provide_task.is_finished(),
            "provide should wait for the lock of the concurrent install"
        );
        install_binary(&cache_dir.join("v0.43.1"), "concurrently installed");
        concurrent_lock.unlock().unwrap();
        let binary_path = provide_task.await.unwrap().unwrap();

        assert_eq!(
            "concurrently installed",
            fs::read_to_string(binary_path).unwrap()
        );
    }
}
