//! Pinned Kubo distribution downloaded by the client.
//!
//! The expected checksums are the SHA-256 digests computed by GitHub for the release assets
//! (displayed on the release page, and as the `digest` field of the GitHub API).
//!
//! # Update the Kubo version
//!
//! 1. Set the new version, then print the SHA-256 digests of the supported platforms assets:
//!
//!    ```sh
//!    KUBO_VERSION=vX.Y.Z
//!    curl -fsSL "https://api.github.com/repos/ipfs/kubo/releases/tags/$KUBO_VERSION" \
//!      | jq -r --arg filter '_(linux-amd64|linux-arm64|darwin-arm64)\.tar\.gz$|_windows-amd64\.zip$' \
//!        '.assets[] | select(.name | test($filter)) | "\(.digest | ltrimstr("sha256:"))  \(.name)"'
//!    ```
//!
//!    `curl -fsSL "https://api.github.com/..."` can be replaced with `gh api "repos/..."` to
//!    use an authenticated request.
//!
//! 2. (Optional) Download the archives and check them against both the GitHub digests and the
//!    `.sha512` files published by Kubo:
//!
//!    ```sh
//!    gh release download "$KUBO_VERSION" -R ipfs/kubo -D "kubo-$KUBO_VERSION" \
//!      -p "kubo_${KUBO_VERSION}_linux-amd64.tar.gz*" -p "kubo_${KUBO_VERSION}_linux-arm64.tar.gz*" \
//!      -p "kubo_${KUBO_VERSION}_darwin-arm64.tar.gz*" -p "kubo_${KUBO_VERSION}_windows-amd64.zip*"
//!    cd "kubo-$KUBO_VERSION" && sha512sum -c ./*.sha512 && sha256sum ./*.tar.gz ./*.zip
//!    ```
//!
//! 3. Update [KUBO_VERSION] and the checksums in [KuboDistribution::for_platform] and in the
//!    tests of this module.

use anyhow::anyhow;

use mithril_client::MithrilResult;

/// Owner of the GitHub repository of Kubo
pub const KUBO_GITHUB_OWNER: &str = "ipfs";

/// Name of the GitHub repository of Kubo
pub const KUBO_GITHUB_REPOSITORY: &str = "kubo";

/// Pinned version of Kubo downloaded by the client
pub const KUBO_VERSION: &str = "v0.43.1";

/// Kubo release archive for a platform, at the pinned [KUBO_VERSION]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KuboDistribution {
    /// Name of the release asset, e.g. `kubo_v0.43.1_linux-amd64.tar.gz`
    pub asset_name: String,
    /// Expected SHA-256 of the release asset, hex encoded
    pub sha256: String,
    /// Path of the Kubo binary inside the unpacked release asset
    pub binary_path_in_archive: &'static str,
}

impl KuboDistribution {
    /// Get the Kubo distribution of the given platform.
    ///
    /// `os` and `arch` follow the values of [std::env::consts::OS] and [std::env::consts::ARCH].
    pub fn for_platform(os: &str, arch: &str) -> MithrilResult<Self> {
        // SHA-256 digests computed by GitHub for the release assets (see the module documentation)
        let (kubo_platform, extension, sha256) = match (os, arch) {
            ("linux", "x86_64") => (
                "linux-amd64",
                "tar.gz",
                "3f2bf974ab2a3ec6d997fac7d8cb46f59983a7cddd0b55ef998e6ce379155fb2",
            ),
            ("linux", "aarch64") => (
                "linux-arm64",
                "tar.gz",
                "e09237abadd9578d7a73dd2e2b718848b78437cb56e48cc9742b23ce9ebac829",
            ),
            ("macos", "aarch64") => (
                "darwin-arm64",
                "tar.gz",
                "63ab05f578190a39aaba1e80b697644a9b717f5dc6a5485ec7a2bded68f9374f",
            ),
            ("windows", "x86_64") => (
                "windows-amd64",
                "zip",
                "c25871516dec4d97ce1d160a26c1e3fdad294cb0eea065c0c0343bcfca86c524",
            ),
            _ => {
                return Err(anyhow!(
                    "Unsupported platform for the managed Kubo node: os='{os}', arch='{arch}'"
                ));
            }
        };

        Ok(Self {
            asset_name: format!("kubo_{KUBO_VERSION}_{kubo_platform}.{extension}"),
            sha256: sha256.to_string(),
            binary_path_in_archive: if os == "windows" {
                "kubo/ipfs.exe"
            } else {
                "kubo/ipfs"
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_amd64() {
        let distribution = KuboDistribution::for_platform("linux", "x86_64").unwrap();

        assert_eq!(
            KuboDistribution {
                asset_name: "kubo_v0.43.1_linux-amd64.tar.gz".to_string(),
                sha256: "3f2bf974ab2a3ec6d997fac7d8cb46f59983a7cddd0b55ef998e6ce379155fb2"
                    .to_string(),
                binary_path_in_archive: "kubo/ipfs",
            },
            distribution
        );
    }

    #[test]
    fn linux_arm64() {
        let distribution = KuboDistribution::for_platform("linux", "aarch64").unwrap();

        assert_eq!(
            KuboDistribution {
                asset_name: "kubo_v0.43.1_linux-arm64.tar.gz".to_string(),
                sha256: "e09237abadd9578d7a73dd2e2b718848b78437cb56e48cc9742b23ce9ebac829"
                    .to_string(),
                binary_path_in_archive: "kubo/ipfs",
            },
            distribution
        );
    }

    #[test]
    fn macos_arm64() {
        let distribution = KuboDistribution::for_platform("macos", "aarch64").unwrap();

        assert_eq!(
            KuboDistribution {
                asset_name: "kubo_v0.43.1_darwin-arm64.tar.gz".to_string(),
                sha256: "63ab05f578190a39aaba1e80b697644a9b717f5dc6a5485ec7a2bded68f9374f"
                    .to_string(),
                binary_path_in_archive: "kubo/ipfs",
            },
            distribution
        );
    }

    #[test]
    fn windows_amd64() {
        let distribution = KuboDistribution::for_platform("windows", "x86_64").unwrap();

        assert_eq!(
            KuboDistribution {
                asset_name: "kubo_v0.43.1_windows-amd64.zip".to_string(),
                sha256: "c25871516dec4d97ce1d160a26c1e3fdad294cb0eea065c0c0343bcfca86c524"
                    .to_string(),
                binary_path_in_archive: "kubo/ipfs.exe",
            },
            distribution
        );
    }

    #[test]
    fn fails_for_unsupported_platforms() {
        for (os, arch) in [
            ("macos", "x86_64"),
            ("windows", "aarch64"),
            ("freebsd", "x86_64"),
            ("linux", "riscv64"),
        ] {
            KuboDistribution::for_platform(os, arch)
                .expect_err(&format!("Should fail for os='{os}', arch='{arch}'"));
        }
    }
}
