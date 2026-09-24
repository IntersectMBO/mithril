use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use chrono::TimeDelta;
use clap::ValueEnum;

use mithril_client::MithrilResult;
use mithril_client::certificate_client::{
    CertificateVerifierCache, CertificateVerifierCacheMode, FileCertificateVerifierCache,
};

/// Verification mode of the certificate chain when the cache is used
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CertificateChainCacheMode {
    /// Cached certificates are cryptographically re-verified
    #[default]
    #[clap(name = "FullVerification")]
    FullVerification,
    /// The chain verification stops at the first cached certificate
    #[clap(name = "EarlyStopVerification")]
    EarlyStopVerification,
}

impl From<CertificateChainCacheMode> for CertificateVerifierCacheMode {
    fn from(mode: CertificateChainCacheMode) -> Self {
        match mode {
            CertificateChainCacheMode::FullVerification => Self::FullVerification,
            CertificateChainCacheMode::EarlyStopVerification => Self::EarlyStopVerification,
        }
    }
}

/// State of the directory of the certificate chain cache
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateChainCacheDirectoryState {
    /// The directory does not exist or holds no data besides the marker file
    Absent,
    /// The directory holds certificate chain cache data
    Cache,
    /// The directory holds data but no marker file
    Foreign,
}

/// Configuration of the certificate chain cache
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChainCacheConfiguration {
    /// Whether the certificate chain verification uses the cache
    pub enabled: bool,
    /// Verification mode of the certificate chain when the cache is used
    pub mode: CertificateChainCacheMode,
    /// Directory where the cache is stored
    pub directory: PathBuf,
}

impl CertificateChainCacheConfiguration {
    /// Default directory of the cache
    pub const DEFAULT_DIRECTORY: &str = "./certificate-chain-cache";

    /// Name of the file that marks a directory as a certificate chain cache
    pub(crate) const MARKER_FILE_NAME: &str = ".mithril-certificate-chain-cache";

    /// Time a verified certificate stays in the cache
    const EXPIRATION_DELAY: TimeDelta = TimeDelta::weeks(1);

    /// Create the file system cache located in the configured directory
    pub fn build_cache(&self) -> FileCertificateVerifierCache {
        FileCertificateVerifierCache::new(&self.directory, Self::EXPIRATION_DELAY)
    }

    /// Cache and verification mode used by the certificate chain verification, if enabled
    pub fn verifier_cache(
        &self,
    ) -> Option<(
        Arc<dyn CertificateVerifierCache>,
        CertificateVerifierCacheMode,
    )> {
        self.enabled.then(|| {
            let cache: Arc<dyn CertificateVerifierCache> = Arc::new(self.build_cache());
            (cache, self.mode.into())
        })
    }

    /// Inspect the configured directory
    pub fn directory_state(&self) -> MithrilResult<CertificateChainCacheDirectoryState> {
        let has_marker = self.directory.join(Self::MARKER_FILE_NAME).is_file();
        let has_data = Self::holds_data_besides_marker(&self.directory)?;

        Ok(match (has_marker, has_data) {
            (_, false) => CertificateChainCacheDirectoryState::Absent,
            (true, true) => CertificateChainCacheDirectoryState::Cache,
            (false, true) => CertificateChainCacheDirectoryState::Foreign,
        })
    }

    /// Ensure the configured directory can hold the cache, creating it with its marker file
    ///
    /// Fails if the directory holds other data or is not writable.
    pub fn prepare_directory(&self) -> MithrilResult<()> {
        self.ensure_not_foreign()?;
        fs::create_dir_all(&self.directory).with_context(|| {
            format!(
                "Failed to create the certificate chain cache directory '{}'",
                self.directory.display()
            )
        })?;
        fs::write(self.directory.join(Self::MARKER_FILE_NAME), "").with_context(|| {
            format!(
                "Certificate chain cache directory '{}' is not writable",
                self.directory.display()
            )
        })
    }

    /// Fail if the configured directory is not empty and does not hold a certificate chain cache
    fn ensure_not_foreign(&self) -> MithrilResult<()> {
        match self.directory_state()? {
            CertificateChainCacheDirectoryState::Foreign => Err(anyhow!(
                "Directory '{}' is not empty and is not a certificate chain cache",
                self.directory.display()
            )),
            CertificateChainCacheDirectoryState::Absent
            | CertificateChainCacheDirectoryState::Cache => Ok(()),
        }
    }

    fn holds_data_besides_marker(directory: &Path) -> MithrilResult<bool> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed to read the certificate chain cache directory '{}'",
                        directory.display()
                    )
                });
            }
        };

        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read the certificate chain cache directory '{}'",
                    directory.display()
                )
            })?;
            if entry.file_name() != Self::MARKER_FILE_NAME {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl Default for CertificateChainCacheConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CertificateChainCacheMode::default(),
            directory: PathBuf::from(Self::DEFAULT_DIRECTORY),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs::Permissions;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use mithril_common::temp_dir_create;

    use super::*;

    fn configuration(enabled: bool, directory: PathBuf) -> CertificateChainCacheConfiguration {
        CertificateChainCacheConfiguration {
            enabled,
            mode: CertificateChainCacheMode::EarlyStopVerification,
            directory,
        }
    }

    #[test]
    fn default_configuration_is_disabled_in_full_verification_mode_and_default_directory() {
        let configuration = CertificateChainCacheConfiguration::default();

        assert!(!configuration.enabled);
        assert_eq!(
            CertificateChainCacheMode::FullVerification,
            configuration.mode
        );
        assert_eq!(
            PathBuf::from(CertificateChainCacheConfiguration::DEFAULT_DIRECTORY),
            configuration.directory
        );
    }

    #[test]
    fn convert_mode_to_certificate_verifier_cache_mode() {
        assert_eq!(
            CertificateVerifierCacheMode::FullVerification,
            CertificateChainCacheMode::FullVerification.into()
        );
        assert_eq!(
            CertificateVerifierCacheMode::EarlyStopVerification,
            CertificateChainCacheMode::EarlyStopVerification.into()
        );
    }

    mod verifier_cache {
        use super::*;

        #[test]
        fn returns_none_when_disabled() {
            let configuration = configuration(false, PathBuf::from("cache"));

            assert!(configuration.verifier_cache().is_none());
        }

        #[test]
        fn returns_the_cache_with_the_configured_mode_when_enabled() {
            let configuration = configuration(true, PathBuf::from("cache"));

            let (_cache, mode) = configuration.verifier_cache().unwrap();

            assert_eq!(CertificateVerifierCacheMode::EarlyStopVerification, mode);
        }
    }

    mod directory_state {
        use super::*;

        #[test]
        fn absent_when_the_directory_does_not_exist() {
            let configuration = configuration(true, temp_dir_create!().join("not_existing"));

            assert_eq!(
                CertificateChainCacheDirectoryState::Absent,
                configuration.directory_state().unwrap()
            );
        }

        #[test]
        fn absent_when_the_directory_is_empty() {
            let configuration = configuration(true, temp_dir_create!());

            assert_eq!(
                CertificateChainCacheDirectoryState::Absent,
                configuration.directory_state().unwrap()
            );
        }

        #[test]
        fn foreign_when_the_directory_holds_other_data() {
            let directory = temp_dir_create!();
            fs::create_dir(directory.join("staged")).unwrap();
            let configuration = configuration(true, directory);

            assert_eq!(
                CertificateChainCacheDirectoryState::Foreign,
                configuration.directory_state().unwrap()
            );
        }

        #[test]
        fn absent_when_the_directory_holds_only_the_marker_file() {
            let configuration = configuration(true, temp_dir_create!());
            configuration.prepare_directory().unwrap();

            assert_eq!(
                CertificateChainCacheDirectoryState::Absent,
                configuration.directory_state().unwrap()
            );
        }

        #[test]
        fn cache_when_the_prepared_directory_holds_data() {
            let directory = temp_dir_create!();
            let configuration = configuration(true, directory.clone());
            configuration.prepare_directory().unwrap();
            fs::create_dir(directory.join("committed")).unwrap();

            assert_eq!(
                CertificateChainCacheDirectoryState::Cache,
                configuration.directory_state().unwrap()
            );
        }

        #[test]
        fn fails_when_the_path_is_a_file() {
            let path = temp_dir_create!().join("file");
            fs::write(&path, "content").unwrap();
            let configuration = configuration(true, path);

            configuration
                .directory_state()
                .expect_err("directory_state should fail on a file");
        }
    }

    mod prepare_directory {
        use super::*;

        #[test]
        fn creates_the_missing_directory() {
            let directory = temp_dir_create!().join("cache");
            let configuration = configuration(true, directory.clone());

            configuration.prepare_directory().unwrap();

            assert!(directory.is_dir());
        }

        #[test]
        fn accepts_a_directory_already_prepared() {
            let configuration = configuration(true, temp_dir_create!());
            configuration.prepare_directory().unwrap();

            configuration.prepare_directory().unwrap();
        }

        #[test]
        fn accepts_a_prepared_directory_holding_cache_data() {
            let directory = temp_dir_create!();
            let configuration = configuration(true, directory.clone());
            configuration.prepare_directory().unwrap();
            fs::create_dir(directory.join("committed")).unwrap();

            configuration.prepare_directory().unwrap();
        }

        #[test]
        fn refuses_a_directory_holding_other_data() {
            let directory = temp_dir_create!();
            fs::write(directory.join("data.txt"), "content").unwrap();
            let configuration = configuration(true, directory);

            configuration
                .prepare_directory()
                .expect_err("prepare_directory should refuse a foreign directory");
        }

        #[cfg(unix)]
        #[test]
        fn fails_when_the_directory_is_not_writable() {
            let directory = temp_dir_create!();
            fs::set_permissions(&directory, Permissions::from_mode(0o555)).unwrap();
            let configuration = configuration(true, directory.clone());

            let result = configuration.prepare_directory();

            fs::set_permissions(&directory, Permissions::from_mode(0o755)).unwrap();
            result.expect_err("prepare_directory should fail on a read only directory");
        }
    }
}
