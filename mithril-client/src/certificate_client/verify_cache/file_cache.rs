use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, DirEntry};
use tokio::sync::RwLock;

use crate::certificate_client::{CertificateVerifierCache, CertificateVerifierCacheSpace};
use crate::{MithrilCertificate, MithrilResult};

const COMMITTED_DIRECTORY_NAME: &str = "committed";
const STAGED_DIRECTORY_NAME: &str = "staged";
const CERTIFICATE_FILE_EXTENSION: &str = "json";
const COMMITTING_FILE_EXTENSION: &str = "committing";
const BATCH_CREATION_FILE_NAME: &str = "created_at";
const DEFAULT_STAGING_BATCH_TTL: TimeDelta = TimeDelta::minutes(15);

/// A file system cache for the certificate verifier.
///
/// Layout under the root directory:
/// - `committed/<space>/<certificate_hash>.json`: one file per verified certificate, holding
///   the certificate and its expiration date, under the space that validated it.
/// - `staged/<certificate_chain_validation_id>/`: a chain validation in progress, holding one
///   `<certificate_hash>.json` file per staged certificate and the creation date of the batch in
///   a `created_at` file.
///
/// A commit writes each staged certificate with its expiration date to a `.committing` file of the
/// batch, then moves it to the committed directory with an atomic rename, leaving the staged file
/// untouched until the batch is removed.
/// The files are not synced to disk, so a power loss can leave a truncated committed file: like
/// any committed file that cannot be parsed, it is deleted when read.
/// A staged batch expires after the staging expiration delay from its creation.
pub struct FileCertificateVerifierCache {
    /// Directory of the committed certificate files, one sub directory per space
    committed_directory: PathBuf,
    /// Directory of the staged batches, one sub directory per certificate chain validation id
    staged_directory: PathBuf,
    /// Time a committed certificate stays valid
    expiration_delay: TimeDelta,
    /// Time a staged batch survives after its creation
    staging_expiration_delay: TimeDelta,
    /// Serializes the file system mutations of this instance, except the removal of an
    /// unparsable committed file when read, which is idempotent
    lock: RwLock<()>,
}

/// The content of a certificate cache file
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct CertificateCacheEntry {
    /// The cached certificate
    certificate: MithrilCertificate,
    /// The date after which the entry is ignored
    expire_at: DateTime<Utc>,
}

impl CertificateCacheEntry {
    /// Whether the entry is still valid at the given date
    fn is_valid_at(&self, date: DateTime<Utc>) -> bool {
        self.expire_at >= date
    }
}

/// The expiration date of a certificate cache file, read without deserializing the certificate
#[derive(Debug, Deserialize)]
struct CertificateCacheEntryExpiration {
    /// The date after which the entry is ignored
    expire_at: DateTime<Utc>,
}

impl CertificateCacheEntryExpiration {
    /// Whether the entry is still valid at the given date
    fn is_valid_at(&self, date: DateTime<Utc>) -> bool {
        self.expire_at >= date
    }
}

impl FileCertificateVerifierCache {
    /// `FileCertificateVerifierCache` factory
    ///
    /// The directories are created on first use.
    pub fn new(root_directory: &Path, expiration_delay: TimeDelta) -> Self {
        Self {
            committed_directory: root_directory.join(COMMITTED_DIRECTORY_NAME),
            staged_directory: root_directory.join(STAGED_DIRECTORY_NAME),
            expiration_delay,
            staging_expiration_delay: DEFAULT_STAGING_BATCH_TTL,
            lock: RwLock::new(()),
        }
    }

    /// Set how long a staged (uncommitted) batch survives after its creation before being
    /// silently dropped instead of committed.
    ///
    /// Warn: Too short and a slow-but-valid `verify_chain` call may never get to commit, and too
    /// long and an abandoned batch from a failed run lingers longer.
    pub fn with_staging_expiration_delay(mut self, staging_expiration_delay: TimeDelta) -> Self {
        self.staging_expiration_delay = staging_expiration_delay;
        self
    }

    /// Directory of the committed files of the given space
    fn committed_space_directory(&self, space: &CertificateVerifierCacheSpace) -> PathBuf {
        self.committed_directory.join(space.as_str())
    }

    /// Path of the committed file of the given certificate hash in the given space
    fn committed_file_path(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<PathBuf> {
        Ok(self
            .committed_space_directory(space)
            .join(Self::certificate_file_name(certificate_hash)?))
    }

    /// Path of the staged batch directory of the given certificate chain validation id
    fn batch_directory_path(
        &self,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<PathBuf> {
        Self::ensure_safe_file_name(
            certificate_chain_validation_id,
            "certificate chain validation id",
        )?;
        Ok(self.staged_directory.join(certificate_chain_validation_id))
    }

    /// File name of the given certificate hash
    fn certificate_file_name(certificate_hash: &str) -> MithrilResult<String> {
        Self::ensure_safe_file_name(certificate_hash, "certificate hash")?;
        Ok(format!("{certificate_hash}.{CERTIFICATE_FILE_EXTENSION}"))
    }

    /// Reject a value that could escape the cache directories when used as a file name
    fn ensure_safe_file_name(value: &str, value_name: &str) -> MithrilResult<()> {
        let is_safe = !value.is_empty()
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character));

        if is_safe {
            Ok(())
        } else {
            Err(anyhow!("Unsafe {value_name} for a file name: '{value}'"))
        }
    }

    /// Read a committed entry, ignoring the expired ones
    async fn read_committed(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<CertificateCacheEntry>> {
        let path = self.committed_file_path(space, certificate_hash)?;

        let _guard = self.lock.read().await;
        Ok(Self::read_entry(&path)
            .await?
            .filter(|entry| entry.is_valid_at(Utc::now())))
    }

    /// Read a certificate cache file, deleting it if it cannot be parsed
    async fn read_entry(path: &Path) -> MithrilResult<Option<CertificateCacheEntry>> {
        Self::read_cache_file(path).await
    }

    /// Read the expiration date of a certificate cache file, deleting it if it cannot be parsed
    async fn read_expiration(
        path: &Path,
    ) -> MithrilResult<Option<CertificateCacheEntryExpiration>> {
        Self::read_cache_file(path).await
    }

    /// Read a cache file, deleting it if it cannot be parsed
    async fn read_cache_file<T: DeserializeOwned>(path: &Path) -> MithrilResult<Option<T>> {
        let content = match fs::read(path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to read certificate cache file '{}'", path.display())
                });
            }
        };

        match serde_json::from_slice(&content) {
            Ok(entry) => Ok(Some(entry)),
            Err(error) => {
                Self::remove_file_if_exists(path).await?;
                Err(anyhow!(error).context(format!(
                    "Invalidated unparsable certificate cache file '{}'",
                    path.display()
                )))
            }
        }
    }

    /// Delete the staged batches created for longer than the staging expiration delay
    ///
    /// Best effort: an entry that is not a directory, or that cannot be inspected or removed, is
    /// left in place.
    async fn sweep_expired_batches(&self) {
        let now = Utc::now();
        for batch in Self::list_directory_or_empty(&self.staged_directory).await {
            let Ok(metadata) = batch.metadata().await else {
                continue;
            };

            if metadata.is_dir() && self.is_batch_expired_at(&batch.path(), &metadata, now).await {
                let _ = Self::remove_directory_if_exists(&batch.path()).await;
            }
        }
    }

    /// Whether the given staged batch is expired at the given date
    ///
    /// A batch without a readable creation file (interrupted creation) falls back on the last
    /// modification of its directory.
    async fn is_batch_expired_at(
        &self,
        batch_directory: &Path,
        metadata: &Metadata,
        date: DateTime<Utc>,
    ) -> bool {
        let creation_date = match Self::read_batch_creation_date(batch_directory).await {
            Some(creation_date) => Some(creation_date),
            None => match metadata.modified() {
                Ok(last_modification) => Self::to_date_time(last_modification),
                Err(_) => return false,
            },
        };

        creation_date
            .is_none_or(|creation_date| creation_date + self.staging_expiration_delay < date)
    }

    /// Read the creation date of the given staged batch, `None` if it cannot be read
    async fn read_batch_creation_date(batch_directory: &Path) -> Option<DateTime<Utc>> {
        let content = fs::read(batch_directory.join(BATCH_CREATION_FILE_NAME)).await.ok()?;
        serde_json::from_slice(&content).ok()
    }

    /// Create the directory of a staged batch with its creation file
    async fn create_batch(batch_directory: &Path) -> MithrilResult<()> {
        fs::create_dir_all(batch_directory).await.with_context(|| {
            format!(
                "Failed to create staged batch directory '{}'",
                batch_directory.display()
            )
        })?;
        let creation_file = batch_directory.join(BATCH_CREATION_FILE_NAME);
        let content = serde_json::to_vec(&Utc::now())
            .context("Failed to serialize the creation date of the staged batch")?;

        fs::write(&creation_file, content).await.with_context(|| {
            format!(
                "Failed to write staged batch creation file '{}'",
                creation_file.display()
            )
        })
    }

    /// Write the certificate of the given staged file with its expiration date to a committing
    /// file, then move it to the given committed path
    async fn commit_staged_file(
        staged_path: &Path,
        committed_path: &Path,
        expire_at: DateTime<Utc>,
    ) -> MithrilResult<()> {
        let certificate: MithrilCertificate = Self::read_cache_file(staged_path)
            .await?
            .ok_or_else(|| anyhow!("Staged file '{}' not found", staged_path.display()))?;
        let content = serde_json::to_vec(&CertificateCacheEntry {
            certificate,
            expire_at,
        })
        .context("Failed to serialize the certificate to cache")?;

        let committing_path = staged_path.with_extension(COMMITTING_FILE_EXTENSION);

        fs::write(&committing_path, content).await.with_context(|| {
            format!(
                "Failed to write committing file '{}'",
                committing_path.display()
            )
        })?;
        fs::rename(&committing_path, committed_path).await.with_context(|| {
            format!(
                "Failed to move committing file '{}' to '{}'",
                committing_path.display(),
                committed_path.display()
            )
        })
    }

    /// Delete the committed files that are expired, in all the spaces
    ///
    /// Best effort: an entry that is not a certificate file, or that cannot be removed, is left
    /// in place.
    async fn sweep_expired_committed(&self) {
        let now = Utc::now();
        for space_directory in Self::list_directory_or_empty(&self.committed_directory).await {
            for file in Self::list_directory_or_empty(&space_directory.path()).await {
                let path = file.path();
                if Self::is_certificate_file(&path)
                    && let Ok(Some(expiration)) = Self::read_expiration(&path).await
                    && !expiration.is_valid_at(now)
                {
                    let _ = Self::remove_file_if_exists(&path).await;
                }
            }
        }
    }

    /// Convert a file system time to a date, `None` if it is out of the range of a date
    fn to_date_time(time: SystemTime) -> Option<DateTime<Utc>> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(since_epoch) => TimeDelta::from_std(since_epoch)
                .ok()
                .and_then(|delta| DateTime::UNIX_EPOCH.checked_add_signed(delta)),
            Err(error) => TimeDelta::from_std(error.duration())
                .ok()
                .and_then(|delta| DateTime::UNIX_EPOCH.checked_sub_signed(delta)),
        }
    }

    /// Whether the given path has the extension of a certificate file
    fn is_certificate_file(path: &Path) -> bool {
        path.extension()
            .is_some_and(|extension| extension == CERTIFICATE_FILE_EXTENSION)
    }

    /// List the entries of a directory, an unreadable directory is empty
    async fn list_directory_or_empty(directory: &Path) -> Vec<DirEntry> {
        Self::list_directory(directory).await.unwrap_or_default()
    }

    /// List the entries of a directory, a missing directory is empty
    async fn list_directory(directory: &Path) -> MithrilResult<Vec<DirEntry>> {
        let mut read_dir = match fs::read_dir(directory).await {
            Ok(read_dir) => read_dir,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to list directory '{}'", directory.display())
                });
            }
        };

        let mut entries = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .with_context(|| format!("Failed to list directory '{}'", directory.display()))?
        {
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Delete a file, a missing file is not an error
    async fn remove_file_if_exists(path: &Path) -> MithrilResult<()> {
        match fs::remove_file(path).await {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                Err(error).with_context(|| format!("Failed to remove file '{}'", path.display()))
            }
            _ => Ok(()),
        }
    }

    /// Delete a directory and its content, a missing directory is not an error
    async fn remove_directory_if_exists(path: &Path) -> MithrilResult<()> {
        match fs::remove_dir_all(path).await {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error)
                .with_context(|| format!("Failed to remove directory '{}'", path.display())),
            _ => Ok(()),
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifierCache for FileCertificateVerifierCache {
    async fn stage_certificate(
        &self,
        certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()> {
        let batch_directory = self.batch_directory_path(certificate_chain_validation_id)?;
        let file_path = batch_directory.join(Self::certificate_file_name(&certificate.hash)?);
        let content = serde_json::to_vec(&certificate)
            .context("Failed to serialize the certificate to cache")?;

        let _guard = self.lock.write().await;
        let is_new_batch = !fs::try_exists(&batch_directory).await.with_context(|| {
            format!(
                "Failed to check existence of staged batch '{}'",
                batch_directory.display()
            )
        })?;
        if is_new_batch {
            self.sweep_expired_batches().await;
            self.sweep_expired_committed().await;
            Self::create_batch(&batch_directory).await?;
        }

        fs::write(&file_path, content)
            .await
            .with_context(|| format!("Failed to write staged file '{}'", file_path.display()))
    }

    async fn commit_staged_certificates(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()> {
        let batch_directory = self.batch_directory_path(certificate_chain_validation_id)?;
        let committed_space_directory = self.committed_space_directory(space);

        let _guard = self.lock.write().await;
        self.sweep_expired_batches().await;
        self.sweep_expired_committed().await;

        let staged_files: Vec<DirEntry> = Self::list_directory(&batch_directory)
            .await?
            .into_iter()
            .filter(|staged_file| Self::is_certificate_file(&staged_file.path()))
            .collect();
        if staged_files.is_empty() {
            return Self::remove_directory_if_exists(&batch_directory).await;
        }

        fs::create_dir_all(&committed_space_directory)
            .await
            .with_context(|| {
                format!(
                    "Failed to create committed space directory '{}'",
                    committed_space_directory.display()
                )
            })?;
        let expire_at = Utc::now() + self.expiration_delay;
        let mut failures = Vec::new();
        for staged_file in staged_files {
            let committed_path = committed_space_directory.join(staged_file.file_name());
            if let Err(error) =
                Self::commit_staged_file(&staged_file.path(), &committed_path, expire_at).await
            {
                failures.push(format!("{error:#}"));
            }
        }

        if failures.is_empty() {
            Self::remove_directory_if_exists(&batch_directory).await
        } else {
            Err(anyhow!(
                "Failed to commit {} staged certificate(s) of batch '{}': {}",
                failures.len(),
                batch_directory.display(),
                failures.join(", ")
            ))
        }
    }

    async fn get_certificate_by_hash(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        Ok(self
            .read_committed(space, certificate_hash)
            .await?
            .map(|entry| entry.certificate))
    }

    async fn certificate_exist(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<bool> {
        Ok(self.read_committed(space, certificate_hash).await?.is_some())
    }

    async fn reset(&self) -> MithrilResult<()> {
        let _guard = self.lock.write().await;
        Self::remove_directory_if_exists(&self.staged_directory).await?;
        Self::remove_directory_if_exists(&self.committed_directory).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    #[cfg(unix)]
    use std::fs::Permissions;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};
    use mithril_common::temp_dir_create;
    use mithril_common::test::double::Dummy;

    use super::*;

    mod test_tools {
        use super::*;

        impl FileCertificateVerifierCache {
            /// `Test only` Populate the given space of the cache with the given certificates
            pub(super) async fn with_items<T>(
                self,
                space: &CertificateVerifierCacheSpace,
                chain: T,
            ) -> Self
            where
                T: IntoIterator<Item = MithrilCertificate>,
            {
                let expire_at = Utc::now() + self.expiration_delay;
                fs::create_dir_all(self.committed_space_directory(space))
                    .await
                    .unwrap();
                for certificate in chain {
                    let path = self.committed_file_path(space, &certificate.hash).unwrap();
                    Self::write_entry(
                        &path,
                        &CertificateCacheEntry {
                            certificate,
                            expire_at,
                        },
                    )
                    .await;
                }
                self
            }

            /// `Test only` Return the hashes of the certificates committed to the given space
            pub(super) async fn committed_hashes(
                &self,
                space: &CertificateVerifierCacheSpace,
            ) -> HashSet<String> {
                Self::list_directory(&self.committed_space_directory(space))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|entry| entry.path().file_stem().unwrap().to_string_lossy().to_string())
                    .collect()
            }

            /// `Test only` Return the ids of staged batches
            pub(super) async fn staged_batch_ids(&self) -> HashSet<String> {
                Self::list_directory(&self.staged_directory)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|entry| entry.file_name().to_string_lossy().to_string())
                    .collect()
            }

            /// `Test only` Overwrite the expiration date of the entry of the given certificate hash.
            ///
            /// panic if the key is not found
            pub(super) async fn overwrite_expiration_date(
                &self,
                space: &CertificateVerifierCacheSpace,
                certificate_hash: &str,
                expire_at: DateTime<Utc>,
            ) {
                let path = self.committed_file_path(space, certificate_hash).unwrap();
                let mut entry = Self::read_entry(&path).await.unwrap().expect("Key not found");
                entry.expire_at = expire_at;
                Self::write_entry(&path, &entry).await;
            }

            /// `Test only` Get the committed entry of the given certificate hash
            pub(super) async fn get_cached_value(
                &self,
                space: &CertificateVerifierCacheSpace,
                certificate_hash: &str,
            ) -> Option<CertificateCacheEntry> {
                let path = self.committed_file_path(space, certificate_hash).unwrap();
                Self::read_entry(&path).await.unwrap()
            }

            /// `Test only` Get the staged certificate of the given hash and validation id
            pub(super) async fn get_staged_value(
                &self,
                certificate_hash: &str,
                certificate_chain_validation_id: &str,
            ) -> Option<MithrilCertificate> {
                let path = self
                    .batch_directory_path(certificate_chain_validation_id)
                    .unwrap()
                    .join(Self::certificate_file_name(certificate_hash).unwrap());
                Self::read_cache_file(&path).await.unwrap()
            }

            /// `Test only` Overwrite the creation date of the staged batch of the given id
            pub(super) async fn overwrite_batch_creation_date(
                &self,
                certificate_chain_validation_id: &str,
                created_at: DateTime<Utc>,
            ) {
                let path = self
                    .batch_directory_path(certificate_chain_validation_id)
                    .unwrap()
                    .join(BATCH_CREATION_FILE_NAME);
                fs::write(path, serde_json::to_vec(&created_at).unwrap())
                    .await
                    .unwrap();
            }

            async fn write_entry(path: &Path, entry: &CertificateCacheEntry) {
                fs::write(path, serde_json::to_vec(entry).unwrap()).await.unwrap();
            }
        }
    }

    fn space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        )
    }

    fn other_space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::from_ed25519(GenesisEd25519Signer::create_non_deterministic_signer())
                .create_verifier(),
        )
    }

    fn dummy_certificate(hash: &str, previous_hash: &str) -> MithrilCertificate {
        MithrilCertificate {
            hash: hash.to_string(),
            previous_hash: previous_hash.to_string(),
            ..Dummy::dummy()
        }
    }

    #[tokio::test]
    async fn from_certificate_iterator() {
        let chain = vec![
            dummy_certificate("first", "first_parent"),
            dummy_certificate("second", "second_parent"),
        ];
        let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
            .with_items(&space(), chain.clone())
            .await;

        assert_eq!(
            HashSet::from(["first".to_string(), "second".to_string()]),
            cache.committed_hashes(&space()).await
        );
        assert_eq!(
            Some(chain[0].clone()),
            cache.get_certificate_by_hash(&space(), "first").await.unwrap()
        );
    }

    #[tokio::test]
    async fn constructor_does_not_touch_the_file_system() {
        let root_directory = temp_dir_create!().join("not_created_yet");

        let _cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1));

        assert!(!root_directory.exists());
    }

    mod to_date_time {
        use std::time::Duration;

        use super::*;

        #[test]
        fn converts_a_time_after_the_epoch() {
            let time = UNIX_EPOCH + Duration::from_secs(3600);

            assert_eq!(
                Some(DateTime::UNIX_EPOCH + TimeDelta::hours(1)),
                FileCertificateVerifierCache::to_date_time(time)
            );
        }

        #[test]
        fn converts_a_time_before_the_epoch() {
            let time = UNIX_EPOCH - Duration::from_secs(3600);

            assert_eq!(
                Some(DateTime::UNIX_EPOCH - TimeDelta::hours(1)),
                FileCertificateVerifierCache::to_date_time(time)
            );
        }

        #[cfg(unix)]
        #[test]
        fn returns_none_for_a_time_out_of_the_range_of_a_date() {
            let time = UNIX_EPOCH
                .checked_add(Duration::from_secs(i64::MAX as u64))
                .expect("the platform time should hold the largest timestamp");

            assert_eq!(None, FileCertificateVerifierCache::to_date_time(time));
        }
    }

    mod stage_commit {
        use super::*;

        #[tokio::test]
        async fn committing_to_a_space_does_not_expose_certificates_in_another_space() {
            let other_space = other_space();
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&other_space, "hash").await.unwrap()
            );
            assert!(!cache.certificate_exist(&other_space, "hash").await.unwrap());
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_expired_committed_certificates_of_every_space()
        {
            let other_space = other_space();
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("expired_hash", "parent")])
                .await
                .with_items(
                    &other_space,
                    [dummy_certificate("other_expired_hash", "parent")],
                )
                .await;
            let expired_at = Utc::now() - TimeDelta::hours(1);
            cache
                .overwrite_expiration_date(&space(), "expired_hash", expired_at)
                .await;
            cache
                .overwrite_expiration_date(&other_space, "other_expired_hash", expired_at)
                .await;

            cache.commit_staged_certificates(&space(), "second_id").await.unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
            assert_eq!(HashSet::new(), cache.committed_hashes(&other_space).await);
        }

        #[tokio::test]
        async fn staging_a_certificate_does_not_make_it_retrievable_before_commit() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_staged_value("hash", "chain_validation_id").await
            );
        }

        #[tokio::test]
        async fn committing_makes_previously_staged_certificates_retrievable() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn committing_removes_the_staged_batch() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[tokio::test]
        async fn committing_one_id_does_not_expose_certificates_staged_under_another_id() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_id_a", dummy_certificate("hash_a", "parent"))
                .await
                .unwrap();
            cache
                .stage_certificate("chain_id_b", dummy_certificate("hash_b", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_id_a")
                .await
                .unwrap();

            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash_a")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash_b").await.unwrap()
            );
        }

        #[tokio::test]
        async fn committing_an_unknown_id_is_a_no_op_not_an_error() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));

            cache
                .commit_staged_certificates(&space(), "never_staged")
                .await
                .unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
        }

        #[tokio::test]
        async fn committing_the_same_id_twice_is_a_no_op_the_second_time() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }

        #[tokio::test]
        async fn committing_an_expired_staged_batch_does_not_commit_it() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[tokio::test]
        async fn committing_in_empty_cache_add_new_item_that_expire_after_parametrized_delay() {
            let expiration_delay = TimeDelta::hours(1);
            let start_time = Utc::now();
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), expiration_delay);
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let cached = cache
                .get_cached_value(&space(), "hash")
                .await
                .expect("Cache should have been populated");

            assert_eq!(
                HashSet::from(["hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
            assert_eq!("hash", cached.certificate.hash);
            assert!(cached.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn committing_sets_the_expiration_date_from_the_commit_time() {
            let root_directory = temp_dir_create!();
            let expiration_delay = TimeDelta::days(10);
            let start_time = Utc::now();
            FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            let cache = FileCertificateVerifierCache::new(&root_directory, expiration_delay);

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let cached = cache.get_cached_value(&space(), "hash").await.unwrap();
            assert!(cached.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn committing_a_batch_expired_since_its_creation_does_not_commit_it() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .overwrite_batch_creation_date(
                    "chain_validation_id",
                    Utc::now() - TimeDelta::hours(2),
                )
                .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash2", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[tokio::test]
        async fn staging_a_new_batch_sweeps_away_an_expired_batch_without_creation_file() {
            let root_directory = temp_dir_create!();
            fs::create_dir_all(root_directory.join(STAGED_DIRECTORY_NAME).join("interrupted_id"))
                .await
                .unwrap();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());

            cache
                .stage_certificate("new_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_keeps_a_recent_batch_without_creation_file() {
            let root_directory = temp_dir_create!();
            fs::create_dir_all(root_directory.join(STAGED_DIRECTORY_NAME).join("creating_id"))
                .await
                .unwrap();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));

            cache
                .stage_certificate("new_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["creating_id".to_string(), "new_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn committing_moves_every_valid_staged_file_when_one_fails() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            let unparsable_path = cache
                .batch_directory_path("chain_validation_id")
                .unwrap()
                .join("unparsable_hash.json");
            fs::write(&unparsable_path, b"not a certificate").await.unwrap();
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash2", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .expect_err("the unparsable staged file must be reported");

            assert_eq!(
                HashSet::from(["hash".to_string(), "hash2".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }

        #[tokio::test]
        async fn committing_keeps_the_staged_certificate_when_the_move_fails() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            let blocking_directory = cache.committed_file_path(&space(), "hash").unwrap();
            fs::create_dir_all(blocking_directory.join("not_empty"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .expect_err("the failed move must be reported");

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_staged_value("hash", "chain_validation_id").await
            );
        }

        #[tokio::test]
        async fn committing_new_hash_dont_alter_existing_values() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(
                    &space(),
                    [
                        dummy_certificate("existing_hash", "existing_parent"),
                        dummy_certificate("another_hash", "another_parent"),
                    ],
                )
                .await;
            cache
                .stage_certificate(
                    "chain_validation_id",
                    dummy_certificate("new_hash", "new_parent"),
                )
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from([
                    "existing_hash".to_string(),
                    "another_hash".to_string(),
                    "new_hash".to_string()
                ]),
                cache.committed_hashes(&space()).await
            );
            assert_eq!(
                Some(dummy_certificate("existing_hash", "existing_parent")),
                cache
                    .get_certificate_by_hash(&space(), "existing_hash")
                    .await
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn committing_a_certificate_with_an_existing_hash_update_data_and_expiration_time() {
            let expiration_delay = TimeDelta::days(2);
            let start_time = Utc::now();
            let before_update = dummy_certificate("hash", "parent");
            let expected = MithrilCertificate {
                epoch: before_update.epoch + 10,
                previous_hash: "updated_parent".to_string(),
                ..before_update.clone()
            };
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), expiration_delay)
                .with_items(&space(), [before_update])
                .await;
            cache
                .overwrite_expiration_date(&space(), "hash", start_time - TimeDelta::days(1))
                .await;

            cache
                .stage_certificate("chain_validation_id", expected.clone())
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let updated_value = cache.get_cached_value(&space(), "hash").await.unwrap();
            assert_eq!(expected, updated_value.certificate);
            assert!(updated_value.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_expired_batches() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("abandoned_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache.commit_staged_certificates(&space(), "other_id").await.unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[tokio::test]
        async fn committing_certificates_keeps_other_batches_that_are_not_expired() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("to_commit_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("remaining_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "to_commit_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["remaining_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_expired_committed_certificates() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(
                    &space(),
                    [
                        dummy_certificate("expired_hash", "parent"),
                        dummy_certificate("new_hash", "parent"),
                    ],
                )
                .await;
            cache
                .overwrite_expiration_date(
                    &space(),
                    "expired_hash",
                    Utc::now() - TimeDelta::hours(1),
                )
                .await;

            cache.commit_staged_certificates(&space(), "second_id").await.unwrap();

            assert_eq!(
                HashSet::from(["new_hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_unparsable_committed_files() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("valid_hash", "parent")])
                .await;
            let unparsable_path = cache.committed_file_path(&space(), "unparsable_hash").unwrap();
            fs::write(&unparsable_path, b"not a certificate").await.unwrap();

            cache.commit_staged_certificates(&space(), "second_id").await.unwrap();

            assert_eq!(
                HashSet::from(["valid_hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_sweeps_away_other_expired_batches() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_batch".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_sweeps_away_expired_committed_certificates() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(
                    &space(),
                    [
                        dummy_certificate("expired_hash", "parent"),
                        dummy_certificate("new_hash", "parent"),
                    ],
                )
                .await;
            cache
                .overwrite_expiration_date(
                    &space(),
                    "expired_hash",
                    Utc::now() - TimeDelta::hours(1),
                )
                .await;

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }

        #[tokio::test]
        async fn staging_under_an_existing_batch_does_not_sweep_other_expired_batches() {
            let root_directory = temp_dir_create!();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("existing_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            let expiring_cache =
                FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                    .with_staging_expiration_delay(TimeDelta::zero());

            expiring_cache
                .stage_certificate("existing_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["expired_batch".to_string(), "existing_id".to_string()]),
                expiring_cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_skips_a_file_in_the_staged_directory() {
            let root_directory = temp_dir_create!();
            let stray_file = root_directory.join(STAGED_DIRECTORY_NAME).join("stray_file");
            fs::create_dir_all(stray_file.parent().unwrap()).await.unwrap();
            fs::write(&stray_file, b"not a batch").await.unwrap();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());

            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert!(stray_file.exists());
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn staging_a_new_batch_skips_an_expired_batch_that_cannot_be_removed() {
            let root_directory = temp_dir_create!();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("locked_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            let locked_batch = cache.batch_directory_path("locked_id").unwrap();
            fs::set_permissions(&locked_batch, Permissions::from_mode(0o500))
                .await
                .unwrap();

            let result = cache
                .stage_certificate("new_id", dummy_certificate("hash2", "parent2"))
                .await;
            fs::set_permissions(&locked_batch, Permissions::from_mode(0o700))
                .await
                .unwrap();

            result.unwrap();
        }

        #[tokio::test]
        async fn committing_keeps_a_file_of_the_committed_directory_that_is_not_a_certificate() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;
            let foreign_file = cache.committed_space_directory(&space()).join("notes.txt");
            fs::write(&foreign_file, b"not a certificate").await.unwrap();

            cache.commit_staged_certificates(&space(), "other_id").await.unwrap();

            assert!(foreign_file.exists());
        }

        #[tokio::test]
        async fn staging_under_an_unsafe_validation_id_fails_without_touching_the_file_system() {
            let root_directory = temp_dir_create!();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1));

            cache
                .stage_certificate("../escaped", dummy_certificate("hash", "parent"))
                .await
                .expect_err("an id escaping the staged directory must be rejected");

            assert!(!root_directory.join("escaped").exists());
            assert!(!root_directory.join(STAGED_DIRECTORY_NAME).exists());
        }

        #[tokio::test]
        async fn staging_a_certificate_with_an_unsafe_hash_fails() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));

            cache
                .stage_certificate(
                    "chain_validation_id",
                    dummy_certificate("../hash", "parent"),
                )
                .await
                .expect_err("a hash escaping the batch directory must be rejected");
        }
    }

    mod get_certificate_by_hash {
        use super::*;

        #[tokio::test]
        async fn returns_none_for_a_hash_committed_to_another_space() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&other_space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn returns_the_certificate_when_key_exists() {
            let expected = dummy_certificate("hash", "parent");
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(
                    &space(),
                    [expected.clone(), dummy_certificate("another_hash", "another_parent")],
                )
                .await;

            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn returns_none_if_not_found() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "not_found").await.unwrap()
            );
        }

        #[tokio::test]
        async fn returns_none_when_the_cache_directory_does_not_exist() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn returns_none_for_an_expired_entry() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;
            cache
                .overwrite_expiration_date(&space(), "hash", Utc::now() - TimeDelta::days(5))
                .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn invalidates_an_unparsable_entry() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;
            let path = cache.committed_file_path(&space(), "hash").unwrap();
            fs::write(&path, b"not a certificate").await.unwrap();

            cache
                .get_certificate_by_hash(&space(), "hash")
                .await
                .expect_err("an unparsable entry must be reported");

            assert!(!path.exists());
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn returns_certificates_committed_by_another_instance_on_the_same_directory() {
            let root_directory = temp_dir_create!();
            let first_instance =
                FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1));
            first_instance
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            first_instance
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let second_instance =
                FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1));

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                second_instance
                    .get_certificate_by_hash(&space(), "hash")
                    .await
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn rejects_an_unsafe_hash_without_touching_the_file_system() {
            let root_directory = temp_dir_create!();
            let escaped_path = root_directory.join("escaped.json");
            fs::write(&escaped_path, b"not a certificate").await.unwrap();
            let cache = FileCertificateVerifierCache::new(&root_directory, TimeDelta::hours(1));

            cache
                .get_certificate_by_hash(&space(), "../escaped")
                .await
                .expect_err("a hash escaping the committed directory must be rejected");

            assert!(escaped_path.exists());
        }
    }

    mod certificate_exist {
        use super::*;

        #[tokio::test]
        async fn returns_false_for_a_hash_never_committed() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_true_for_a_committed_hash() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;

            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_false_for_an_expired_committed_entry() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;
            cache
                .overwrite_expiration_date(&space(), "hash", Utc::now() - TimeDelta::days(1))
                .await;

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_false_for_a_staged_but_uncommitted_hash() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn invalidates_an_unparsable_entry() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            fs::create_dir_all(cache.committed_space_directory(&space()))
                .await
                .unwrap();
            let path = cache.committed_file_path(&space(), "hash").unwrap();
            fs::write(&path, b"not a certificate").await.unwrap();

            cache
                .certificate_exist(&space(), "hash")
                .await
                .expect_err("an unparsable entry must be reported");

            assert!(!path.exists());
            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }
    }

    mod reset {
        use super::*;

        #[tokio::test]
        async fn reset_clears_every_space() {
            let other_space = other_space();
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await
                .with_items(&other_space, [dummy_certificate("other_hash", "parent")])
                .await;

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
            assert_eq!(HashSet::new(), cache.committed_hashes(&other_space).await);
        }

        #[tokio::test]
        async fn reset_empty_cache_dont_raise_error() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
        }

        #[tokio::test]
        async fn reset_clears_committed_data() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(
                    &space(),
                    [
                        dummy_certificate("hash", "parent"),
                        dummy_certificate("another_hash", "another_parent"),
                    ],
                )
                .await;

            assert_eq!(2, cache.committed_hashes(&space()).await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.committed_hashes(&space()).await);
        }

        #[tokio::test]
        async fn reset_clears_staged_data() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1));
            cache
                .stage_certificate("chain_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(1, cache.staged_batch_ids().await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[tokio::test]
        async fn cache_is_usable_after_a_reset() {
            let cache = FileCertificateVerifierCache::new(&temp_dir_create!(), TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .await;
            cache.reset().await.unwrap();

            cache
                .stage_certificate("chain_id", dummy_certificate("new_hash", "parent"))
                .await
                .unwrap();
            cache.commit_staged_certificates(&space(), "chain_id").await.unwrap();

            assert_eq!(
                HashSet::from(["new_hash".to_string()]),
                cache.committed_hashes(&space()).await
            );
        }
    }
}
