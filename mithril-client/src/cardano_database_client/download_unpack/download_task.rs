use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, anyhow};
use slog::Logger;
use uuid::Uuid;

use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, immutable_trio_names};
use mithril_common::entities::{CompressionAlgorithm, ImmutableFileNumber};

use crate::{
    MithrilResult,
    file_downloader::{
        DownloadEvent, FileDownloader, FileDownloaderUnreachable, FileDownloaderUri,
    },
    utils::{AncillaryVerifier, ValidatedAncillaryManifest, move_file},
};

/// The future type for downloading a file
type DownloadFuture = dyn Future<Output = MithrilResult<()>> + Send;

/// A task to download and unpack a file
pub struct DownloadTask {
    pub kind: DownloadKind,
    pub locations_to_try: Vec<LocationToDownload>,
    pub size_uncompressed: u64,
    pub target_dir: PathBuf,
    pub download_event: DownloadEvent,
}

impl DownloadTask {
    /// Prefix of the name of the staging directory of an immutable archive
    const IMMUTABLE_STAGING_DIRECTORY_PREFIX: &str = "immutable-";

    /// Prefix of the name of the staging directory of the ancillary archive
    const ANCILLARY_STAGING_DIRECTORY_PREFIX: &str = "ancillary-";

    fn tried_locations(&self) -> String {
        self.locations_to_try
            .iter()
            .map(|l| format!("{:?}", l.file_downloader_uri.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn name(&self) -> String {
        match &self.kind {
            DownloadKind::Immutable(immutable_file_number) => {
                format!("immutable_file_{immutable_file_number:05}")
            }
            DownloadKind::Ancillary { .. } => "ancillary".to_string(),
        }
    }

    async fn download_unpack_file(
        &self,
        staging_directory: &StagingDirectory,
        logger: &Logger,
    ) -> MithrilResult<()> {
        let mut last_location_error = None;

        for location_to_try in &self.locations_to_try {
            if location_to_try.is_circuit_breaker_triggered() {
                continue;
            }
            staging_directory.reset().await.with_context(|| {
                format!("Could not reset the staging directory of {}", self.name())
            })?;

            let downloaded = location_to_try
                .file_downloader
                .download_unpack(
                    &location_to_try.file_downloader_uri,
                    self.size_uncompressed,
                    staging_directory.path(),
                    location_to_try.compression_algorithm,
                    self.download_event.clone(),
                )
                .await;

            match downloaded {
                Err(e) => {
                    // Only confirmed unreachable downloads trigger the circuit breaker.
                    // A location-specific miss (e.g., file not found) should not disable the downloader
                    // for a whole batch.
                    if let Some(circuit_breaker) = &location_to_try.circuit_breaker
                        && e.is::<FileDownloaderUnreachable>()
                    {
                        circuit_breaker.trigger();
                    }

                    slog::error!(
                        logger,
                        "Failed downloading and unpacking {} for location {:?}",
                        self.name(), location_to_try.file_downloader_uri;
                        "error" => ?e
                    );
                    last_location_error = Some(e);
                }
                Ok(()) => match self.verify_download(staging_directory.path()).await {
                    Err(e) => {
                        slog::error!(
                            logger,
                            "Failed validating {} downloaded from location {:?}",
                            self.name(), location_to_try.file_downloader_uri;
                            "error" => ?e
                        );
                        last_location_error = Some(e);
                    }
                    Ok(verified_download) => {
                        match self
                            .promote_download(staging_directory.path(), verified_download)
                            .await
                        {
                            Ok(()) => return Ok(()),
                            Err(e) if Self::is_fatal_local_error(&e) => {
                                slog::error!(
                                    logger,
                                    "Failed promoting {} downloaded from location {:?}, no other location can repair it",
                                    self.name(), location_to_try.file_downloader_uri;
                                    "error" => ?e
                                );
                                return Err(e.context(format!(
                                    "Could not promote {} downloaded from location {:?}",
                                    self.name(),
                                    location_to_try.file_downloader_uri.as_str()
                                )));
                            }
                            Err(e) => {
                                slog::error!(
                                    logger,
                                    "Failed promoting {} downloaded from location {:?}",
                                    self.name(), location_to_try.file_downloader_uri;
                                    "error" => ?e
                                );
                                last_location_error = Some(e);
                            }
                        }
                    }
                },
            }
        }

        let all_locations_failed = format!(
            "All locations failed for {}, tried locations: {}",
            self.name(),
            self.tried_locations()
        );

        Err(match last_location_error {
            Some(error) => error.context(all_locations_failed),
            None => anyhow!(all_locations_failed),
        })
    }

    /// A local failure of the promotion that no other location can repair, so the task stops
    /// instead of downloading the same archive again from the next location.
    ///
    /// A download, unpack or verification failure is never fatal: its cause may come from the
    /// network or from the remote archive, which the next location may not share.
    fn is_fatal_local_error(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause.downcast_ref::<io::Error>().is_some_and(|io_error| {
                matches!(
                    io_error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::PermissionDenied
                )
            })
        })
    }

    /// Verify the content unpacked from one location: an immutable archive must hold exactly its
    /// trio, the ancillary archive must carry a valid manifest.
    async fn verify_download(&self, staging_dir: &Path) -> MithrilResult<VerifiedDownload> {
        match &self.kind {
            DownloadKind::Immutable(immutable_file_number) => {
                Self::verify_immutable_archive_members(staging_dir, *immutable_file_number).await?;
                Ok(VerifiedDownload::ImmutableTrio(*immutable_file_number))
            }
            DownloadKind::Ancillary { verifier } => {
                let validated_manifest = verifier.verify(staging_dir).await?;
                Ok(VerifiedDownload::AncillaryFiles(validated_manifest))
            }
        }
    }

    /// Move the verified content of the staging directory to its final place.
    async fn promote_download(
        &self,
        staging_dir: &Path,
        verified_download: VerifiedDownload,
    ) -> MithrilResult<()> {
        match verified_download {
            VerifiedDownload::ImmutableTrio(immutable_file_number) => {
                Self::promote_immutable_files(staging_dir, &self.target_dir, immutable_file_number)
                    .await
            }
            VerifiedDownload::AncillaryFiles(validated_manifest) => {
                validated_manifest.move_to_final_location(&self.target_dir).await
            }
        }
    }

    /// The staging directory where this download is unpacked.
    fn staging_directory_path(&self) -> PathBuf {
        let download_id = self.download_event.download_id();
        match &self.kind {
            DownloadKind::Immutable(immutable_file_number) => {
                Self::immutable_staging_directory_path(
                    &self.target_dir,
                    *immutable_file_number,
                    download_id,
                )
            }
            DownloadKind::Ancillary { .. } => {
                Self::ancillary_staging_directory_path(&self.target_dir, download_id)
            }
        }
    }

    /// The staging directory of an immutable archive, a sibling of the immutable directory under
    /// the target directory so that the promoted files are renamed on the same filesystem.
    fn immutable_staging_directory_path(
        target_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
        download_id: &str,
    ) -> PathBuf {
        target_dir.join(format!(
            "{}{immutable_file_number:05}-{download_id}",
            Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX
        ))
    }

    /// The staging directory of the ancillary archive, a sibling of its final location under the
    /// target directory.
    fn ancillary_staging_directory_path(target_dir: &Path, download_id: &str) -> PathBuf {
        target_dir.join(format!(
            "{}{download_id}",
            Self::ANCILLARY_STAGING_DIRECTORY_PREFIX
        ))
    }

    /// Tell if a name is the one of a staging directory of the given download.
    pub fn is_staging_directory_name(name: &str, download_id: &str) -> bool {
        name.ends_with(&format!("-{download_id}"))
            && (name.starts_with(Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX)
                || name.starts_with(Self::ANCILLARY_STAGING_DIRECTORY_PREFIX))
    }

    /// Tell if a name is the one of a staging directory, whatever the download it belongs to.
    pub fn is_staging_directory_name_of_any_download(name: &str) -> bool {
        let download_id = match name.strip_prefix(Self::IMMUTABLE_STAGING_DIRECTORY_PREFIX) {
            Some(immutable_suffix) => {
                immutable_suffix
                    .split_once('-')
                    .and_then(|(file_number, download_id)| {
                        let is_file_number = !file_number.is_empty()
                            && file_number.chars().all(|character| character.is_ascii_digit());
                        is_file_number.then_some(download_id)
                    })
            }
            None => name.strip_prefix(Self::ANCILLARY_STAGING_DIRECTORY_PREFIX),
        };

        download_id.is_some_and(|download_id| Uuid::parse_str(download_id).is_ok())
    }

    /// Check that the unpacked immutable archive holds exactly the immutable directory and the
    /// regular files of the immutable trio, nothing else.
    async fn verify_immutable_archive_members(
        staging_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
    ) -> MithrilResult<()> {
        let staging_entries = Self::list_entry_names(staging_dir).await?;
        let expected_staging_entries = BTreeSet::from([IMMUTABLE_DIR.to_string()]);
        if staging_entries != expected_staging_entries {
            anyhow::bail!(
                "Unexpected entries in the archive of immutable file {immutable_file_number}: expected {expected_staging_entries:?}, found {staging_entries:?}"
            );
        }

        let staged_immutable_dir = staging_dir.join(IMMUTABLE_DIR);
        let expected_names: BTreeSet<String> =
            immutable_trio_names(immutable_file_number).into_iter().collect();
        let found_names = Self::list_entry_names(&staged_immutable_dir).await?;
        if found_names != expected_names {
            anyhow::bail!(
                "Unexpected content in the archive of immutable file {immutable_file_number}: expected {expected_names:?}, found {found_names:?}"
            );
        }

        for name in &expected_names {
            let path = staged_immutable_dir.join(name);
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .with_context(|| format!("Could not read metadata of '{}'", path.display()))?;
            if !metadata.is_file() {
                anyhow::bail!(
                    "Entry '{name}' of the archive of immutable file {immutable_file_number} is not a regular file"
                );
            }
        }

        Ok(())
    }

    /// List the names of the entries of a directory.
    async fn list_entry_names(dir: &Path) -> MithrilResult<BTreeSet<String>> {
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .with_context(|| format!("Could not read directory '{}'", dir.display()))?;
        let mut names = BTreeSet::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("Could not read an entry of directory '{}'", dir.display()))?
        {
            names.insert(entry.file_name().to_string_lossy().to_string());
        }

        Ok(names)
    }

    /// Move the immutable trio from the staging directory to the immutable directory of the
    /// target directory, creating the latter when it does not exist.
    async fn promote_immutable_files(
        staging_dir: &Path,
        target_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
    ) -> MithrilResult<()> {
        let target_immutable_dir = target_dir.join(IMMUTABLE_DIR);
        tokio::fs::create_dir_all(&target_immutable_dir)
            .await
            .with_context(|| {
                format!(
                    "Could not create directory '{}'",
                    target_immutable_dir.display()
                )
            })?;
        for name in immutable_trio_names(immutable_file_number) {
            let source = staging_dir.join(IMMUTABLE_DIR).join(&name);
            let destination = target_immutable_dir.join(&name);
            move_file(&source, &destination).await.with_context(|| {
                format!(
                    "Could not move '{}' to '{}'",
                    source.display(),
                    destination.display()
                )
            })?;
        }

        Ok(())
    }

    /// Build a future that will download and unpack the file when awaited.
    ///
    /// The download is attempted for each location until the file is downloaded.
    /// If all locations fail, an error is returned.
    pub fn build_download_future(self, logger: Logger) -> Pin<Box<DownloadFuture>> {
        let download_future = async move {
            let staging_directory =
                StagingDirectory::create(self.staging_directory_path(), &logger)?;
            let download_result = self.download_unpack_file(&staging_directory, &logger).await;
            staging_directory.remove().await;

            download_result
        };

        Box::pin(download_future)
    }
}

/// The content of a staging directory once verified, ready to be moved to its final place.
enum VerifiedDownload {
    /// The trio of an immutable file number
    ImmutableTrio(ImmutableFileNumber),
    /// The files listed by a valid ancillary manifest
    AncillaryFiles(ValidatedAncillaryManifest),
}

/// A directory where one download is unpacked, removed when dropped so that a cancelled or failed
/// download leaves nothing behind.
struct StagingDirectory {
    /// Path of the directory
    path: PathBuf,
    /// Logger used to report a failed removal
    logger: Logger,
    /// Set once the asynchronous removal ran, so that the drop does not remove the directory again
    removed: bool,
}

impl StagingDirectory {
    /// Create the directory synchronously so that no cancellation point exists between its
    /// creation and the guard that removes it.
    fn create(path: PathBuf, logger: &Logger) -> MithrilResult<Self> {
        std::fs::create_dir(&path).with_context(|| {
            format!(
                "can not create download staging directory '{}'",
                path.display()
            )
        })?;

        Ok(Self {
            path,
            logger: logger.clone(),
            removed: false,
        })
    }

    /// Path of the staging directory
    fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory without blocking the runtime, in one attempt: the sweep of the download
    /// is the backstop. The synchronous removal of the drop is kept for a cancellation.
    async fn remove(mut self) {
        if let Err(error) = tokio::fs::remove_dir_all(&self.path).await
            && error.kind() != io::ErrorKind::NotFound
        {
            slog::warn!(
                self.logger, "Failed to remove download staging directory '{}'", self.path.display();
                "error" => ?error
            );
        }
        self.removed = true;
    }

    /// Remove the content left by a previous location attempt, keeping the directory itself so that
    /// nothing has to recreate it after a cancellation.
    async fn reset(&self) -> MithrilResult<()> {
        let mut entries = tokio::fs::read_dir(&self.path).await.with_context(|| {
            format!(
                "can not read download staging directory '{}'",
                self.path.display()
            )
        })?;
        while let Some(entry) = entries.next_entry().await.with_context(|| {
            format!(
                "can not read an entry of download staging directory '{}'",
                self.path.display()
            )
        })? {
            let entry_path = entry.path();
            let entry_type = entry.file_type().await.with_context(|| {
                format!(
                    "can not read the type of '{}' in the download staging directory",
                    entry_path.display()
                )
            })?;
            let removed = if entry_type.is_dir() {
                tokio::fs::remove_dir_all(&entry_path).await
            } else {
                tokio::fs::remove_file(&entry_path).await
            };
            removed.with_context(|| {
                format!(
                    "can not remove '{}' from the download staging directory",
                    entry_path.display()
                )
            })?;
        }

        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if !self.removed
            && let Err(error) = std::fs::remove_dir_all(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            slog::warn!(
                self.logger, "Failed to remove download staging directory '{}'", self.path.display();
                "error" => ?error
            );
        }
    }
}

pub enum DownloadKind {
    Immutable(ImmutableFileNumber),
    Ancillary { verifier: Arc<AncillaryVerifier> },
}

/// A circuit breaker for a download location, meant to be shared across every location backed by
/// the same downloader kind within one batch (e.g., one per download_unpack() call for all Ipfs locations).
#[derive(Clone)]
pub struct CircuitBreaker(Arc<AtomicBool>);

impl CircuitBreaker {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    #[cfg(test)]
    pub fn new_triggered() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn trigger(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_triggered(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LocationToDownload {
    pub file_downloader: Arc<dyn FileDownloader>,
    pub file_downloader_uri: FileDownloaderUri,
    pub compression_algorithm: Option<CompressionAlgorithm>,
    pub circuit_breaker: Option<CircuitBreaker>,
}

impl LocationToDownload {
    pub fn is_circuit_breaker_triggered(&self) -> bool {
        self.circuit_breaker
            .as_ref()
            .is_some_and(|breaker| breaker.is_triggered())
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use async_trait::async_trait;

    use mithril_common::StdResult;
    use mithril_common::entities::FileUri;
    use mithril_common::test::{assert_dir_eq, double::fake_keys, temp_dir_create};

    use crate::file_downloader::{MockFileDownloader, MockFileDownloaderBuilder};
    use crate::test_utils::TestLogger;

    use super::*;

    fn create_locations_to_download<U>(
        file_downloader: Arc<dyn FileDownloader>,
        uris: U,
    ) -> Vec<LocationToDownload>
    where
        U: IntoIterator,
        U::Item: AsRef<str>,
    {
        uris.into_iter()
            .map(|uri| LocationToDownload {
                file_downloader: file_downloader.clone(),
                file_downloader_uri: FileDownloaderUri::FileUri(FileUri(uri.as_ref().to_string())),
                compression_algorithm: Some(CompressionAlgorithm::default()),
                circuit_breaker: None,
            })
            .collect()
    }

    struct PendingFileDownloader;

    #[async_trait]
    impl FileDownloader for PendingFileDownloader {
        async fn download_unpack(
            &self,
            _location: &FileDownloaderUri,
            _file_size: u64,
            _target_dir: &Path,
            _compression_algorithm: Option<CompressionAlgorithm>,
            _download_event_type: DownloadEvent,
        ) -> StdResult<()> {
            pending().await
        }
    }

    struct PanickingFileDownloader;

    #[async_trait]
    impl FileDownloader for PanickingFileDownloader {
        async fn download_unpack(
            &self,
            _location: &FileDownloaderUri,
            _file_size: u64,
            _target_dir: &Path,
            _compression_algorithm: Option<CompressionAlgorithm>,
            _download_event_type: DownloadEvent,
        ) -> StdResult<()> {
            panic!("the download panics")
        }
    }

    const MAX_YIELDS_WAITING_FOR_A_PATH: usize = 1_000_000;

    async fn wait_until_exists(path: &Path) {
        for _ in 0..MAX_YIELDS_WAITING_FOR_A_PATH {
            if path.exists() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("'{}' was never created", path.display());
    }

    mod download_unpack_immutable_files {
        use super::*;

        type StagedContent = fn(&Path) -> StdResult<()>;

        const FIRST_LOCATION: &str = "http://whatever-1/00001.tar.zst";
        const SECOND_LOCATION: &str = "http://whatever-2/00001.tar.zst";
        const FULL_TRIO: [&str; 3] = ["00001.chunk", "00001.primary", "00001.secondary"];
        const PROMOTED_TRIO: &str = "* immutable/
            ** 00001.chunk
            ** 00001.primary
            ** 00001.secondary";

        fn immutable_download_task<U>(
            file_downloader: Arc<dyn FileDownloader>,
            target_dir: &Path,
            uris: U,
        ) -> DownloadTask
        where
            U: IntoIterator,
            U::Item: AsRef<str>,
        {
            DownloadTask {
                kind: DownloadKind::Immutable(1),
                locations_to_try: create_locations_to_download(file_downloader, uris),
                size_uncompressed: 0,
                target_dir: target_dir.to_path_buf(),
                download_event: DownloadEvent::Immutable {
                    download_id: "download_id".to_string(),
                    immutable_file_number: 1,
                },
            }
        }

        async fn download<U>(
            file_downloader: MockFileDownloader,
            target_dir: &Path,
            uris: U,
        ) -> MithrilResult<()>
        where
            U: IntoIterator,
            U::Item: AsRef<str>,
        {
            immutable_download_task(Arc::new(file_downloader), target_dir, uris)
                .build_download_future(TestLogger::stdout())
                .await
        }

        fn first_location_staging(staged_content: StagedContent) -> MockFileDownloaderBuilder {
            MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_returning(Box::new(move |_, _, unpack_dir: &Path, _, _| {
                    staged_content(unpack_dir)
                }))
        }

        fn first_location_staging_a_valid_trio() -> MockFileDownloaderBuilder {
            MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_success_and_create_fake_immutable_files()
        }

        fn create_immutable_trio(unpack_dir: &Path, names: &[&str]) {
            let immutable_dir = unpack_dir.join(IMMUTABLE_DIR);
            std::fs::create_dir_all(&immutable_dir).unwrap();
            for name in names {
                std::fs::File::create(immutable_dir.join(name)).unwrap();
            }
        }

        fn then_second_location_staging_a_valid_trio(
            first_location: MockFileDownloaderBuilder,
        ) -> MockFileDownloader {
            first_location
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_success_and_create_fake_immutable_files()
                .build()
        }

        #[cfg(unix)]
        fn create_read_only_immutable_dir(target_dir: &Path) -> PathBuf {
            let immutable_dir = target_dir.join(IMMUTABLE_DIR);
            std::fs::create_dir_all(&immutable_dir).unwrap();
            std::fs::set_permissions(&immutable_dir, std::fs::Permissions::from_mode(0o555))
                .unwrap();
            immutable_dir
        }

        #[cfg(unix)]
        fn make_writable(dir: &Path) {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn create_file(parent_dir: &Path, name: &str) {
            std::fs::create_dir_all(parent_dir).unwrap();
            std::fs::File::create(parent_dir.join(name)).unwrap();
        }

        fn assert_staging_directory_is_removed(target_dir: &Path) {
            assert!(
                !DownloadTask::immutable_staging_directory_path(target_dir, 1, "download_id")
                    .exists(),
                "the staging directory must be removed"
            );
        }

        fn assert_target_dir_is_empty(target_dir: &Path) {
            assert!(
                std::fs::read_dir(target_dir).unwrap().next().is_none(),
                "target directory must be left empty"
            );
        }

        #[tokio::test]
        async fn fails_if_no_location_is_retrieved() {
            let target_dir = temp_dir_create!();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_times(2)
                .with_failure()
                .build();

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect_err("downloading should fail when all locations fail");

            assert!(
                !DownloadTask::immutable_staging_directory_path(&target_dir, 1, "download_id")
                    .exists()
            );
            assert_target_dir_is_empty(&target_dir);
        }

        #[tokio::test]
        async fn succeeds_if_at_least_one_location_is_retrieved() {
            let target_dir = temp_dir_create!();
            let staging_dir =
                DownloadTask::immutable_staging_directory_path(&target_dir, 1, "download_id");
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_target_dir(staging_dir.clone())
                .with_failure()
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_target_dir(staging_dir)
                .with_success_and_create_fake_immutable_files()
                .build();

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn unpacks_in_a_staging_directory_then_promotes_only_the_immutable_trio() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging_a_valid_trio()
                .with_target_dir(DownloadTask::immutable_staging_directory_path(
                    &target_dir,
                    1,
                    "download_id",
                ))
                .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .unwrap();

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn rejects_an_archive_with_an_entry_outside_the_immutable_trio_and_leaves_nothing() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_immutable_trio(unpack_dir, &FULL_TRIO);
                create_file(&unpack_dir.join("ledger"), "state");
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("an archive with an entry outside the immutable trio must be rejected");

            assert_target_dir_is_empty(&target_dir);
        }

        #[tokio::test]
        async fn rejects_an_archive_missing_a_file_of_the_immutable_trio_and_leaves_nothing() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_immutable_trio(unpack_dir, &["00001.chunk", "00001.primary"]);
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("an archive missing a file of the immutable trio must be rejected");

            assert_target_dir_is_empty(&target_dir);
        }

        #[tokio::test]
        async fn rejects_an_archive_whose_trio_entry_is_not_a_regular_file_and_leaves_nothing() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_immutable_trio(unpack_dir, &["00001.primary", "00001.secondary"]);
                std::fs::create_dir_all(unpack_dir.join(IMMUTABLE_DIR).join("00001.chunk"))
                    .unwrap();
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("a trio entry that is a directory must be rejected");

            assert_target_dir_is_empty(&target_dir);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn rejects_an_archive_whose_trio_entry_is_a_symlink_and_leaves_nothing() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_immutable_trio(unpack_dir, &["00001.primary", "00001.secondary"]);
                create_file(unpack_dir.parent().unwrap(), "outside_file");
                std::os::unix::fs::symlink(
                    unpack_dir.parent().unwrap().join("outside_file"),
                    unpack_dir.join(IMMUTABLE_DIR).join("00001.chunk"),
                )
                .unwrap();
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("a trio entry that is a symlink must be rejected");

            assert_dir_eq!(&target_dir, "* outside_file");
        }

        #[tokio::test]
        async fn rejects_an_archive_carrying_a_file_of_another_immutable_and_leaves_nothing() {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_immutable_trio(unpack_dir, &FULL_TRIO);
                create_immutable_trio(unpack_dir, &["00002.chunk"]);
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("a file of another immutable must be rejected");

            assert_target_dir_is_empty(&target_dir);
        }

        #[tokio::test]
        async fn rejects_a_download_that_leaves_a_raw_file_instead_of_an_archive_and_leaves_nothing()
         {
            let target_dir = temp_dir_create!();
            let file_downloader = first_location_staging(|unpack_dir| {
                create_file(unpack_dir, "download_id");
                Ok(())
            })
            .build();

            download(file_downloader, &target_dir, [FIRST_LOCATION])
                .await
                .expect_err("a raw file in place of the immutable archive must be rejected");

            assert_target_dir_is_empty(&target_dir);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_first_one_leaves_a_stray_entry() {
            let target_dir = temp_dir_create!();
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging(|unpack_dir| {
                    create_immutable_trio(unpack_dir, &FULL_TRIO);
                    create_file(unpack_dir, "extra");
                    Err(anyhow!("truncated stream"))
                }));

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("the second location must succeed");

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_first_one_leaves_a_stray_directory() {
            let target_dir = temp_dir_create!();
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging(|unpack_dir| {
                    create_immutable_trio(unpack_dir, &FULL_TRIO);
                    create_file(&unpack_dir.join("ledger"), "state");
                    Err(anyhow!("truncated stream"))
                }));

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("the second location must succeed");

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_first_archive_fails_verification() {
            let target_dir = temp_dir_create!();
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging(|unpack_dir| {
                    create_immutable_trio(unpack_dir, &["00001.chunk", "00001.primary"]);
                    Ok(())
                }));

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("the second location must succeed");

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_download_fails_with_a_permission_denied_cause()
         {
            let target_dir = temp_dir_create!();
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging(|_| {
                    Err(
                        anyhow::Error::from(io::Error::from(io::ErrorKind::PermissionDenied))
                            .context("connection rejected"),
                    )
                }));

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("a download failure of the first location must not stop the task");

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_unpack_fails_with_a_storage_full_cause() {
            let target_dir = temp_dir_create!();
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging(|unpack_dir| {
                    create_file(unpack_dir, "partial");
                    Err(
                        anyhow::Error::from(io::Error::from(io::ErrorKind::StorageFull))
                            .context("could not write the archive entry"),
                    )
                }));

            download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("an unpack failure of the first location must not stop the task");

            assert_dir_eq!(&target_dir, PROMOTED_TRIO);
        }

        #[tokio::test]
        async fn aborting_the_download_future_removes_the_staging_directory() {
            let target_dir = temp_dir_create!();
            let staging_dir =
                DownloadTask::immutable_staging_directory_path(&target_dir, 1, "download_id");
            let download_future = immutable_download_task(
                Arc::new(PendingFileDownloader),
                &target_dir,
                [FIRST_LOCATION],
            )
            .build_download_future(TestLogger::stdout());
            let handle = tokio::spawn(download_future);
            wait_until_exists(&staging_dir).await;

            handle.abort();
            handle.await.expect_err("the download future is cancelled");

            assert!(
                !staging_dir.exists(),
                "a cancelled download must not leave its staging directory"
            );
            assert_target_dir_is_empty(&target_dir);
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn promotes_the_immutable_trio_to_an_immutable_directory_on_another_filesystem() {
            let target_dir = temp_dir_create!();
            let other_filesystem_dir = Path::new("/dev/shm").join(format!(
                "mithril_client_promotes_the_immutable_trio_{}",
                std::process::id()
            ));
            assert_ne!(
                std::fs::metadata(&target_dir).unwrap().dev(),
                std::fs::metadata("/dev/shm").unwrap().dev(),
                "this test needs '/dev/shm' and the temporary directory on two filesystems"
            );
            let _ = std::fs::remove_dir_all(&other_filesystem_dir);
            std::fs::create_dir(&other_filesystem_dir).unwrap();
            std::os::unix::fs::symlink(&other_filesystem_dir, target_dir.join(IMMUTABLE_DIR))
                .unwrap();

            let result = download(
                first_location_staging_a_valid_trio().build(),
                &target_dir,
                [FIRST_LOCATION],
            )
            .await;

            let promoted_trio: Vec<bool> = FULL_TRIO
                .iter()
                .map(|name| other_filesystem_dir.join(name).is_file())
                .collect();
            std::fs::remove_dir_all(&other_filesystem_dir).unwrap();
            result.expect("the trio must be promoted across filesystems");
            assert_eq!(vec![true, true, true], promoted_trio);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn stops_without_trying_the_next_location_when_the_promotion_fails_locally() {
            let target_dir = temp_dir_create!();
            let immutable_dir = create_read_only_immutable_dir(&target_dir);

            let result = download(
                first_location_staging_a_valid_trio().build(),
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await;

            make_writable(&immutable_dir);
            let error = result.expect_err("a local promotion failure must stop the task");
            assert!(
                format!("{error:?}").contains("Could not move"),
                "unexpected error: {error:?}"
            );
            assert_staging_directory_is_removed(&target_dir);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn reports_the_task_and_the_location_when_the_promotion_fails_locally() {
            let target_dir = temp_dir_create!();
            let immutable_dir = create_read_only_immutable_dir(&target_dir);
            let (logger, log_inspector) = TestLogger::memory();

            let result = immutable_download_task(
                Arc::new(first_location_staging_a_valid_trio().build()),
                &target_dir,
                [FIRST_LOCATION],
            )
            .build_download_future(logger)
            .await;

            make_writable(&immutable_dir);
            let error = result.expect_err("a local promotion failure must stop the task");
            let error_message = format!("{error:?}");
            assert!(
                error_message.contains("immutable_file_00001")
                    && error_message.contains(&format!("{FIRST_LOCATION:?}")),
                "the error must name the task and the location: {error_message}"
            );
            assert!(
                log_inspector.contains_log(FIRST_LOCATION),
                "the failure must be logged with its location"
            );
            assert_staging_directory_is_removed(&target_dir);
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_promotion_fails_with_another_io_error_kind()
         {
            let target_dir = temp_dir_create!();
            create_file(
                &target_dir.join(IMMUTABLE_DIR).join("00001.chunk"),
                "content",
            );
            let file_downloader =
                then_second_location_staging_a_valid_trio(first_location_staging_a_valid_trio());

            let error = download(
                file_downloader,
                &target_dir,
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect_err("no location can be promoted over a directory");

            assert!(
                error.to_string().contains("All locations failed"),
                "every location must have been tried: {error:?}"
            );
            assert_staging_directory_is_removed(&target_dir);
        }

        #[tokio::test]
        async fn escapes_control_characters_of_the_location_uris_in_the_error() {
            let target_dir = temp_dir_create!();
            let file_downloader = MockFileDownloaderBuilder::default().with_failure().build();

            let error = download(
                file_downloader,
                &target_dir,
                ["http://whatever/00001.tar.zst\x1b[31m"],
            )
            .await
            .expect_err("downloading should fail when all locations fail");

            assert!(
                !error.to_string().contains('\x1b'),
                "the error must not carry raw control characters: {error:?}"
            );
        }
    }

    mod download_unpack_ancillary_file {
        use std::collections::BTreeMap;

        use sha2::{Digest, Sha256};

        use mithril_cardano_node_internal_database::entities::AncillaryFilesManifest;
        use mithril_common::crypto_helper::ManifestSigner;

        use crate::file_downloader::FakeAncillaryFileBuilder;
        use crate::utils::AncillaryVerificationError;

        use super::*;

        const FIRST_LOCATION: &str = "http://whatever-1/ancillary.tar.zst";
        const SECOND_LOCATION: &str = "http://whatever-2/ancillary.tar.zst";

        fn fake_ancillary_verifier() -> AncillaryVerifier {
            AncillaryVerifier::new(fake_keys::manifest_verification_key()[0].try_into().unwrap())
        }

        fn verifier_of(signer: &ManifestSigner) -> AncillaryVerifier {
            AncillaryVerifier::new(signer.verification_key())
        }

        fn ancillary_download_task<U>(
            file_downloader: Arc<dyn FileDownloader>,
            target_dir: &Path,
            verifier: AncillaryVerifier,
            uris: U,
        ) -> DownloadTask
        where
            U: IntoIterator,
            U::Item: AsRef<str>,
        {
            DownloadTask {
                kind: DownloadKind::Ancillary {
                    verifier: Arc::new(verifier),
                },
                locations_to_try: create_locations_to_download(file_downloader, uris),
                size_uncompressed: 0,
                target_dir: target_dir.to_path_buf(),
                download_event: DownloadEvent::Ancillary {
                    download_id: "download_id".to_string(),
                },
            }
        }

        async fn download<U>(
            file_downloader: MockFileDownloader,
            target_dir: &Path,
            verifier: AncillaryVerifier,
            uris: U,
        ) -> MithrilResult<()>
        where
            U: IntoIterator,
            U::Item: AsRef<str>,
        {
            ancillary_download_task(Arc::new(file_downloader), target_dir, verifier, uris)
                .build_download_future(TestLogger::stdout())
                .await
        }

        fn unsigned_ancillary_files(file_name: &str) -> FakeAncillaryFileBuilder {
            FakeAncillaryFileBuilder::builder()
                .files_in_manifest_to_create(vec![file_name.to_string()])
                .build()
        }

        fn signed_ancillary_files(
            file_name: &str,
            signer: &ManifestSigner,
        ) -> FakeAncillaryFileBuilder {
            FakeAncillaryFileBuilder::builder()
                .files_in_manifest_to_create(vec![file_name.to_string()])
                .sign_manifest(signer.clone())
                .build()
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn stops_without_trying_the_next_location_when_the_ancillary_promotion_fails_locally()
        {
            let target_dir = temp_dir_create!();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let manifest_signer = ancillary_signer.clone();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_returning(Box::new(move |_, _, unpack_dir: &Path, _, _| {
                    std::fs::File::create(unpack_dir.join("dummy_ledger")).unwrap();
                    let mut manifest =
                        AncillaryFilesManifest::new_without_signature(BTreeMap::from([(
                            PathBuf::from("dummy_ledger"),
                            hex::encode(Sha256::digest(b"")),
                        )]));
                    manifest.set_signature(manifest_signer.sign(&manifest.compute_hash()));
                    serde_json::to_writer(
                        std::fs::File::create(
                            unpack_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME),
                        )
                        .unwrap(),
                        &manifest,
                    )
                    .unwrap();
                    std::fs::set_permissions(
                        unpack_dir.parent().unwrap(),
                        std::fs::Permissions::from_mode(0o555),
                    )
                    .unwrap();
                    Ok(())
                }))
                .build();

            let result = download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await;

            std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let error = result.expect_err("a local promotion failure must stop the task");
            assert!(
                format!("{error:?}").contains("Could not promote ancillary"),
                "unexpected error: {error:?}"
            );
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_first_ancillary_manifest_is_not_readable()
        {
            let target_dir = temp_dir_create!();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_returning(Box::new(|_, _, unpack_dir: &Path, _, _| {
                    let manifest_path =
                        unpack_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME);
                    std::fs::File::create(&manifest_path).unwrap();
                    std::fs::set_permissions(
                        &manifest_path,
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                    Ok(())
                }))
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "dummy_ledger",
                    &ancillary_signer,
                ))
                .build();

            download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("a verification failure of the first location must not stop the task");

            assert_dir_eq!(&target_dir, "* dummy_ledger");
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_first_ancillary_archive_fails_verification()
         {
            let target_dir = temp_dir_create!();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_success_and_create_fake_ancillary_files(unsigned_ancillary_files(
                    "dummy_ledger",
                ))
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "dummy_ledger",
                    &ancillary_signer,
                ))
                .build();

            download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect("the second location must succeed");

            assert_dir_eq!(&target_dir, "* dummy_ledger");
        }

        #[tokio::test]
        async fn aborting_the_download_future_removes_the_ancillary_staging_directory() {
            let target_dir = temp_dir_create!();
            let staging_dir =
                DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id");
            let download_task = ancillary_download_task(
                Arc::new(PendingFileDownloader),
                &target_dir,
                fake_ancillary_verifier(),
                [FIRST_LOCATION],
            );
            let handle = tokio::spawn(download_task.build_download_future(TestLogger::stdout()));
            wait_until_exists(&staging_dir).await;

            handle.abort();
            handle.await.expect_err("the download future is cancelled");

            assert!(
                !staging_dir.exists(),
                "a cancelled download must not leave its staging directory"
            );
        }

        #[tokio::test]
        async fn a_panicking_download_removes_the_ancillary_staging_directory() {
            let target_dir = temp_dir_create!();
            let download_task = ancillary_download_task(
                Arc::new(PanickingFileDownloader),
                &target_dir,
                fake_ancillary_verifier(),
                [FIRST_LOCATION],
            );

            let join_error =
                tokio::spawn(download_task.build_download_future(TestLogger::stdout()))
                    .await
                    .expect_err("the download future panics");

            assert!(join_error.is_panic());
            assert!(
                !DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id")
                    .exists(),
                "a panicking download must not leave its staging directory"
            );
        }

        #[tokio::test]
        async fn falls_back_to_the_next_location_when_the_ancillary_promotion_fails_with_another_io_error_kind()
         {
            let target_dir = temp_dir_create!();
            let occupied_path = target_dir.join("dummy_ledger");
            std::fs::create_dir(&occupied_path).unwrap();
            std::fs::File::create(occupied_path.join("content")).unwrap();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "dummy_ledger",
                    &ancillary_signer,
                ))
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "dummy_ledger",
                    &ancillary_signer,
                ))
                .build();

            let error = download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .expect_err("no location can be promoted over a directory");

            assert!(
                error.to_string().contains("All locations failed"),
                "every location must have been tried: {error:?}"
            );
            assert!(
                !DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id")
                    .exists()
            );
        }

        #[tokio::test]
        async fn fails_and_delete_temp_ancillary_download_dir_if_no_location_is_retrieved() {
            let target_dir = temp_dir_create!();
            let file_downloader = MockFileDownloaderBuilder::default().with_failure().build();

            download(
                file_downloader,
                &target_dir,
                fake_ancillary_verifier(),
                [FIRST_LOCATION],
            )
            .await
            .expect_err("batch_download_unpack of ancillary file should fail");

            assert!(
                !DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id")
                    .exists()
            );
        }

        #[tokio::test]
        async fn succeeds_if_at_least_one_location_is_retrieved() {
            let target_dir = temp_dir_create!();
            let staging_dir =
                DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id");
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_target_dir(staging_dir.clone())
                .with_failure()
                .next_call()
                .with_file_uri(SECOND_LOCATION)
                .with_target_dir(staging_dir)
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "ledger",
                    &ancillary_signer,
                ))
                .build();

            download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn succeeds_when_first_location_is_retrieved() {
            let target_dir = temp_dir_create!();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_target_dir(DownloadTask::ancillary_staging_directory_path(
                    &target_dir,
                    "download_id",
                ))
                .with_success_and_create_fake_ancillary_files(signed_ancillary_files(
                    "ledger",
                    &ancillary_signer,
                ))
                .build();

            download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION, SECOND_LOCATION],
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn fail_and_delete_temp_ancillary_download_dir_if_verify_fail() {
            let target_dir = temp_dir_create!();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_success_and_create_fake_ancillary_files(unsigned_ancillary_files("ledger"))
                .build();

            download(
                file_downloader,
                &target_dir,
                fake_ancillary_verifier(),
                [FIRST_LOCATION],
            )
            .await
            .expect_err("an unsigned manifest must fail the verification");

            assert!(
                !DownloadTask::ancillary_staging_directory_path(&target_dir, "download_id")
                    .exists()
            );
        }

        #[tokio::test]
        async fn returns_the_verification_failure_of_the_last_location_as_the_cause_of_the_error() {
            let target_dir = temp_dir_create!();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_success_and_create_fake_ancillary_files(unsigned_ancillary_files("ledger"))
                .build();

            let error = download(
                file_downloader,
                &target_dir,
                fake_ancillary_verifier(),
                [FIRST_LOCATION],
            )
            .await
            .expect_err("an unsigned manifest must fail the verification");

            assert!(
                error.to_string().contains("All locations failed"),
                "unexpected error: {error:?}"
            );
            assert!(
                matches!(
                    error.downcast_ref::<AncillaryVerificationError>(),
                    Some(AncillaryVerificationError::SignatureMissing)
                ),
                "the verification failure must be the cause of the error: {error:?}"
            );
        }

        #[tokio::test]
        async fn move_file_in_manifest_then_delete_temporary_unpack_subfolder_if_verify_succeed() {
            let target_dir = temp_dir_create!();
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let file_downloader = MockFileDownloaderBuilder::default()
                .with_file_uri(FIRST_LOCATION)
                .with_target_dir(DownloadTask::ancillary_staging_directory_path(
                    &target_dir,
                    "download_id",
                ))
                .with_success_and_create_fake_ancillary_files(
                    FakeAncillaryFileBuilder::builder()
                        .files_in_manifest_to_create(vec!["dummy_ledger".to_string()])
                        .files_not_in_manifest_to_create(vec!["not_in_ancillary".to_string()])
                        .sign_manifest(ancillary_signer.clone())
                        .build(),
                )
                .build();

            download(
                file_downloader,
                &target_dir,
                verifier_of(&ancillary_signer),
                [FIRST_LOCATION],
            )
            .await
            .unwrap();

            assert_dir_eq!(&target_dir, "* dummy_ledger");
        }
    }

    mod staging_directory_name {
        use super::*;

        const DOWNLOAD_ID: &str = "0c8d8ea5-7b0c-4d7d-9d7f-5a4a3b1f2e10";

        #[test]
        fn an_immutable_staging_directory_name_is_recognized() {
            assert!(DownloadTask::is_staging_directory_name_of_any_download(
                &format!("immutable-00001-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_immutable_staging_directory_name_with_a_long_file_number_is_recognized() {
            assert!(DownloadTask::is_staging_directory_name_of_any_download(
                &format!("immutable-123456-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_ancillary_staging_directory_name_is_recognized() {
            assert!(DownloadTask::is_staging_directory_name_of_any_download(
                &format!("ancillary-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn the_immutable_directory_name_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                IMMUTABLE_DIR
            ));
        }

        #[test]
        fn an_immutable_name_without_a_download_id_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                "immutable-00001"
            ));
        }

        #[test]
        fn an_immutable_name_with_an_invalid_download_id_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                "immutable-00001-notes"
            ));
        }

        #[test]
        fn an_immutable_name_with_an_invalid_file_number_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                &format!("immutable-notes-{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_immutable_name_without_a_file_number_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                &format!("immutable--{DOWNLOAD_ID}")
            ));
        }

        #[test]
        fn an_ancillary_name_with_an_invalid_download_id_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                "ancillary-notes"
            ));
        }

        #[test]
        fn a_name_with_another_prefix_is_not_a_staging_directory_name() {
            assert!(!DownloadTask::is_staging_directory_name_of_any_download(
                &format!("notes-{DOWNLOAD_ID}")
            ));
        }
    }

    mod fatal_local_error {
        use super::*;

        fn error_caused_by(kind: io::ErrorKind) -> anyhow::Error {
            anyhow::Error::from(io::Error::from(kind)).context("could not move")
        }

        #[test]
        fn a_storage_full_cause_is_fatal() {
            assert!(DownloadTask::is_fatal_local_error(&error_caused_by(
                io::ErrorKind::StorageFull
            )));
        }

        #[test]
        fn a_permission_denied_cause_is_fatal() {
            assert!(DownloadTask::is_fatal_local_error(&error_caused_by(
                io::ErrorKind::PermissionDenied
            )));
        }

        #[test]
        fn another_io_cause_is_not_fatal() {
            assert!(!DownloadTask::is_fatal_local_error(&error_caused_by(
                io::ErrorKind::NotFound
            )));
        }

        #[test]
        fn an_error_without_io_cause_is_not_fatal() {
            assert!(!DownloadTask::is_fatal_local_error(&anyhow!("no io cause")));
        }
    }

    mod staging_directory {
        use super::*;

        #[cfg(unix)]
        #[tokio::test]
        async fn removing_the_staging_directory_warns_once_when_the_removal_fails() {
            let temp_dir = temp_dir_create!();
            let (logger, log_inspector) = TestLogger::memory();
            let staging_directory =
                StagingDirectory::create(temp_dir.join("staging"), &logger).unwrap();
            let locked_dir = staging_directory.path().join("locked");
            std::fs::create_dir(&locked_dir).unwrap();
            std::fs::File::create(locked_dir.join("file")).unwrap();
            std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

            staging_directory.remove().await;

            std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                1,
                log_inspector
                    .search_logs("Failed to remove download staging directory")
                    .len(),
                "one asynchronous removal attempt must warn once"
            );
        }
    }

    mod circuit_breaker {
        use super::*;

        #[tokio::test]
        async fn skip_to_next_location_if_first_location_circuit_breaker_was_triggered() {
            let target_dir = temp_dir_create!();
            let logger = TestLogger::stdout();
            let file_downloader = Arc::new(
                MockFileDownloaderBuilder::default()
                    .with_file_uri("http://whatever-2/00001.tar.zst")
                    .with_target_dir(DownloadTask::immutable_staging_directory_path(
                        &target_dir,
                        1,
                        "download_id",
                    ))
                    .with_compression(None)
                    .with_success_and_create_fake_immutable_files()
                    .build(),
            );

            let download_task = DownloadTask {
                kind: DownloadKind::Immutable(1),
                locations_to_try: vec![
                    LocationToDownload {
                        file_downloader: file_downloader.clone(),
                        file_downloader_uri: FileDownloaderUri::FileUri(FileUri(
                            "http://whatever-1/00001.tar.zst".to_string(),
                        )),
                        compression_algorithm: None,
                        circuit_breaker: Some(CircuitBreaker::new_triggered()),
                    },
                    LocationToDownload {
                        file_downloader: file_downloader.clone(),
                        file_downloader_uri: FileDownloaderUri::FileUri(FileUri(
                            "http://whatever-2/00001.tar.zst".to_string(),
                        )),
                        compression_algorithm: None,
                        circuit_breaker: None,
                    },
                ],
                size_uncompressed: 0,
                target_dir: target_dir.clone(),
                download_event: DownloadEvent::Immutable {
                    download_id: "download_id".to_string(),
                    immutable_file_number: 1,
                },
            };

            download_task.build_download_future(logger).await.unwrap();
        }

        #[tokio::test]
        async fn if_circuit_breaker_is_set_and_downloader_is_unreachable_it_trigger_the_circuit_breaker()
         {
            let target_dir = temp_dir_create!();
            let logger = TestLogger::stdout();
            let file_downloader = Arc::new(
                MockFileDownloaderBuilder::default()
                    .with_file_uri("http://whatever-1/00001.tar.zst")
                    .with_unreachable_downloader_failure("source")
                    .with_compression(None)
                    .build(),
            );
            let circuit_breaker = Some(CircuitBreaker::new());

            let download_task = DownloadTask {
                kind: DownloadKind::Immutable(1),
                locations_to_try: vec![LocationToDownload {
                    file_downloader: file_downloader.clone(),
                    file_downloader_uri: FileDownloaderUri::FileUri(FileUri(
                        "http://whatever-1/00001.tar.zst".to_string(),
                    )),
                    compression_algorithm: None,
                    circuit_breaker: circuit_breaker.clone(),
                }],
                size_uncompressed: 0,
                target_dir: target_dir.clone(),
                download_event: DownloadEvent::Immutable {
                    download_id: "download_id".to_string(),
                    immutable_file_number: 1,
                },
            };

            let err = download_task.build_download_future(logger).await.unwrap_err();
            assert!(err.to_string().contains("All locations failed"));
            assert!(circuit_breaker.is_some_and(|c| c.is_triggered()));
        }
    }

    #[tokio::test]
    async fn if_circuit_breaker_is_set_and_downloader_is_raise_error_other_than_unreachable_the_circuit_breaker_is_not_triggered()
     {
        let target_dir = temp_dir_create!();
        let logger = TestLogger::stdout();
        let file_downloader = Arc::new(
            MockFileDownloaderBuilder::default()
                .with_file_uri("http://whatever-1/00001.tar.zst")
                .with_compression(None)
                .with_failure()
                .build(),
        );
        let circuit_breaker = Some(CircuitBreaker::new());

        let download_task = DownloadTask {
            kind: DownloadKind::Immutable(1),
            locations_to_try: vec![LocationToDownload {
                file_downloader: file_downloader.clone(),
                file_downloader_uri: FileDownloaderUri::FileUri(FileUri(
                    "http://whatever-1/00001.tar.zst".to_string(),
                )),
                compression_algorithm: None,
                circuit_breaker: circuit_breaker.clone(),
            }],
            size_uncompressed: 0,
            target_dir: target_dir.clone(),
            download_event: DownloadEvent::Immutable {
                download_id: "download_id".to_string(),
                immutable_file_number: 1,
            },
        };

        let err = download_task.build_download_future(logger).await.unwrap_err();
        assert!(err.to_string().contains("All locations failed"));
        assert!(circuit_breaker.is_some_and(|c| !c.is_triggered()));
    }
}
