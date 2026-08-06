use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug};
use std::path::{Path, PathBuf};

use mithril_common::StdResult;
use mithril_common::{entities::FileUri, logging::LoggerExtensions};

use crate::file_uploaders::{FileUploadRetryPolicy, FileUploader};
use crate::tools::url_sanitizer::SanitizedUrlWithTrailingSlash;

/// LocalUploader is a file uploader working using local files
pub struct LocalUploader {
    /// File server URL prefix
    server_url_prefix: SanitizedUrlWithTrailingSlash,

    /// Target folder where to store files archives
    target_location: Option<PathBuf>,

    retry_policy: FileUploadRetryPolicy,
    logger: Logger,
}

impl LocalUploader {
    /// Instantiates a new LocalUploader that copies 'uploaded' files to a target location
    pub(crate) fn new(
        server_url_prefix: SanitizedUrlWithTrailingSlash,
        target_location: &Path,
        retry_policy: FileUploadRetryPolicy,
        logger: Logger,
    ) -> Self {
        let logger = logger.new_with_component_name::<Self>();
        debug!(logger, "New LocalUploader created"; "server_url_prefix" => &server_url_prefix.as_str());

        Self {
            server_url_prefix,
            target_location: Some(target_location.to_path_buf()),
            logger,
            retry_policy,
        }
    }

    /// Instantiates a new LocalUploader that does not copy files and only returns the location
    pub(crate) fn new_without_copy(
        server_url_prefix: SanitizedUrlWithTrailingSlash,
        retry_policy: FileUploadRetryPolicy,
        logger: Logger,
    ) -> Self {
        let logger = logger.new_with_component_name::<Self>();
        debug!(logger, "New LocalUploader created"; "server_url_prefix" => &server_url_prefix.as_str());

        Self {
            server_url_prefix,
            target_location: None,
            logger,
            retry_policy,
        }
    }
}

#[async_trait]
impl FileUploader for LocalUploader {
    async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri> {
        let archive_name = filepath.file_name().unwrap().to_str().unwrap();

        let disk_path = if let Some(target_location) = &self.target_location {
            let target_path = target_location.join(archive_name);
            tokio::fs::copy(filepath, &target_path)
                .await
                .with_context(|| "File copy failure")?;
            target_path
        } else {
            filepath.to_path_buf()
        };

        let uri = self.server_url_prefix.join(archive_name)?.to_string();

        debug!(self.logger, "File 'uploaded' to local storage"; "uri" => &uri, "disk_path" => disk_path.display());

        Ok(FileUri(uri))
    }

    fn retry_policy(&self) -> FileUploadRetryPolicy {
        self.retry_policy.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use mithril_common::test::TempDir;

    use crate::test::TestLogger;

    use super::*;

    fn create_fake_archive(dir: &Path, name: &str) -> PathBuf {
        let file_path = dir.join(format!("{name}.tar.zst"));
        let mut file = File::create(&file_path).unwrap();
        writeln!(
            file,
            "I swear, this is an archive, not a temporary test file."
        )
        .unwrap();

        file_path
    }

    #[tokio::test]
    async fn should_extract_archive_name_to_deduce_location() {
        let source_dir = TempDir::create(
            "local_uploader",
            "should_extract_archive_name_to_deduce_location_source",
        );
        let target_dir = TempDir::create(
            "local_uploader",
            "should_extract_archive_name_to_deduce_location_target",
        );
        let archive_name = "an_archive";
        let archive = create_fake_archive(&source_dir, archive_name);
        let expected_location = format!(
            "http://test.com:8080/base-root/{}",
            archive.file_name().unwrap().to_string_lossy()
        );

        let url_prefix =
            SanitizedUrlWithTrailingSlash::parse("http://test.com:8080/base-root").unwrap();
        let uploader = LocalUploader::new(
            url_prefix,
            &target_dir,
            FileUploadRetryPolicy::never(),
            TestLogger::stdout(),
        );
        let location = FileUploader::upload(&uploader, &archive)
            .await
            .expect("local upload should not fail");

        assert_eq!(FileUri(expected_location), location);
    }

    #[tokio::test]
    async fn should_copy_file_to_target_location() {
        let source_dir = TempDir::create(
            "local_uploader",
            "should_copy_file_to_target_location_source",
        );
        let target_dir = TempDir::create(
            "local_uploader",
            "should_copy_file_to_target_location_target",
        );
        let archive = create_fake_archive(&source_dir, "an_archive");
        let uploader = LocalUploader::new(
            SanitizedUrlWithTrailingSlash::parse("http://test.com:8080/base-root/").unwrap(),
            &target_dir,
            FileUploadRetryPolicy::never(),
            TestLogger::stdout(),
        );
        FileUploader::upload(&uploader, &archive).await.unwrap();

        assert!(target_dir.join(archive.file_name().unwrap()).exists());
    }

    #[tokio::test]
    async fn should_error_if_path_is_a_directory() {
        let source_dir = TempDir::create(
            "local_uploader",
            "should_error_if_path_is_a_directory_source",
        );
        let target_dir = TempDir::create(
            "local_uploader",
            "should_error_if_path_is_a_directory_target",
        );
        let uploader = LocalUploader::new(
            SanitizedUrlWithTrailingSlash::parse("http://test.com:8080/base-root/").unwrap(),
            &target_dir,
            FileUploadRetryPolicy::never(),
            TestLogger::stdout(),
        );
        FileUploader::upload(&uploader, &source_dir)
            .await
            .expect_err("Uploading a directory should fail");
    }

    #[tokio::test]
    async fn retry_policy_from_file_uploader_trait_should_be_implemented() {
        let target_dir = TempDir::create("local_uploader", "test_retry_policy");
        let expected_policy = FileUploadRetryPolicy {
            attempts: 10,
            delay_between_attempts: Duration::from_millis(123),
        };

        let uploader: Box<dyn FileUploader> = Box::new(LocalUploader::new(
            SanitizedUrlWithTrailingSlash::parse("http://test.com:8080/base-root/").unwrap(),
            &target_dir,
            expected_policy.clone(),
            TestLogger::stdout(),
        ));

        assert_eq!(expected_policy, uploader.retry_policy());
    }

    #[tokio::test]
    async fn should_only_return_location_if_copy_disabled() {
        let source_dir = TempDir::create(
            "local_uploader",
            "should_only_return_location_and_not_copy_file_if_copy_disabled",
        );
        let archive = create_fake_archive(&source_dir, "an_archive");
        let uploader = LocalUploader::new_without_copy(
            SanitizedUrlWithTrailingSlash::parse("http://test.com:8080/base-root/").unwrap(),
            FileUploadRetryPolicy::never(),
            TestLogger::stdout(),
        );
        let location = FileUploader::upload(&uploader, &archive).await.unwrap();

        let expected_location = format!(
            "http://test.com:8080/base-root/{}",
            archive.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(FileUri(expected_location), location);
    }
}
