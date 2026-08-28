use async_trait::async_trait;
use mithril_common::{StdResult, entities::FileUri};
use std::{path::Path, time::Duration};

/// Policy for retrying file uploads.
#[derive(Debug, PartialEq, Clone)]
pub struct FileUploadRetryPolicy {
    /// Number of attempts to upload a file.
    pub attempts: usize,
    /// Delay between two attempts.
    pub delay_between_attempts: Duration,
}

impl FileUploadRetryPolicy {
    /// Create a policy that never retries.
    pub fn never() -> Self {
        Self {
            attempts: 1,
            delay_between_attempts: Duration::from_secs(0),
        }
    }
}

impl Default for FileUploadRetryPolicy {
    /// Create a default retry policy.
    fn default() -> Self {
        Self {
            attempts: 3,
            delay_between_attempts: Duration::from_secs(5),
        }
    }
}

/// FileUploader represents a file uploader interactor.
/// It retries the upload operation according to the retry policy.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait FileUploader: Sync + Send {
    /// Try to upload once.
    async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri>;

    /// Get the retry policy for this uploader.
    fn retry_policy(&self) -> FileUploadRetryPolicy {
        FileUploadRetryPolicy::never()
    }

    /// Upload a file with retries according to the retry policy.
    async fn upload(&self, filepath: &Path) -> StdResult<FileUri> {
        let retry_policy = self.retry_policy();
        retry(
            async || self.upload_without_retry(filepath).await,
            retry_policy,
            format!(" Uploaded file path: {}", filepath.display()),
        )
        .await
    }
}

pub(super) async fn retry<T, F, Fut>(
    f: F,
    retry_policy: FileUploadRetryPolicy,
    additional_err_context: String,
) -> StdResult<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = StdResult<T>>,
{
    let mut nb_attempts = 0;
    loop {
        nb_attempts += 1;
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) if nb_attempts >= retry_policy.attempts => {
                return Err(e.context(format!(
                    "Upload failed after {nb_attempts} attempts.{additional_err_context}"
                )));
            }
            _ => tokio::time::sleep(retry_policy.delay_between_attempts).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Mutex, time::Instant};

    use super::*;
    use anyhow::anyhow;
    use mockall::{mock, predicate::eq};

    mock! {
        TestFileUploaderWithDefaultRetryPolicy {
        }
        #[async_trait]
        impl FileUploader for TestFileUploaderWithDefaultRetryPolicy {
            async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri>;
        }
    }

    mock! {
        TestFileUploader {
        }

        #[async_trait]
        impl FileUploader for TestFileUploader {
            async fn upload_without_retry(&self, filepath: &Path) -> StdResult<FileUri>;
            fn retry_policy(&self) -> FileUploadRetryPolicy;
        }
    }

    #[tokio::test]
    async fn upload_return_the_result_of_upload_without_retry() {
        let mut uploader = MockTestFileUploaderWithDefaultRetryPolicy::new();
        uploader
            .expect_upload_without_retry()
            .with(eq(PathBuf::from("file_to_upload")))
            .times(1)
            .returning(|_| Ok(FileUri("file_uploaded".to_string())));

        let file_uploaded = uploader.upload(Path::new("file_to_upload")).await.unwrap();
        assert_eq!(FileUri("file_uploaded".to_string()), file_uploaded);
    }

    #[tokio::test]
    async fn when_upload_fails_do_not_retry_by_default() {
        let mut uploader = MockTestFileUploaderWithDefaultRetryPolicy::new();
        uploader
            .expect_upload_without_retry()
            .with(eq(PathBuf::from("file_to_upload")))
            .times(1)
            .returning(|_| Err(anyhow!("Failure while uploading...")));

        uploader
            .upload(Path::new("file_to_upload"))
            .await
            .expect_err("Should fail on upload");
    }

    #[tokio::test]
    async fn should_retry_if_fail() {
        let mut uploader = MockTestFileUploader::new();

        uploader.expect_retry_policy().returning(|| FileUploadRetryPolicy {
            attempts: 50,
            delay_between_attempts: Duration::ZERO,
        });

        uploader
            .expect_upload_without_retry()
            .with(eq(PathBuf::from("file_to_upload")))
            .times(2)
            .returning(|_| Err(anyhow!("Failure while uploading...")));
        uploader
            .expect_upload_without_retry()
            .with(eq(PathBuf::from("file_to_upload")))
            .times(1)
            .returning(|_| Ok(FileUri("file_uploaded".to_string())));

        let file_uploaded = uploader.upload(Path::new("file_to_upload")).await.unwrap();
        assert_eq!(FileUri("file_uploaded".to_string()), file_uploaded);
    }

    #[tokio::test]
    async fn should_recall_a_failing_inner_uploader_up_to_the_limit() {
        let mut uploader = MockTestFileUploader::new();

        uploader.expect_retry_policy().returning(|| FileUploadRetryPolicy {
            attempts: 4,
            delay_between_attempts: Duration::ZERO,
        });

        uploader
            .expect_upload_without_retry()
            .with(eq(PathBuf::from("file_to_upload")))
            .times(4)
            .returning(|_| Err(anyhow!("Failure while uploading...")));

        uploader
            .upload(&PathBuf::from("file_to_upload"))
            .await
            .expect_err("An error should be returned when all retries are done");
    }

    #[tokio::test]
    async fn should_delay_between_retries() {
        struct FileUploaderAssertDelay {
            delay_ms: u64,
            last_attempt_start_time: Mutex<Option<Instant>>,
        }

        #[async_trait]
        impl FileUploader for FileUploaderAssertDelay {
            async fn upload_without_retry(&self, _filepath: &Path) -> StdResult<FileUri> {
                let mut last_attempt_start_time = self.last_attempt_start_time.lock().unwrap();
                if let Some(last_start_attempt) = *last_attempt_start_time {
                    let duration = last_start_attempt.elapsed();
                    let expected_delay_greater_than_or_equal = Duration::from_millis(self.delay_ms);
                    assert!(
                        duration >= expected_delay_greater_than_or_equal,
                        "duration should be greater than or equal to {}ms but was {}ms",
                        expected_delay_greater_than_or_equal.as_millis(),
                        duration.as_millis()
                    );
                    let expected_delay_less_than = Duration::from_millis(2 * self.delay_ms);
                    assert!(
                        duration < expected_delay_less_than,
                        "duration should be less than {}ms but was {}ms",
                        expected_delay_less_than.as_millis(),
                        duration.as_millis()
                    );
                }
                *last_attempt_start_time = Some(Instant::now());

                Err(anyhow::anyhow!("Upload failed"))
            }

            fn retry_policy(&self) -> FileUploadRetryPolicy {
                FileUploadRetryPolicy {
                    attempts: 4,
                    delay_between_attempts: Duration::from_millis(self.delay_ms),
                }
            }
        }

        let uploader = FileUploaderAssertDelay {
            delay_ms: 50,
            last_attempt_start_time: Mutex::new(None),
        };

        uploader
            .upload(&PathBuf::from("file_to_upload"))
            .await
            .expect_err("An error should be returned when all retries are done");
    }
}
