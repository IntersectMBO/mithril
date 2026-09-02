use anyhow::anyhow;
use mockall::predicate;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use mithril_cardano_node_internal_database::entities::AncillaryFilesManifest;
use mithril_common::{
    StdResult,
    crypto_helper::ManifestSigner,
    entities::{CompressionAlgorithm, FileUri},
};

use super::{DownloadEvent, FileDownloaderUnreachable, FileDownloaderUri, MockFileDownloader};

type MockFileDownloaderBuilderReturningFunc = Box<
    dyn FnMut(
            &FileDownloaderUri,
            u64,
            &Path,
            Option<CompressionAlgorithm>,
            DownloadEvent,
        ) -> StdResult<()>
        + Send
        + 'static,
>;

/// A mock file downloader builder
pub struct MockFileDownloaderBuilder {
    mock_file_downloader: Option<MockFileDownloader>,
    times: usize,
    param_file_downloader_uri: Option<FileDownloaderUri>,
    param_target_dir: Option<PathBuf>,
    param_compression_algorithm: Option<Option<CompressionAlgorithm>>,
    returning_func: Option<MockFileDownloaderBuilderReturningFunc>,
}

/// Parameters to create fake ancillary files with a (potentially) signed manifest when calling
/// [MockFileDownloaderBuilder::with_success_and_create_fake_ancillary_files]
#[derive(bon::Builder)]
pub struct FakeAncillaryFileBuilder {
    /// List of ancillary files to create and include in the manifest (created files will be empty)
    files_in_manifest_to_create: Vec<String>,
    /// List of files to create and not to include in the manifest (created files will be empty)
    files_not_in_manifest_to_create: Option<Vec<String>>,
    /// The signer to use to sign the manifest, manifest will not be signed if None
    sign_manifest: Option<ManifestSigner>,
}

impl Default for MockFileDownloaderBuilder {
    fn default() -> Self {
        Self {
            mock_file_downloader: None,
            times: 1,
            param_file_downloader_uri: None,
            param_target_dir: None,
            param_compression_algorithm: Some(Some(CompressionAlgorithm::default())),
            returning_func: None,
        }
    }
}

impl MockFileDownloaderBuilder {
    /// Constructs a new MockFileDownloaderBuilder from an existing MockFileDownloader.
    pub fn from_mock(mock: MockFileDownloader) -> Self {
        Self {
            mock_file_downloader: Some(mock),
            ..Self::default()
        }
    }

    /// The MockFileDownloader will succeed
    pub fn with_success(self) -> Self {
        self.with_returning(Box::new(|_, _, _, _, _| Ok(())))
    }

    /// The MockFileDownloader will fail
    pub fn with_failure(self) -> Self {
        self.with_returning(Box::new(|_, _, _, _, _| {
            Err(anyhow!("Download unpack failed"))
        }))
    }

    /// The MockFileDownloader will fail with a [FileDownloaderUnreachable]
    pub fn with_unreachable_downloader_failure(self, src: &'static str) -> Self {
        self.with_returning(Box::new(move |location, _, _, _, _| {
            Err(anyhow!(FileDownloaderUnreachable {
                source: src,
                uri: location.as_str().to_string()
            }))
        }))
    }

    /// The MockFileDownloader will succeed and will create ancillary files and a manifest
    /// in the target directory (target directory must exist otherwise the function will panic).
    pub fn with_success_and_create_fake_ancillary_files(
        self,
        fake_ancillary_file_builder: FakeAncillaryFileBuilder,
    ) -> Self {
        self.with_returning(Box::new(move |_, _, target_dir: &Path, _, _| {
            for filename in [
                fake_ancillary_file_builder.files_in_manifest_to_create.as_slice(),
                fake_ancillary_file_builder
                    .files_not_in_manifest_to_create
                    .as_ref()
                    .unwrap_or(&vec![])
                    .as_slice(),
            ]
            .concat()
            {
                File::create(target_dir.join(filename)).unwrap();
            }

            let empty_file_sha256 = hex::encode(Sha256::digest(""));
            let mut ancillary_manifest =
                AncillaryFilesManifest::new_without_signature(BTreeMap::from_iter(
                    fake_ancillary_file_builder
                        .files_in_manifest_to_create
                        .iter()
                        .map(|filename| (PathBuf::from(filename), empty_file_sha256.clone())),
                ));

            if let Some(manifest_signer) = &fake_ancillary_file_builder.sign_manifest {
                ancillary_manifest
                    .set_signature(manifest_signer.sign(&ancillary_manifest.compute_hash()));
            }

            let ancillary_file =
                File::create(target_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME))
                    .unwrap();
            serde_json::to_writer(ancillary_file, &ancillary_manifest).unwrap();
            Ok(())
        }))
    }

    /// The MockFileDownloader expected number of calls of download_unpack
    pub fn with_times(self, times: usize) -> Self {
        let mut self_mut = self;
        self_mut.times = times;

        self_mut
    }

    /// The MockFileDownloader expected FileDownloaderUri when download_unpack is called
    pub fn with_file_uri<T: AsRef<str>>(self, file_uri: T) -> Self {
        let mut self_mut = self;
        self_mut.param_file_downloader_uri = Some(FileDownloaderUri::FileUri(FileUri(
            file_uri.as_ref().to_string(),
        )));

        self_mut
    }

    /// The MockFileDownloader expected target_dir when download_unpack is called
    pub fn with_target_dir(self, target_dir: PathBuf) -> Self {
        let mut self_mut = self;
        self_mut.param_target_dir = Some(target_dir);

        self_mut
    }

    /// The MockFileDownloader expected compression_algorithm when download_unpack is called
    pub fn with_compression(self, compression: Option<CompressionAlgorithm>) -> Self {
        let mut self_mut = self;
        self_mut.param_compression_algorithm = Some(compression);

        self_mut
    }

    /// The MockFileDownloader will return the result of the returning_func when download_unpack is called
    pub fn with_returning(self, returning_func: MockFileDownloaderBuilderReturningFunc) -> Self {
        let mut self_mut = self;
        self_mut.returning_func = Some(returning_func);

        self_mut
    }

    /// Builds the MockFileDownloader
    pub fn build(self) -> MockFileDownloader {
        let predicate_file_downloader_uri = predicate::function(move |u| {
            self.param_file_downloader_uri
                .as_ref()
                .map(|x| x == u)
                .unwrap_or(true)
        });
        let predicate_target_dir = predicate::function(move |u| {
            self.param_target_dir.as_ref().map(|x| x == u).unwrap_or(true)
        });
        let predicate_compression_algorithm = predicate::function(move |u| {
            self.param_compression_algorithm
                .as_ref()
                .map(|x| x == u)
                .unwrap_or(true)
        });
        let predicate_download_event_type = predicate::always();

        let mut mock_file_downloader = self.mock_file_downloader.unwrap_or_default();
        mock_file_downloader
            .expect_download_unpack()
            .with(
                predicate_file_downloader_uri,
                predicate::always(),
                predicate_target_dir,
                predicate_compression_algorithm,
                predicate_download_event_type,
            )
            .times(self.times)
            .returning(self.returning_func.unwrap());

        mock_file_downloader
    }

    /// Builds the MockFileDownloader and returns a new MockFileDownloaderBuilder
    ///
    /// This helps building multiple expectations for the mock.
    pub fn next_call(self) -> Self {
        let mock_file_downloader = self.build();

        Self::from_mock(mock_file_downloader)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{assert_dir_eq, temp_dir_create};

    use crate::file_downloader::FileDownloader;

    use super::*;

    #[tokio::test]
    async fn can_be_parametrized_to_create_fake_ancillary_files_with_signed_manifest() {
        let target_dir = temp_dir_create!();
        let ancillary_signer = ManifestSigner::create_deterministic_signer();
        let verifier = ancillary_signer.verification_key();
        let fake_ancillary_file_builder = FakeAncillaryFileBuilder::builder()
            .files_in_manifest_to_create(vec!["file1.txt".to_string(), "file2.txt".to_string()])
            .files_not_in_manifest_to_create(vec!["not_in_manifest.txt".to_string()])
            .sign_manifest(ancillary_signer)
            .build();

        let mock_file_downloader = MockFileDownloaderBuilder::default()
            .with_file_uri("http://ancillary.tar.zst")
            .with_success_and_create_fake_ancillary_files(fake_ancillary_file_builder)
            .build();

        mock_file_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://ancillary.tar.zst".to_string())),
                0,
                &target_dir,
                Some(CompressionAlgorithm::default()),
                DownloadEvent::Ancillary {
                    download_id: "whatever".to_string(),
                },
            )
            .await
            .unwrap();

        let ancillary_manifest: AncillaryFilesManifest = serde_json::from_reader(
            File::open(target_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME))
                .unwrap(),
        )
        .unwrap();

        const EMPTY_SHA256_HASH: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            ancillary_manifest.signable_manifest.data,
            BTreeMap::from([
                (PathBuf::from("file1.txt"), EMPTY_SHA256_HASH.to_string()),
                (PathBuf::from("file2.txt"), EMPTY_SHA256_HASH.to_string()),
            ])
        );
        verifier
            .verify(
                &ancillary_manifest.compute_hash(),
                &ancillary_manifest.signature().expect("Manifest should be signed"),
            )
            .expect("Signed manifest should have a valid signature");

        assert_dir_eq!(
            &target_dir,
            format!(
                "* {}
                 * file1.txt
                 * file2.txt
                 * not_in_manifest.txt",
                AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME
            )
        );
    }
}
