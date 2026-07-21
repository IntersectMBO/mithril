use std::{
    fs::File,
    io::{BufReader, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::Context;
use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use sha2::{Digest, Sha256};

use crate::{StmResult, circuits::MITHRIL_CIRCUIT_CACHE_FOLDER};
#[cfg(any(test, feature = "benchmark-internals"))]
use {rand_chacha::ChaCha20Rng, rand_core::SeedableRng, std::fs::create_dir_all};

/// Constant storing the hash of the SRS of degree 22 used to create proof in production.
/// This SRS is coming from the trusted setup done by Midnight and available in the following
/// repository: https://github.com/midnightntwrk/midnight-trusted-setup.
///
/// If the degree of the SRS used were to change, this hash would need to be updated using
/// the proper value available here: https://github.com/midnightntwrk/midnight-trusted-setup/blob/main/MIDNIGHT_SRS_CATALOG.md
const MIDNIGHT_SRS_HASH_K22: &str =
    "e8ad5eed936d657a0fb59d2a55ba19f81a3083bb3554ef88f464f5377e9b2c2f";
/// Constant storing URL to download the SRS of degree 22 used to create proof in production
const MIDNIGHT_SRS_URL_K22: &str = "https://srs.midnight.network/midnight-srs-2p22";
/// Constant holding the folder of the SRS file
const MITHRIL_CIRCUIT_SRS_FOLDER: &str = "srs";
/// Constant holding the filename of the SRS
const MITHRIL_CIRCUIT_SRS_FILENAME: &str = "srs-parameters";

/// Errors which can be outputted by the trusted setup verification.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TrustedSetupError {
    /// The hash verification of the SRS bytes failed
    #[error(
        "The hash of the SRS file does not match the hard-coded value. Expected: {expected}, Computed hash: {computed}"
    )]
    VerifyHashFail { expected: String, computed: String },
}

/// A structure to manage the trusted setup SRS. It stores the local path of the SRS file
/// and information to download the file and verify integrity if it is missing.
pub struct TrustedSetupProvider {
    /// Path of the local SRS folder
    local_srs_folder_path: PathBuf,
    /// Expected hash of the downloaded SRS file
    srs_expected_hash: String,
    /// URL where to download the SRS file if it is not present locally
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    url_to_download_srs: String,
    /// The timeout limit when trying to download the SRS file
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    download_timeout_limit: Duration,
}

impl TrustedSetupProvider {
    /// Create a new TrustedSetupProvider
    pub fn new<P: Into<PathBuf>, S: Into<String>, U: Into<String>>(
        local_srs_folder_path: P,
        srs_expected_hash: S,
        url_to_download_srs: U,
        download_timeout_limit: Duration,
    ) -> Self {
        Self {
            local_srs_folder_path: local_srs_folder_path.into().join(MITHRIL_CIRCUIT_SRS_FOLDER),
            srs_expected_hash: srs_expected_hash.into(),
            url_to_download_srs: url_to_download_srs.into(),
            download_timeout_limit,
        }
    }

    /// Computes the SHA256 hash of the given bytes and returns its hex encoding.
    fn compute_hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);

        hex::encode(hasher.finalize())
    }

    /// Checks SHA256 hash of the given bytes against the stored expected value.
    fn verify_bytes_sha256_hash(&self, srs_bytes: &[u8]) -> StmResult<()> {
        let recomputed_hash = Self::compute_hash(srs_bytes);

        if self.srs_expected_hash != recomputed_hash {
            return Err(TrustedSetupError::VerifyHashFail {
                expected: self.srs_expected_hash.clone(),
                computed: recomputed_hash,
            }
            .into());
        }
        Ok(())
    }

    /// Fetches the SRS from `self.url_to_download_srs` and returns its bytes.
    #[cfg(not(target_family = "wasm"))]
    fn download_srs_file(&self) -> StmResult<Vec<u8>> {
        let response = reqwest::blocking::Client::builder()
            .timeout(self.download_timeout_limit)
            .build()?
            .get(&self.url_to_download_srs)
            .header("User-Agent", "mithril-stm")
            .send()?
            .error_for_status()?;
        let bytes = response.bytes()?;

        Ok(bytes.to_vec())
    }

    /// The SRS download relies on a blocking HTTP client that is unavailable on wasm targets,
    /// where the prover is never executed.
    #[cfg(target_family = "wasm")]
    fn download_srs_file(&self) -> StmResult<Vec<u8>> {
        Err(anyhow::anyhow!(
            "SRS download is not supported on wasm targets"
        ))
    }

    /// Saves the given bytes in a temporary file then atomically moves it to the stored path
    /// while creating the directories of the path if needed.
    /// If the writing is interrupted, the temporary file will be overwritten and renamed during
    /// the next download.
    fn store_srs_bytes_to_file(&self, srs_bytes: &[u8]) -> StmResult<()> {
        std::fs::create_dir_all(&self.local_srs_folder_path)
            .with_context(|| "Subdirectory creation should have succeeded.")?;

        let temp_path = self
            .local_srs_folder_path
            .join(MITHRIL_CIRCUIT_SRS_FILENAME)
            .with_extension("temp");
        let final_path = self.local_srs_folder_path.join(MITHRIL_CIRCUIT_SRS_FILENAME);

        let mut temporary_file = File::create(&temp_path)
            .with_context(|| format!("Failed to create temporary SRS file at {temp_path:?}."))?;
        temporary_file.write_all(srs_bytes)?;
        temporary_file
            .sync_all()
            .with_context(|| "Failed to fsync temporary SRS file before rename.")?;
        drop(temporary_file);

        std::fs::rename(temp_path, final_path)?;

        File::open(&self.local_srs_folder_path)
            .and_then(|dir| dir.sync_all())
            .with_context(|| "Failed to fsync SRS directory after rename.")?;
        Ok(())
    }

    /// Ensures the SRS file is present. If the file is missing,
    /// downloads it, verifies its hash and stores it if the hash is valid.
    fn download_srs_file_if_not_cached(&self) -> StmResult<()> {
        if !self.local_srs_folder_path.join(MITHRIL_CIRCUIT_SRS_FILENAME).exists() {
            let srs_bytes = self
                .download_srs_file()
                .with_context(|| "Download of the SRS file should have succeeded.")?;
            self.verify_bytes_sha256_hash(&srs_bytes)?;
            self.store_srs_bytes_to_file(&srs_bytes)
                .with_context(|| "Saving the SRS to disk should have succeeded.")?;
        }

        Ok(())
    }

    /// Ensures the SRS file is available, downloading it if necessary
    /// and deserializes it into memory.
    pub fn get_trusted_setup_parameters(&self) -> StmResult<ParamsKZG<Bls12>> {
        self.download_srs_file_if_not_cached()?;

        let file = File::open(self.local_srs_folder_path.join(MITHRIL_CIRCUIT_SRS_FILENAME))
            .with_context(|| {
                format!(
                    "Failed to open SRS file at {:?}.",
                    self.local_srs_folder_path.join(MITHRIL_CIRCUIT_SRS_FILENAME)
                )
            })?;
        let mut reader = BufReader::new(file);

        ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked)
            .with_context(|| "Failed to deserialize SRS from file.")
    }
}

impl Default for TrustedSetupProvider {
    fn default() -> Self {
        Self::new(
            std::env::temp_dir().join(MITHRIL_CIRCUIT_CACHE_FOLDER),
            MIDNIGHT_SRS_HASH_K22,
            MIDNIGHT_SRS_URL_K22,
            Duration::from_secs(600),
        )
    }
}

/// Seed for the deterministic unsafe SRS used by the tests; it pins the SRS's tau. Test key caches
/// fold in this seed so they stay correct if it ever changes. The IVC setup cache also folds in the
/// SRS degree; the certificate-key cache omits it, since keygen downsizes the seed-pinned SRS to the
/// certificate circuit's own degree, so the oversized degree never affects the certificate key.
#[cfg(any(test, feature = "benchmark-internals"))]
pub(crate) const UNSAFE_SRS_SEED: u64 = 42;

#[cfg(any(test, feature = "benchmark-internals"))]
impl TrustedSetupProvider {
    /// Builds a `TrustedSetupProvider` backed by a freshly generated unsafe SRS of degree `k`, written
    /// to `base_dir/srs/srs-parameters` with a matching SHA256 hash so the provider's hash check passes.
    /// For tests and benchmarks only.
    pub(crate) fn with_unsafe_srs(base_dir: &std::path::Path, k: u32) -> Self {
        let srs = ParamsKZG::<Bls12>::unsafe_setup(k, ChaCha20Rng::seed_from_u64(UNSAFE_SRS_SEED));
        let mut srs_bytes = Vec::new();
        srs.write_custom(&mut srs_bytes, SerdeFormat::RawBytes).unwrap();

        let srs_dir = base_dir.join(MITHRIL_CIRCUIT_SRS_FOLDER);
        create_dir_all(&srs_dir).unwrap();
        File::create(srs_dir.join(MITHRIL_CIRCUIT_SRS_FILENAME))
            .unwrap()
            .write_all(&srs_bytes)
            .unwrap();

        let expected_hash = hex::encode(Sha256::digest(&srs_bytes));
        Self::new(base_dir, expected_hash, "", Duration::from_secs(600))
    }
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;

    use super::*;

    const SRS_HASH_K1: &str = "bbe04fe3c70d0c138447cb086b4baddc30cb8bb2a004114bc02e6f739516280e";

    const SRS_K1: &[u8; 772] = &[
        1, 0, 0, 0, 23, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195,
        104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249,
        122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 8, 179, 244, 129, 227, 170, 160, 241,
        160, 158, 48, 237, 116, 29, 138, 228, 252, 245, 224, 149, 213, 208, 10, 246, 0, 219, 24,
        203, 44, 4, 179, 237, 208, 60, 199, 68, 162, 136, 138, 228, 12, 170, 35, 41, 70, 197, 231,
        225, 21, 176, 173, 99, 244, 249, 255, 16, 204, 15, 172, 98, 0, 72, 248, 188, 99, 134, 184,
        91, 165, 82, 104, 25, 167, 240, 44, 241, 22, 110, 22, 153, 65, 156, 8, 179, 10, 142, 78,
        128, 243, 209, 17, 13, 50, 163, 45, 245, 16, 124, 133, 229, 90, 163, 193, 6, 96, 106, 49,
        225, 51, 203, 31, 64, 83, 232, 27, 240, 224, 46, 118, 112, 208, 26, 51, 6, 200, 126, 61,
        238, 129, 167, 217, 107, 169, 15, 82, 187, 244, 42, 187, 171, 185, 103, 67, 72, 8, 38, 246,
        126, 89, 155, 211, 217, 41, 203, 21, 58, 68, 77, 94, 162, 224, 172, 97, 77, 138, 1, 50, 81,
        76, 12, 42, 139, 177, 226, 14, 80, 158, 177, 21, 144, 203, 217, 32, 181, 188, 166, 81, 188,
        230, 151, 135, 171, 20, 243, 44, 204, 170, 114, 100, 20, 255, 137, 169, 91, 55, 231, 255,
        10, 137, 141, 197, 138, 133, 211, 195, 7, 206, 34, 63, 178, 0, 167, 170, 174, 55, 172, 160,
        66, 2, 103, 113, 188, 85, 98, 73, 144, 236, 129, 50, 191, 8, 250, 143, 167, 57, 187, 53, 6,
        192, 78, 148, 54, 52, 60, 187, 221, 248, 176, 163, 14, 245, 135, 74, 190, 149, 65, 43, 252,
        26, 173, 64, 18, 59, 177, 21, 118, 236, 165, 44, 177, 155, 65, 243, 49, 140, 215, 245, 105,
        13, 63, 226, 237, 85, 23, 33, 99, 233, 109, 45, 72, 207, 211, 52, 69, 121, 77, 156, 236,
        164, 52, 110, 29, 200, 76, 71, 187, 55, 202, 112, 172, 172, 51, 125, 240, 41, 10, 48, 12,
        252, 217, 29, 214, 149, 243, 242, 88, 19, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211,
        160, 136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127,
        80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162,
        178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2,
        180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200,
        193, 33, 189, 184, 6, 6, 196, 160, 46, 167, 52, 204, 50, 172, 210, 176, 43, 194, 139, 153,
        203, 62, 40, 126, 133, 167, 99, 175, 38, 116, 146, 171, 87, 46, 153, 171, 63, 55, 13, 39,
        92, 236, 29, 161, 170, 169, 7, 95, 240, 95, 121, 190, 12, 229, 213, 39, 114, 125, 110, 17,
        140, 201, 205, 198, 218, 46, 53, 26, 173, 253, 155, 170, 140, 189, 211, 167, 109, 66, 154,
        105, 81, 96, 209, 44, 146, 58, 201, 204, 59, 172, 162, 137, 225, 147, 84, 134, 8, 184, 40,
        1, 4, 187, 225, 162, 79, 204, 79, 152, 140, 110, 242, 104, 208, 193, 22, 14, 172, 10, 12,
        79, 83, 216, 11, 215, 79, 61, 46, 70, 103, 190, 39, 64, 134, 37, 168, 56, 37, 53, 78, 39,
        199, 8, 89, 136, 49, 2, 235, 67, 7, 172, 181, 105, 179, 24, 124, 15, 209, 153, 57, 128,
        170, 82, 166, 233, 226, 8, 11, 150, 151, 250, 185, 106, 189, 92, 95, 28, 59, 152, 130, 86,
        242, 217, 147, 102, 241, 187, 204, 241, 60, 240, 226, 7, 2, 254, 225, 140, 15, 8, 23, 150,
        4, 171, 232, 193, 130, 11, 190, 209, 17, 39, 64, 141, 203, 80, 114, 173, 202, 184, 87, 116,
        163, 45, 81, 139, 104, 35, 80, 176, 106, 34, 168, 123, 241, 120, 135, 115, 42, 10, 244, 93,
        223, 204, 191, 248, 16, 225, 178, 33, 226, 165, 145, 29, 111, 150, 131, 163, 111, 78, 127,
        231, 212, 66, 129, 222, 134, 161, 134, 204, 16, 108, 51, 54, 245, 143, 236, 224, 30, 118,
        109, 196, 20, 125, 56, 227, 25, 54, 16, 90, 73, 68, 203, 89,
    ];

    #[test]
    fn both_bytes_encoding_work_to_load_srs_from_file() {
        let temp_dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::create_dir_all(temp_dir.path().join("srs")).unwrap();
        let mut srs_file =
            File::create(temp_dir.path().join("srs").join(MITHRIL_CIRCUIT_SRS_FILENAME)).unwrap();
        srs_file.write_all(SRS_K1).unwrap();
        let srs_manager =
            TrustedSetupProvider::new(temp_dir.path(), SRS_HASH_K1, "", Duration::from_secs(600));
        let loaded_srs = srs_manager.get_trusted_setup_parameters().unwrap();
        let srs_rawbytes: ParamsKZG<Bls12> =
            ParamsKZG::read_custom(&mut SRS_K1.as_slice(), SerdeFormat::RawBytes).unwrap();

        let srs_rawbytes_unchecked: ParamsKZG<Bls12> =
            ParamsKZG::read_custom(&mut SRS_K1.as_slice(), SerdeFormat::RawBytesUnchecked).unwrap();

        let mut loaded_buffer = vec![];
        loaded_srs
            .write_custom(&mut loaded_buffer, SerdeFormat::RawBytes)
            .unwrap();
        let mut raw_bytes_buffer = vec![];
        srs_rawbytes
            .write_custom(&mut raw_bytes_buffer, SerdeFormat::RawBytes)
            .unwrap();
        let mut raw_bytes_unchecked_buffer = vec![];
        srs_rawbytes_unchecked
            .write_custom(
                &mut raw_bytes_unchecked_buffer,
                SerdeFormat::RawBytesUnchecked,
            )
            .unwrap();

        assert_eq!(loaded_buffer, raw_bytes_buffer);
        assert_eq!(raw_bytes_unchecked_buffer, raw_bytes_buffer);
    }

    #[test]
    fn verification_of_hash_of_invalid_srs_file_fails() {
        let mut tampered_bytes = SRS_K1.to_vec();
        tampered_bytes[0] = tampered_bytes[0].wrapping_add(1);

        let result = TrustedSetupProvider::new("", SRS_HASH_K1, "", Duration::from_secs(600))
            .verify_bytes_sha256_hash(&tampered_bytes);

        let err = result.unwrap_err();

        assert!(
            matches!(
                err.downcast_ref::<TrustedSetupError>(),
                Some(TrustedSetupError::VerifyHashFail {
                    expected: _,
                    computed: _
                })
            ),
            "Hash verification should have failed due to the tampering of the bytes!"
        );
    }

    #[test]
    fn hash_of_correct_bytes_verifies() {
        let result = TrustedSetupProvider::new("", SRS_HASH_K1, "", Duration::from_secs(600))
            .verify_bytes_sha256_hash(SRS_K1);

        assert!(result.is_ok());
    }

    #[test]
    fn existing_file_on_disk_skips_download_and_verification() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/srs");
            then.status(200).body([0, 1, 2, 3, 4]);
        });
        let temp_dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::create_dir_all(temp_dir.path().join("srs")).unwrap();
        let mut srs_file =
            File::create(temp_dir.path().join("srs").join(MITHRIL_CIRCUIT_SRS_FILENAME)).unwrap();
        srs_file.write_all(&[0, 1, 2, 3, 4]).unwrap();

        let result = TrustedSetupProvider::new(
            temp_dir.path(),
            SRS_HASH_K1,
            server.url("/srs"),
            Duration::from_secs(600),
        )
        .download_srs_file_if_not_cached();

        assert!(result.is_ok());
        mock.assert_calls(0);
    }

    #[test]
    fn interrupted_writing_of_srs_resumes_properly_at_next_try() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/srs");
            then.status(200).body(SRS_K1);
        });
        let temp_dir = tempfile::tempdir_in("/tmp").unwrap();
        let srs_folder = temp_dir.path().join("srs");
        std::fs::create_dir_all(&srs_folder).unwrap();
        std::fs::write(srs_folder.join("srs-parameters.temp"), [0, 1, 2, 3, 4]).unwrap();

        assert!(!srs_folder.join(MITHRIL_CIRCUIT_SRS_FILENAME).exists());

        let result = TrustedSetupProvider::new(
            temp_dir.path(),
            SRS_HASH_K1,
            server.url("/srs"),
            Duration::from_secs(600),
        )
        .download_srs_file_if_not_cached();

        assert!(srs_folder.join(MITHRIL_CIRCUIT_SRS_FILENAME).exists());
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn missing_srs_file_triggers_download_verification_and_storage() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/srs");
            then.status(200).body(SRS_K1);
        });
        let temp_dir = tempfile::tempdir().unwrap();
        let srs_path = temp_dir.path().join("srs").join(MITHRIL_CIRCUIT_SRS_FILENAME);

        TrustedSetupProvider::new(
            temp_dir.path(),
            SRS_HASH_K1,
            server.url("/srs"),
            Duration::from_secs(600),
        )
        .download_srs_file_if_not_cached()
        .unwrap();

        mock.assert();
        assert!(srs_path.exists());
    }

    #[test]
    fn downloaded_file_with_wrong_hash_fails_and_does_not_store_file() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/srs");
            then.status(200).body(b"tampered content");
        });
        let temp_dir = tempfile::tempdir().unwrap();
        let srs_path = temp_dir.path().join("dl_wrong_hash");

        let result = TrustedSetupProvider::new(
            &srs_path,
            SRS_HASH_K1,
            server.url("/srs"),
            Duration::from_secs(600),
        )
        .download_srs_file_if_not_cached();

        let err = result.unwrap_err();

        assert!(
            matches!(
                err.downcast_ref::<TrustedSetupError>(),
                Some(TrustedSetupError::VerifyHashFail {
                    expected: _,
                    computed: _
                })
            ),
            "Hash verification should have failed due to the tampering of the bytes."
        );
        assert!(!srs_path.exists());
    }

    #[test]
    fn server_error_during_download_returns_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/srs");
            then.status(404);
        });

        let temp_dir = tempfile::tempdir().unwrap();
        let srs_path = temp_dir.path().join("server_error_fails");

        let result = TrustedSetupProvider::new(
            srs_path,
            SRS_HASH_K1,
            server.url("/srs"),
            Duration::from_secs(600),
        )
        .download_srs_file_if_not_cached();

        assert!(result.is_err());
    }

    mod golden {
        use super::*;

        #[test]
        fn golden_test_for_production_srs_url() {
            let current_url = "https://srs.midnight.network/midnight-srs-2p22";

            assert_eq!(current_url, MIDNIGHT_SRS_URL_K22);
        }

        #[test]
        fn golden_test_for_production_srs_hash() {
            let current_hash = "e8ad5eed936d657a0fb59d2a55ba19f81a3083bb3554ef88f464f5377e9b2c2f";

            assert_eq!(current_hash, MIDNIGHT_SRS_HASH_K22);
        }
    }
}
