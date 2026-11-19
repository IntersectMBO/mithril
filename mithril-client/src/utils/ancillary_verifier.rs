use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context;
use thiserror::Error;

use mithril_cardano_node_internal_database::entities::{
    AncillaryFilesManifest, AncillaryFilesManifestVerifyError,
};
use mithril_common::crypto_helper::{ManifestVerifier, ManifestVerifierVerificationKey};

use crate::utils::move_file;
use crate::{MithrilError, MithrilResult};

/// Verifies the ancillary files contained in an unpacked ancillary archive
pub struct AncillaryVerifier {
    verifier: ManifestVerifier,
}

/// Error type for the ancillary verification process
#[derive(Error, Debug)]
pub enum AncillaryVerificationError {
    #[error("Failed to read manifest: `{0}`")]
    ManifestParse(PathBuf, #[source] MithrilError),
    #[error("Manifest is invalid")]
    ManifestInvalid(#[from] AncillaryFilesManifestVerifyError),
    #[error("Signature is missing")]
    SignatureMissing,
    #[error("Signature is invalid")]
    SignatureInvalid(#[source] MithrilError),
}

/// Represents a validated ancillary manifest which files can be moved to a final location
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedAncillaryManifest {
    base_directory: PathBuf,
    ancillary_files: Vec<PathBuf>,
}

impl AncillaryVerifier {
    /// `AncillaryVerifier` factory
    pub fn new(verification_key: ManifestVerifierVerificationKey) -> Self {
        AncillaryVerifier {
            verifier: ManifestVerifier::from_verification_key(verification_key),
        }
    }

    /// Verifies that the unpacked ancillary archive contains a signed manifest and that the
    /// files contained in the manifest are present and match the expected hashes
    ///
    /// The signature is verified first, so that only the files named by a signed manifest are read.
    pub async fn verify(
        &self,
        temp_ancillary_dir: &Path,
    ) -> Result<ValidatedAncillaryManifest, AncillaryVerificationError> {
        let ancillary_manifest_path =
            temp_ancillary_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME);
        let manifest_file = File::open(&ancillary_manifest_path)
            .with_context(|| "Failed to open manifest file")
            .map_err(|e| {
                AncillaryVerificationError::ManifestParse(ancillary_manifest_path.clone(), e)
            })?;
        let manifest: AncillaryFilesManifest =
            serde_json::from_reader(&manifest_file).map_err(|e| {
                AncillaryVerificationError::ManifestParse(ancillary_manifest_path, e.into())
            })?;

        let signature = manifest
            .signature()
            .ok_or(AncillaryVerificationError::SignatureMissing)?;
        self.verifier
            .verify(&manifest.compute_hash(), &signature)
            .map_err(AncillaryVerificationError::SignatureInvalid)?;

        manifest.verify_data(temp_ancillary_dir).await?;

        Ok(ValidatedAncillaryManifest {
            base_directory: temp_ancillary_dir.to_path_buf(),
            ancillary_files: manifest.files(),
        })
    }
}

impl ValidatedAncillaryManifest {
    /// Moves the ancillary files to their final location
    pub async fn move_to_final_location(&self, final_location: &Path) -> MithrilResult<()> {
        // Do two passes in order to avoid stopping the process mid-way when we already
        // moved, or even overwrote, some files
        for file in &self.ancillary_files {
            Self::ensure_parent_directory_exists(final_location, file).await?;
        }

        for file in &self.ancillary_files {
            let target_path = final_location.join(file);
            move_file(&self.base_directory.join(file), &target_path)
                .await
                .with_context(|| format!("Failed to move file: `{file:?}`"))?;
        }

        Ok(())
    }

    async fn ensure_parent_directory_exists(
        final_location: &Path,
        file: &Path,
    ) -> MithrilResult<()> {
        let parent_target_dir = final_location.join(file.parent().unwrap_or(Path::new("")));

        if !parent_target_dir.exists() {
            tokio::fs::create_dir_all(&parent_target_dir)
                .await
                .with_context(|| format!("Failed to create directory: `{parent_target_dir:?}`"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use mithril_common::{assert_dir_eq, temp_dir_create};

    use super::*;

    fn write_file(target_path: &Path, content: &str) {
        let mut file = File::create(target_path).unwrap();
        write!(file, "{content}").unwrap();
    }

    mod ancillary_verifier {
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;

        use mithril_common::entities::SignableManifest;
        use mithril_common::{crypto_helper::ManifestSigner, test::double::fake_keys};

        use super::*;

        fn write_manifest(target_dir: &Path, manifest: &AncillaryFilesManifest) {
            serde_json::to_writer(
                File::create(target_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME))
                    .unwrap(),
                manifest,
            )
            .unwrap();
        }

        fn generate_manifest_item(
            target_folder: &Path,
            filename: &str,
            content: &str,
        ) -> (PathBuf, String) {
            write_file(&target_folder.join(filename), content);
            (
                PathBuf::from(filename),
                compute_sha256_hash(content.as_bytes()),
            )
        }

        fn compute_sha256_hash(data: impl AsRef<[u8]>) -> String {
            hex::encode(Sha256::digest(data))
        }

        /// Generates a valid, signed, manifest with two files
        fn valid_manifest(temp_dir: &Path, signer: &ManifestSigner) -> AncillaryFilesManifest {
            let mut manifest = AncillaryFilesManifest::new_without_signature(BTreeMap::from([
                generate_manifest_item(temp_dir, "file1.txt", "content 1"),
                generate_manifest_item(temp_dir, "file2.txt", "content 2"),
            ]));
            manifest.set_signature(signer.sign(&manifest.compute_hash()));
            manifest
        }

        #[tokio::test]
        async fn fail_if_no_manifest_found() {
            let temp_dir = temp_dir_create!();

            let ancillary_verifier = AncillaryVerifier::new(
                fake_keys::manifest_verification_key()[0].try_into().unwrap(),
            );

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::ManifestParse(..)),
                "Expected AncillaryVerificationError::ManifestParse, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_if_manifest_is_not_a_valid_json() {
            let temp_dir = temp_dir_create!();
            let manifest_file =
                File::create(temp_dir.join(AncillaryFilesManifest::ANCILLARY_MANIFEST_FILE_NAME))
                    .unwrap();
            write!(&manifest_file, "invalid json").unwrap();

            let ancillary_verifier = AncillaryVerifier::new(
                fake_keys::manifest_verification_key()[0].try_into().unwrap(),
            );

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::ManifestParse(..)),
                "Expected AncillaryVerificationError::ManifestParse, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_if_manifest_is_invalid() {
            let temp_dir = temp_dir_create!();
            let signer = ManifestSigner::create_deterministic_signer();
            let mut manifest = AncillaryFilesManifest::new_without_signature(BTreeMap::from([(
                PathBuf::from("invalid path"),
                "invalid sha".to_string(),
            )]));
            manifest.set_signature(signer.sign(&manifest.compute_hash()));
            write_manifest(&temp_dir, &manifest);

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::ManifestInvalid(_)),
                "Expected AncillaryVerificationError::ManifestInvalid, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_if_a_signed_manifest_names_a_file_outside_its_directory() {
            let temp_dir = temp_dir_create!();
            let ancillary_dir = temp_dir.join("ancillary");
            std::fs::create_dir(&ancillary_dir).unwrap();
            let signer = ManifestSigner::create_deterministic_signer();
            let (_, outside_file_hash) =
                generate_manifest_item(&temp_dir, "outside.txt", "content");
            let mut manifest = AncillaryFilesManifest::new_without_signature(BTreeMap::from([(
                PathBuf::from("../outside.txt"),
                outside_file_hash,
            )]));
            manifest.set_signature(signer.sign(&manifest.compute_hash()));
            write_manifest(&ancillary_dir, &manifest);

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let err = ancillary_verifier.verify(&ancillary_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::ManifestParse(..)),
                "Expected AncillaryVerificationError::ManifestParse, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_if_signature_is_missing() {
            let temp_dir = temp_dir_create!();
            let signer = ManifestSigner::create_deterministic_signer();
            let manifest = AncillaryFilesManifest {
                signable_manifest: SignableManifest {
                    signature: None,
                    ..valid_manifest(&temp_dir, &signer).signable_manifest
                },
            };
            write_manifest(&temp_dir, &manifest);

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::SignatureMissing),
                "Expected AncillaryVerificationError::SignatureMissing, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_if_signature_is_invalid() {
            let temp_dir = temp_dir_create!();
            let signer = ManifestSigner::create_deterministic_signer();
            let manifest = AncillaryFilesManifest {
                signable_manifest: SignableManifest {
                    // Note: This is a valid signature, but for different data
                    signature: Some(
                        fake_keys::signable_manifest_signature()[0].try_into().unwrap(),
                    ),
                    ..valid_manifest(&temp_dir, &signer).signable_manifest
                },
            };
            write_manifest(&temp_dir, &manifest);

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::SignatureInvalid(_)),
                "Expected AncillaryVerificationError::SignatureInvalid, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn fail_with_an_invalid_signature_before_reading_the_files_of_the_manifest() {
            let temp_dir = temp_dir_create!();
            let signer = ManifestSigner::create_deterministic_signer();
            let manifest = AncillaryFilesManifest {
                signable_manifest: SignableManifest {
                    data: BTreeMap::from([(
                        PathBuf::from("missing_file.txt"),
                        "whatever hash".to_string(),
                    )]),
                    signature: Some(
                        fake_keys::signable_manifest_signature()[0].try_into().unwrap(),
                    ),
                },
            };
            write_manifest(&temp_dir, &manifest);

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let err = ancillary_verifier.verify(&temp_dir).await.unwrap_err();
            assert!(
                matches!(err, AncillaryVerificationError::SignatureInvalid(_)),
                "Expected AncillaryVerificationError::SignatureInvalid, got: {err:?}",
            );
        }

        #[tokio::test]
        async fn succeed_if_manifest_is_valid_and_signed() {
            let temp_dir = temp_dir_create!();
            let signer = ManifestSigner::create_deterministic_signer();
            let manifest = valid_manifest(&temp_dir, &signer);
            write_manifest(&temp_dir, &manifest);
            File::create(temp_dir.join("not_in_manifest.txt")).unwrap();

            let ancillary_verifier = AncillaryVerifier::new(signer.verification_key());

            let validated_manifest = ancillary_verifier.verify(&temp_dir).await.unwrap();
            assert_eq!(
                ValidatedAncillaryManifest {
                    base_directory: temp_dir,
                    ancillary_files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt"),],
                },
                validated_manifest
            );
        }
    }

    mod moving_validated_manifest {
        use super::*;

        #[tokio::test]
        async fn move_only_files_in_structure_to_final_location() {
            let temp_dir = temp_dir_create!();
            println!("temp_dir: {temp_dir:?}");
            let source_dir = temp_dir.join("source");
            let target_dir = temp_dir.join("target");
            for dir in &[&source_dir.join("subdir"), &target_dir] {
                std::fs::create_dir_all(dir).unwrap();
            }

            let file_in_root_dir = PathBuf::from("file1.txt");
            let file_in_subdir = PathBuf::from("subdir/file2.txt");
            let not_moved_path = PathBuf::from("not_moved.txt");

            for path in &[&file_in_root_dir, &file_in_subdir, &not_moved_path] {
                File::create(source_dir.join(path)).unwrap();
            }

            let validated_manifest = ValidatedAncillaryManifest {
                base_directory: source_dir.clone(),
                ancillary_files: vec![file_in_root_dir.clone(), file_in_subdir.clone()],
            };

            validated_manifest.move_to_final_location(&target_dir).await.unwrap();

            assert_dir_eq!(
                &source_dir,
                "* subdir/
                 * not_moved.txt"
            );
            assert_dir_eq!(
                &target_dir,
                "* subdir/
                 ** file2.txt
                 * file1.txt"
            );
        }

        #[tokio::test]
        async fn overwrite_existing_file_in_the_final_location() {
            let temp_dir = temp_dir_create!();
            let source_dir = temp_dir.join("source");
            let target_dir = temp_dir.join("target");
            for dir in &[&source_dir, &target_dir] {
                std::fs::create_dir_all(dir).unwrap();
            }

            let existing_file_path = PathBuf::from("file.txt");
            write_file(&source_dir.join(&existing_file_path), "final content");
            write_file(&target_dir.join(&existing_file_path), "overwritten content");

            let validated_manifest = ValidatedAncillaryManifest {
                base_directory: source_dir.clone(),
                ancillary_files: vec![existing_file_path.clone()],
            };

            assert!(target_dir.join(&existing_file_path).exists());
            validated_manifest.move_to_final_location(&target_dir).await.unwrap();

            assert!(!source_dir.join(&existing_file_path).exists());
            let final_content =
                std::fs::read_to_string(target_dir.join(&existing_file_path)).unwrap();
            assert_eq!("final content", final_content);
        }

        #[tokio::test]
        async fn only_create_parent_directory_if_it_does_not_exist() {
            let temp_dir = temp_dir_create!();
            let existing_dir = PathBuf::from("existing_dir");
            std::fs::create_dir(temp_dir.join(&existing_dir)).unwrap();
            File::create(temp_dir.join(&existing_dir).join("file.txt")).unwrap();

            ValidatedAncillaryManifest::ensure_parent_directory_exists(
                &temp_dir,
                &existing_dir.join("dir_to_add").join("whatever.txt"),
            )
            .await
            .unwrap();

            assert!(
                temp_dir.join(&existing_dir).join("file.txt").exists(),
                "existing file should not have been deleted"
            );
            assert!(temp_dir.join(&existing_dir).join("dir_to_add").exists());
        }
    }
}
