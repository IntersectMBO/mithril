use anyhow::{Context, anyhow};
use slog::{Logger, info, warn};
use std::{
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tar::{Archive, Entry, EntryType, HeaderMode};
use zstd::{Decoder, Encoder};

use mithril_common::StdResult;
use mithril_common::entities::CompressionAlgorithm;
use mithril_common::logging::LoggerExtensions;

use crate::appender::TarAppender;
use crate::entities::{ArchiveParameters, FileArchive, ZstandardCompressionParameters};
use crate::tools::file_size;

/// Tool to archive files and directories.
pub struct FileArchiver {
    zstandard_compression_parameter: ZstandardCompressionParameters,
    // Temporary directory to  the unpacked archive for verification
    verification_temp_dir: PathBuf,
    logger: Logger,
}

impl FileArchiver {
    /// Constructs a new `FileArchiver`.
    pub fn new(
        zstandard_compression_parameter: ZstandardCompressionParameters,
        verification_temp_dir: PathBuf,
        logger: Logger,
    ) -> Self {
        Self {
            zstandard_compression_parameter,
            verification_temp_dir,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Constructs a new `FileArchiver` that uses the default compression parameters.
    pub fn new_with_default_parameters(verification_temp_dir: PathBuf, logger: Logger) -> Self {
        Self::new(
            ZstandardCompressionParameters::default(),
            verification_temp_dir,
            logger,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(verification_temp_dir: PathBuf) -> Self {
        Self::new_with_default_parameters(verification_temp_dir, crate::test::TestLogger::stdout())
    }

    /// Archive the content of a directory.
    pub fn archive<T: TarAppender>(
        &self,
        parameters: ArchiveParameters,
        appender: T,
    ) -> StdResult<FileArchive> {
        fs::create_dir_all(&parameters.target_directory).with_context(|| {
            format!(
                "FileArchiver can not create archive directory: '{}'",
                parameters.target_directory.display()
            )
        })?;

        let target_path = parameters.target_path();
        let temporary_archive_path = parameters.temporary_archive_path();

        let temporary_file_archive = self
            .create_and_verify_archive(
                &temporary_archive_path,
                appender,
                parameters.compression_algorithm,
            )
            .inspect_err(|_err| {
                if temporary_archive_path.exists()
                    && let Err(remove_error) = fs::remove_file(&temporary_archive_path)
                {
                    warn!(
                        self.logger,
                        " > Post FileArchiver.archive failure, could not remove temporary archive";
                        "archive_path" => temporary_archive_path.display(),
                        "error" => remove_error
                    );
                }
            })
            .with_context(|| {
                format!(
                    "FileArchiver can not create and verify archive: '{}'",
                    target_path.display()
                )
            })?;

        fs::rename(&temporary_archive_path, &target_path).with_context(|| {
            format!(
                "FileArchiver can not rename temporary archive: '{}' to final archive: '{}'",
                temporary_archive_path.display(),
                target_path.display()
            )
        })?;

        Ok(FileArchive {
            filepath: target_path,
            ..temporary_file_archive
        })
    }

    fn create_and_verify_archive<T: TarAppender>(
        &self,
        archive_path: &Path,
        appender: T,
        compression_algorithm: CompressionAlgorithm,
    ) -> StdResult<FileArchive> {
        let file_archive = self
            .create_archive(archive_path, appender, compression_algorithm)
            .with_context(|| {
                format!(
                    "FileArchiver can not create archive with path: '{}''",
                    archive_path.display()
                )
            })?;
        self.verify_archive(&file_archive).with_context(|| {
            format!(
                "FileArchiver can not verify archive with path: '{}''",
                archive_path.display()
            )
        })?;

        Ok(file_archive)
    }

    fn create_archive<T: TarAppender>(
        &self,
        archive_path: &Path,
        appender: T,
        compression_algorithm: CompressionAlgorithm,
    ) -> StdResult<FileArchive> {
        info!(
            self.logger,
            "Archiving content to archive: '{}'",
            archive_path.display()
        );

        let tar_file = File::create(archive_path).with_context(|| {
            format!("Error while creating the archive with path: {archive_path:?}")
        })?;

        match compression_algorithm {
            CompressionAlgorithm::Zstandard => {
                let mut enc = Encoder::new(tar_file, self.zstandard_compression_parameter.level)?;
                enc.multithread(self.zstandard_compression_parameter.number_of_workers)
                    .with_context(|| "ZstandardEncoder can not set the number of workers")?;
                let mut tar = tar::Builder::new(enc);
                Self::configure_tar_builder(&mut tar);

                appender
                    .append(&mut tar)
                    .with_context(|| "ZstandardEncoder Builder failed to append content")?;

                let zstd = tar
                    .into_inner()
                    .with_context(|| "ZstandardEncoder Builder can not write the archive")?;
                zstd.finish().with_context(
                    || "ZstandardEncoder can not finish the output stream after writing",
                )?;
            }
        }

        let uncompressed_size = appender.compute_uncompressed_data_size().with_context(|| {
            format!(
                "FileArchiver can not get the size of the uncompressed data to archive: '{}'",
                archive_path.display()
            )
        })?;
        let archive_filesize =
            file_size::compute_size_of_path(archive_path).with_context(|| {
                format!(
                    "FileArchiver can not get file size of archive with path: '{}'",
                    archive_path.display()
                )
            })?;

        Ok(FileArchive {
            filepath: archive_path.to_path_buf(),
            archive_filesize,
            uncompressed_size,
            compression_algorithm,
        })
    }

    /// Verify the integrity of the archive.
    fn verify_archive(&self, archive: &FileArchive) -> StdResult<()> {
        info!(
            self.logger,
            "Verifying archive: {}",
            archive.filepath.display()
        );

        let mut archive_file_tar = File::open(&archive.filepath).with_context(|| {
            format!(
                "Verify archive error: can not open archive: '{}'",
                archive.filepath.display()
            )
        })?;
        archive_file_tar.seek(SeekFrom::Start(0))?;

        let mut tar_archive: Archive<Box<dyn Read>> = match archive.compression_algorithm {
            CompressionAlgorithm::Zstandard => {
                let archive_decoder = Decoder::new(archive_file_tar)?;
                Archive::new(Box::new(archive_decoder))
            }
        };

        let unpack_temp_dir = self
            .verification_temp_dir
            // Add the archive name to the directory to allow two verifications at the same time
            .join(archive.filepath.file_name().with_context(|| format!(
                "Verify archive error: Could not append archive name to temp directory: archive `{}`",
                archive.filepath.display(),
            ))?);

        fs::create_dir_all(&unpack_temp_dir).with_context(|| {
            format!(
                "Verify archive error: Could not create directory `{}`",
                unpack_temp_dir.display(),
            )
        })?;

        let unpack_temp_file = &unpack_temp_dir.join("unpack.tmp");

        let verify_result = {
            let mut result = Ok(());
            for e in tar_archive.entries()? {
                match e {
                    Err(e) => {
                        result = Err(anyhow!(e).context("Verify archive error: invalid entry"));
                        break;
                    }
                    Ok(entry) => Self::unpack_and_delete_file_from_entry(entry, unpack_temp_file)?,
                };
            }
            result
        };

        // Always remove the temp directory
        fs::remove_dir_all(&unpack_temp_dir).with_context(|| {
            format!(
                "Verify archive error: Could not remove directory `{}`",
                unpack_temp_dir.display()
            )
        })?;

        verify_result
    }

    // Helper to unpack and delete a file from en entry, for archive verification purpose
    fn unpack_and_delete_file_from_entry<R: Read>(
        entry: Entry<R>,
        unpack_file_path: &Path,
    ) -> StdResult<()> {
        if entry.header().entry_type() != EntryType::Directory {
            let mut file = entry;
            let _ = file.unpack(unpack_file_path).with_context(|| "can't unpack entry")?;

            fs::remove_file(unpack_file_path).with_context(|| {
                format!(
                    "can't remove temporary unpacked file, file path: `{}`",
                    unpack_file_path.display()
                )
            })?;
        }

        Ok(())
    }

    fn configure_tar_builder<W: std::io::Write>(builder: &mut tar::Builder<W>) {
        builder.mode(HeaderMode::Deterministic);
        builder.follow_symlinks(false);
        // disable sparse files, as their support is not uniform across platforms and the size
        // difference won't matter with zstandard compression
        builder.sparse(false);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use mithril_common::temp_dir_create;
    use mithril_common::test::assert_equivalent;

    use crate::appender::{AppenderEntries, AppenderFile};
    use crate::test::{FileArchiveTestExtension, create_dir, create_file, double::FailAppender};

    use super::*;

    fn list_remaining_files(test_dir: &Path) -> Vec<String> {
        fs::read_dir(test_dir)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn should_create_a_valid_archive_with_zstandard_compression() {
        let test_dir = temp_dir_create!();
        let target_archive = test_dir.join("archive.tar.zst");
        let source_dir = test_dir.join(create_dir(&test_dir, "source"));
        let archived_file = source_dir.join(create_file(&source_dir, "file_to_archive.txt"));

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive = file_archiver
            .create_archive(
                &target_archive,
                AppenderFile::append_at_archive_root(archived_file).unwrap(),
                CompressionAlgorithm::Zstandard,
            )
            .expect("create_archive should not fail");
        file_archiver
            .verify_archive(&archive)
            .expect("verify_archive should not fail");
    }

    #[test]
    fn should_delete_tmp_file_in_target_directory_if_archiving_fail() {
        let test_dir = temp_dir_create!();

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        // this file should not be deleted by the archive creation
        File::create(test_dir.join("other-process.file")).unwrap();

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let _ = file_archiver
            .archive(archive_params, FailAppender)
            .expect_err("FileArchiver::archive should fail if the target path doesn't exist.");

        let remaining_files: Vec<String> = list_remaining_files(&test_dir);
        assert_eq!(vec!["other-process.file".to_string()], remaining_files);
    }

    #[test]
    fn should_not_delete_an_already_existing_archive_with_same_name_if_archiving_fail() {
        let test_dir = temp_dir_create!();

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        // this file should not be deleted by the archive creation
        create_file(&test_dir, "other-process.file");
        create_file(&test_dir, "archive.tar.zst");
        // an already existing temporary archive file should be deleted
        create_file(&test_dir, "archive.tar.tmp");

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let _ = file_archiver
            .archive(archive_params, FailAppender)
            .expect_err("FileArchiver::archive should fail if the db is empty.");
        let remaining_files: Vec<String> = list_remaining_files(&test_dir);

        assert_equivalent!(
            vec!["other-process.file".to_string(), "archive.tar.zst".to_string()],
            remaining_files,
        );
    }

    #[test]
    fn overwrite_already_existing_archive_when_archiving_succeed() {
        let test_dir = temp_dir_create!();
        let source = test_dir.join(create_dir(&test_dir, "source"));
        let file_to_archive = create_file(&source, "file_to_archive.txt");

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let first_archive = file_archiver
            .archive(
                archive_params.clone(),
                AppenderEntries::new(vec![file_to_archive.clone()], source.clone()).unwrap(),
            )
            .unwrap();
        let first_archive_size = first_archive.get_archive_size();

        let another_file_to_archive = create_file(&source, "another_file_to_archive.txt");

        let second_archive = file_archiver
            .archive(
                archive_params,
                AppenderEntries::new(
                    vec![file_to_archive, another_file_to_archive],
                    source.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let second_archive_size = second_archive.get_archive_size();

        assert_ne!(first_archive_size, second_archive_size);

        let unpack_path = second_archive.unpack_zstandard(&test_dir);
        assert!(unpack_path.join("another_file_to_archive.txt").exists());
    }

    #[test]
    fn compute_size_of_uncompressed_data_and_archive() {
        let test_dir = temp_dir_create!();

        let file_path = test_dir.join("file.txt");
        let file = File::create(&file_path).unwrap();
        file.set_len(777).unwrap();

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let archive = file_archiver
            .archive(
                archive_params.clone(),
                AppenderFile::append_at_archive_root(file_path.clone()).unwrap(),
            )
            .unwrap();

        let expected_archive_size = file_size::compute_size_of_path(&archive.filepath).unwrap();
        assert_eq!(expected_archive_size, archive.get_archive_size(),);
        assert_eq!(777, archive.get_uncompressed_size());
    }
}
