use anyhow::{Context, anyhow};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use slog::{Logger, info, warn};
use std::{
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tar::{Archive, Entry, EntryType};
use zstd::{Decoder, Encoder};

use mithril_common::StdResult;
use mithril_common::entities::CompressionAlgorithm;
use mithril_common::logging::LoggerExtensions;

use crate::ZstandardCompressionParameters;
use crate::tools::file_size;

use super::appender::TarAppender;
use super::{ArchiveParameters, FileArchive};

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

    #[cfg(test)]
    pub fn new_for_test(verification_temp_dir: PathBuf) -> Self {
        use crate::test::TestLogger;
        Self {
            zstandard_compression_parameter: ZstandardCompressionParameters::default(),
            verification_temp_dir,
            logger: TestLogger::stdout(),
        }
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
            CompressionAlgorithm::Gzip => {
                let enc = GzEncoder::new(tar_file, Compression::default());
                let mut tar = tar::Builder::new(enc);

                appender
                    .append(&mut tar)
                    .with_context(|| "GzEncoder Builder failed to append content")?;

                let mut gz = tar
                    .into_inner()
                    .with_context(|| "GzEncoder Builder can not write the archive")?;
                gz.try_finish()
                    .with_context(|| "GzEncoder can not finish the output stream after writing")?;
            }
            CompressionAlgorithm::Zstandard => {
                let mut enc = Encoder::new(tar_file, self.zstandard_compression_parameter.level)?;
                enc.multithread(self.zstandard_compression_parameter.number_of_workers)
                    .with_context(|| "ZstandardEncoder can not set the number of workers")?;
                let mut tar = tar::Builder::new(enc);

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
            CompressionAlgorithm::Gzip => {
                let archive_decoder = GzDecoder::new(archive_file_tar);
                Archive::new(Box::new(archive_decoder))
            }
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
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use mithril_common::test::assert_equivalent;

    use crate::tools::file_archiver::appender::{AppenderDirAll, AppenderFile};
    use crate::tools::file_archiver::test_tools::*;

    use super::*;

    fn list_remaining_files(test_dir: &Path) -> Vec<String> {
        fs::read_dir(test_dir)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn should_create_a_valid_archive_with_gzip_compression() {
        let test_dir = get_test_directory("should_create_a_valid_archive_with_gzip_compression");
        let target_archive = test_dir.join("archive.tar.gz");
        let archived_directory = test_dir.join(create_dir(&test_dir, "archived_directory"));
        create_file(&archived_directory, "file_to_archive.txt");

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive = file_archiver
            .create_archive(
                &target_archive,
                AppenderDirAll::new(archived_directory),
                CompressionAlgorithm::Gzip,
            )
            .expect("create_archive should not fail");
        file_archiver
            .verify_archive(&archive)
            .expect("verify_archive should not fail");
    }

    #[test]
    fn should_create_a_valid_archive_with_zstandard_compression() {
        let test_dir =
            get_test_directory("should_create_a_valid_archive_with_zstandard_compression");
        let target_archive = test_dir.join("archive.tar.zst");
        let archived_directory = test_dir.join(create_dir(&test_dir, "archived_directory"));
        create_file(&archived_directory, "file_to_archive.txt");

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive = file_archiver
            .create_archive(
                &target_archive,
                AppenderDirAll::new(archived_directory),
                CompressionAlgorithm::Zstandard,
            )
            .expect("create_archive should not fail");
        file_archiver
            .verify_archive(&archive)
            .expect("verify_archive should not fail");
    }

    #[test]
    fn should_delete_tmp_file_in_target_directory_if_archiving_fail() {
        let test_dir =
            get_test_directory("should_delete_tmp_file_in_target_directory_if_archiving_fail");
        // Note: the archived directory does not exist in order to make the archive process fail
        let archived_directory = test_dir.join("db");

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        // this file should not be deleted by the archive creation
        File::create(test_dir.join("other-process.file")).unwrap();

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let _ = file_archiver
            .archive(archive_params, AppenderDirAll::new(archived_directory))
            .expect_err("FileArchiver::archive should fail if the target path doesn't exist.");

        let remaining_files: Vec<String> = list_remaining_files(&test_dir);
        assert_eq!(vec!["other-process.file".to_string()], remaining_files);
    }

    #[test]
    fn should_not_delete_an_already_existing_archive_with_same_name_if_archiving_fail() {
        let test_dir = get_test_directory(
            "should_not_delete_an_already_existing_archive_with_same_name_if_archiving_fail",
        );
        // Note: the archived directory does not exist in order to make the archive process fail
        let archived_directory = test_dir.join("db");

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
            .archive(archive_params, AppenderDirAll::new(archived_directory))
            .expect_err("FileArchiver::archive should fail if the db is empty.");
        let remaining_files: Vec<String> = list_remaining_files(&test_dir);

        assert_equivalent!(
            vec!["other-process.file".to_string(), "archive.tar.zst".to_string()],
            remaining_files,
        );
    }

    #[test]
    fn overwrite_already_existing_archive_when_archiving_succeed() {
        let test_dir =
            get_test_directory("overwrite_already_existing_archive_when_archiving_succeed");
        let archived_directory = test_dir.join(create_dir(&test_dir, "archived_directory"));

        create_file(&archived_directory, "file_to_archive.txt");

        let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

        let archive_params = ArchiveParameters {
            archive_name_without_extension: "archive".to_string(),
            target_directory: test_dir.clone(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };
        let first_archive = file_archiver
            .archive(
                archive_params.clone(),
                AppenderDirAll::new(archived_directory.clone()),
            )
            .unwrap();
        let first_archive_size = first_archive.get_archive_size();

        create_file(&archived_directory, "another_file_to_archive.txt");

        let second_archive = file_archiver
            .archive(archive_params, AppenderDirAll::new(archived_directory))
            .unwrap();
        let second_archive_size = second_archive.get_archive_size();

        assert_ne!(first_archive_size, second_archive_size);

        let unpack_path = second_archive.unpack_zstandard(&test_dir);
        assert!(unpack_path.join("another_file_to_archive.txt").exists());
    }

    #[test]
    fn compute_size_of_uncompressed_data_and_archive() {
        let test_dir = get_test_directory("compute_size_of_uncompressed_data_and_archive");

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
