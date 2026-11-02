use std::{
    ffi::OsStr,
    fmt::{Display, Formatter},
    fs,
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

use anyhow::Context;

use mithril_common::{
    StdResult,
    entities::{CompressionAlgorithm, ImmutableFileNumber},
};

/// An immutable files archive found in the cache directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImmutableFileArchive {
    /// Number of the immutable file the archive was created from
    pub immutable_file_number: ImmutableFileNumber,
    /// Path of the archive
    pub path: PathBuf,
}

/// Utilities to clean the cache directory of the immutable files compressed archives.
pub struct ImmutablesArchivesCacheCleaner {}

impl ImmutablesArchivesCacheCleaner {
    /// Detect the immutable files archives in the given cache directory.
    ///
    /// Only the files named after an immutable file number (i.e.: `00042.tar.zst`) for any
    /// supported compression algorithm are returned, other files and directories are ignored.
    pub fn detect_archives(cache_dir: &Path) -> StdResult<Vec<ImmutableFileArchive>> {
        if !cache_dir.exists() {
            return Ok(vec![]);
        }

        let mut archives = vec![];
        for entry in fs::read_dir(cache_dir)
            .with_context(|| format!("Can not read cache directory: '{}'", cache_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            if let Some(immutable_file_number) =
                Self::parse_immutable_file_number(&entry.file_name())
            {
                archives.push(ImmutableFileArchive {
                    immutable_file_number,
                    path: entry.path(),
                });
            }
        }

        Ok(archives)
    }

    /// Delete the given immutable files archives.
    pub fn delete_archives(archives: &[ImmutableFileArchive]) -> StdResult<()> {
        // Stop at the first failure: its cause (permissions, read-only filesystem, ...) most
        // likely affects all the archives, and a new run will detect the remaining ones.
        for archive in archives {
            fs::remove_file(&archive.path).with_context(|| {
                format!(
                    "Can not delete immutable files archive: '{}'",
                    archive.path.display()
                )
            })?;
        }

        Ok(())
    }

    fn parse_immutable_file_number(file_name: &OsStr) -> Option<ImmutableFileNumber> {
        let (immutable_file_number, extension) = file_name.to_str()?.split_once('.')?;

        let is_archive = immutable_file_number.len() == 5
            && immutable_file_number.chars().all(|c| c.is_ascii_digit())
            && CompressionAlgorithm::list()
                .iter()
                .any(|algorithm| algorithm.tar_file_extension() == extension);
        if !is_archive {
            return None;
        }

        immutable_file_number.parse().ok()
    }
}

/// Summary of the immutable files archives detected in the cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutablesArchivesSummary {
    /// Number of archives
    pub count: usize,
    /// Range from the lowest to the highest immutable file number (may contain holes)
    pub immutable_file_numbers: Option<RangeInclusive<ImmutableFileNumber>>,
}

impl ImmutablesArchivesSummary {
    /// Compute the summary of the given archives
    pub fn from_archives(archives: &[ImmutableFileArchive]) -> Self {
        let immutable_file_numbers = archives.iter().map(|archive| archive.immutable_file_number);
        let min = immutable_file_numbers.clone().min();
        let max = immutable_file_numbers.max();

        Self {
            count: archives.len(),
            immutable_file_numbers: min.zip(max).map(|(min, max)| min..=max),
        }
    }
}

impl Display for ImmutablesArchivesSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.immutable_file_numbers {
            None => write!(f, "No immutables archives"),
            Some(range) => write!(
                f,
                "{} immutables archives, immutable file numbers from {} to {}",
                self.count,
                range.start(),
                range.end()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, create_dir};

    use mithril_common::{
        temp_dir_create,
        test::{assert_dir_eq, assert_equivalent},
    };

    use super::*;

    fn archive(
        dir: &Path,
        immutable_file_number: ImmutableFileNumber,
        file_name: &str,
    ) -> ImmutableFileArchive {
        ImmutableFileArchive {
            immutable_file_number,
            path: dir.join(file_name),
        }
    }

    fn create_files(dir: &Path, file_names: &[&str]) {
        for file_name in file_names {
            File::create(dir.join(file_name)).unwrap();
        }
    }

    #[test]
    fn detect_nothing_if_cache_dir_does_not_exist() {
        let cache_dir = temp_dir_create!().join("does_not_exist");

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_eq!(Vec::<ImmutableFileArchive>::new(), archives);
    }

    #[test]
    fn detect_nothing_if_cache_dir_is_empty() {
        let cache_dir = temp_dir_create!();

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_eq!(Vec::<ImmutableFileArchive>::new(), archives);
    }

    #[test]
    fn detect_all_archives_even_with_holes_in_immutable_file_numbers() {
        let cache_dir = temp_dir_create!();
        create_files(
            &cache_dir,
            &["00000.tar.zst", "00001.tar.zst", "00005.tar.zst"],
        );

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_equivalent!(
            vec![
                archive(&cache_dir, 0, "00000.tar.zst"),
                archive(&cache_dir, 1, "00001.tar.zst"),
                archive(&cache_dir, 5, "00005.tar.zst"),
            ],
            archives
        );
    }

    #[test]
    fn ignore_files_and_directories_that_are_not_archives() {
        let cache_dir = temp_dir_create!();
        create_files(
            &cache_dir,
            &[
                "00002.tar.zst",
                "foo.txt",
                "1.tar.zst",
                "00001.tar",
                "00003.tar.zst.tmp",
                "x00004.tar.zst",
            ],
        );
        create_dir(cache_dir.join("00006.tar.zst")).unwrap();

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_eq!(vec![archive(&cache_dir, 2, "00002.tar.zst")], archives);
    }

    mod delete {
        use super::*;

        #[test]
        fn delete_detected_archives_and_keep_other_files() {
            let cache_dir = temp_dir_create!();
            create_files(
                &cache_dir,
                &["00000.tar.zst", "00001.tar.zst", "00005.tar.zst", "foo.txt"],
            );
            let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

            ImmutablesArchivesCacheCleaner::delete_archives(&archives).unwrap();

            assert_dir_eq!(&cache_dir, "* foo.txt");
        }

        #[test]
        fn delete_nothing_if_no_archives() {
            ImmutablesArchivesCacheCleaner::delete_archives(&[]).unwrap();
        }

        #[test]
        fn fail_with_the_archive_path_if_an_archive_can_not_be_deleted() {
            let cache_dir = temp_dir_create!();
            let missing_archive = archive(&cache_dir, 3, "00003.tar.zst");

            let error = ImmutablesArchivesCacheCleaner::delete_archives(std::slice::from_ref(
                &missing_archive,
            ))
            .expect_err("Deleting a missing archive should fail");

            assert!(
                error
                    .to_string()
                    .contains(&missing_archive.path.display().to_string()),
                "Error should contain the archive path, got: {error}"
            );
        }
    }

    mod summary {
        use super::*;

        #[test]
        fn summary_of_no_archives() {
            let summary = ImmutablesArchivesSummary::from_archives(&[]);

            assert_eq!(
                ImmutablesArchivesSummary {
                    count: 0,
                    immutable_file_numbers: None,
                },
                summary
            );
            assert_eq!("No immutables archives", summary.to_string());
        }

        #[test]
        fn summary_of_a_single_archive() {
            let cache_dir = PathBuf::from("cache");
            let summary = ImmutablesArchivesSummary::from_archives(&[archive(
                &cache_dir,
                42,
                "00042.tar.zst",
            )]);

            assert_eq!(
                ImmutablesArchivesSummary {
                    count: 1,
                    immutable_file_numbers: Some(42..=42),
                },
                summary
            );
            assert_eq!(
                "1 immutables archives, immutable file numbers from 42 to 42",
                summary.to_string()
            );
        }

        #[test]
        fn summary_of_unordered_archives_with_holes() {
            let cache_dir = PathBuf::from("cache");
            let summary = ImmutablesArchivesSummary::from_archives(&[
                archive(&cache_dir, 5, "00005.tar.zst"),
                archive(&cache_dir, 0, "00000.tar.zst"),
                archive(&cache_dir, 1, "00001.tar.zst"),
            ]);

            assert_eq!(
                ImmutablesArchivesSummary {
                    count: 3,
                    immutable_file_numbers: Some(0..=5),
                },
                summary
            );
            assert_eq!(
                "3 immutables archives, immutable file numbers from 0 to 5",
                summary.to_string()
            );
        }
    }
}
