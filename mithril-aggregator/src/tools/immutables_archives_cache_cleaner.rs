use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;

use mithril_common::{StdResult, entities::CompressionAlgorithm};

/// Utilities to clean the cache directory of the immutable files compressed archives.
pub struct ImmutablesArchivesCacheCleaner {}

impl ImmutablesArchivesCacheCleaner {
    /// Detect the immutable files archives in the given cache directory.
    ///
    /// Only the files named after an immutable file number (i.e.: `00042.tar.zst`) for any
    /// supported compression algorithm are returned, other files and directories are ignored.
    pub fn detect_archives(cache_dir: &Path) -> StdResult<Vec<PathBuf>> {
        if !cache_dir.exists() {
            return Ok(vec![]);
        }

        let mut archives = vec![];
        for entry in fs::read_dir(cache_dir)
            .with_context(|| format!("Can not read cache directory: '{}'", cache_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_file() && Self::is_archive_file_name(&entry.file_name()) {
                archives.push(entry.path());
            }
        }

        Ok(archives)
    }

    fn is_archive_file_name(file_name: &OsStr) -> bool {
        let Some((immutable_file_number, extension)) =
            file_name.to_str().and_then(|name| name.split_once('.'))
        else {
            return false;
        };

        immutable_file_number.len() == 5
            && immutable_file_number.chars().all(|c| c.is_ascii_digit())
            && CompressionAlgorithm::list()
                .iter()
                .any(|algorithm| algorithm.tar_file_extension() == extension)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, create_dir};

    use mithril_common::{temp_dir_create, test::assert_equivalent};

    use super::*;

    fn create_files(dir: &Path, file_names: &[&str]) {
        for file_name in file_names {
            File::create(dir.join(file_name)).unwrap();
        }
    }

    #[test]
    fn detect_nothing_if_cache_dir_does_not_exist() {
        let cache_dir = temp_dir_create!().join("does_not_exist");

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_eq!(Vec::<PathBuf>::new(), archives);
    }

    #[test]
    fn detect_nothing_if_cache_dir_is_empty() {
        let cache_dir = temp_dir_create!();

        let archives = ImmutablesArchivesCacheCleaner::detect_archives(&cache_dir).unwrap();

        assert_eq!(Vec::<PathBuf>::new(), archives);
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
                cache_dir.join("00000.tar.zst"),
                cache_dir.join("00001.tar.zst"),
                cache_dir.join("00005.tar.zst"),
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

        assert_eq!(vec![cache_dir.join("00002.tar.zst")], archives);
    }
}
