//! Tooling to compute File and Directory Sizes

use anyhow::Context;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use mithril_common::StdResult;

/// Compute the size of the given paths that could be files or folders.
pub fn compute_size(paths: Vec<PathBuf>) -> StdResult<u64> {
    fn remove_duplicated_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        let mut result_folders = vec![];
        let mut result_files = HashSet::new();
        let mut paths = paths;
        paths.sort();
        for path in paths {
            if result_folders
                .last()
                .is_none_or(|last_folder| !path.starts_with(last_folder))
            {
                if path.is_file() {
                    result_files.insert(path);
                } else {
                    result_folders.push(path);
                }
            }
        }

        result_folders.extend(result_files);
        result_folders
    }

    let paths = remove_duplicated_paths(paths);

    let mut total = 0;
    for path_to_include in paths {
        total += compute_size_of_path(&path_to_include)?;
    }
    Ok(total)
}

/// Compute the size of one given path that could be a file or a folder.
///
/// Returns 0 if the path is not a file or a folder.
pub fn compute_size_of_path(path: &Path) -> StdResult<u64> {
    if path.is_file() {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for file: {path:?}"))?;

        return Ok(metadata.len());
    }

    if path.is_dir() {
        let entries = std::fs::read_dir(path)
            .with_context(|| format!("Failed to read directory: {path:?}"))?;
        let mut directory_size = 0;
        for entry in entries {
            let path = entry
                .with_context(|| format!("Failed to read directory entry in {path:?}"))?
                .path();
            directory_size += compute_size_of_path(&path)?;
        }

        return Ok(directory_size);
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use mithril_common::current_function;
    use mithril_common::test::TempDir;

    use super::*;

    /// Create a file with the given name in the given dir, write some text to it, and then
    /// return its path.
    fn write_dummy_file(optional_size: Option<u64>, dir: &Path, filename: &str) -> PathBuf {
        let file = dir.join(Path::new(filename));
        let mut source_file = File::create(&file).unwrap();

        write!(source_file, "This is a test file named '{filename}'").unwrap();

        if let Some(file_size) = optional_size {
            writeln!(source_file).unwrap();
            source_file.set_len(file_size).unwrap();
        }

        file
    }

    #[test]
    fn test_compute_file_size() {
        let test_dir = TempDir::create("utils", current_function!());
        let file_path = write_dummy_file(Some(4), &test_dir, "file");

        let size = compute_size(vec![file_path]).unwrap();
        assert_eq!(size, 4);
    }

    #[test]
    fn test_compute_multiple_files_size() {
        let test_dir = TempDir::create("utils", current_function!());
        let file_path_1 = write_dummy_file(Some(4), &test_dir, "file_1");
        let file_path_2 = write_dummy_file(Some(7), &test_dir, "file_2");

        let size = compute_size(vec![file_path_1, file_path_2]).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn test_compute_folder_size() {
        let test_dir = TempDir::create("utils", current_function!());
        write_dummy_file(Some(4), &test_dir, "file_1");
        write_dummy_file(Some(7), &test_dir, "file_2");

        let size = compute_size(vec![test_dir]).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn test_compute_multi_folders_size() {
        let test_dir = TempDir::create("utils", current_function!());

        let sub_dir_1 = test_dir.join("sub_dir_1");
        std::fs::create_dir(&sub_dir_1).unwrap();
        write_dummy_file(Some(4), &sub_dir_1, "file_1");

        let sub_dir_2 = test_dir.join("sub_dir_2");
        std::fs::create_dir(&sub_dir_2).unwrap();
        write_dummy_file(Some(7), &sub_dir_2, "file_2");

        let sub_dir_3 = test_dir.join("sub_dir_3");
        std::fs::create_dir(&sub_dir_3).unwrap();
        write_dummy_file(Some(3), &sub_dir_3, "file_3");

        let size = compute_size(vec![sub_dir_1, sub_dir_2]).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn test_compute_sub_folders_size() {
        let test_dir = TempDir::create("utils", current_function!());

        let sub_dir_1 = test_dir.join("sub_dir_1");
        std::fs::create_dir(&sub_dir_1).unwrap();
        write_dummy_file(Some(4), &sub_dir_1, "file_1");

        let sub_dir_2 = sub_dir_1.join("sub_dir_2");
        std::fs::create_dir(&sub_dir_2).unwrap();
        write_dummy_file(Some(7), &sub_dir_2, "file_2");

        let size = compute_size(vec![sub_dir_1]).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn test_compute_size_count_a_file_only_once() {
        let test_dir = TempDir::create("utils", current_function!());
        let file_path_1 = write_dummy_file(Some(4), &test_dir, "file_1");

        let size =
            compute_size(vec![file_path_1.clone(), file_path_1.clone(), file_path_1]).unwrap();
        assert_eq!(size, 4);
    }

    #[test]
    fn test_compute_size_count_a_file_only_once_when_it_s_part_of_a_computed_folder() {
        let test_dir = TempDir::create("utils", current_function!());
        let file_path_1 = write_dummy_file(Some(4), &test_dir, "file_1");

        let size = compute_size(vec![test_dir.clone(), file_path_1.clone()]).unwrap();
        assert_eq!(size, 4);

        let size = compute_size(vec![file_path_1, test_dir]).unwrap();
        assert_eq!(size, 4);
    }

    #[test]
    fn test_compute_file_with_file_name_starting_with_a_folder_name() {
        let test_dir = TempDir::create("utils", current_function!());

        let sub_dir_1 = test_dir.join("sub_dir_1");
        std::fs::create_dir(&sub_dir_1).unwrap();
        write_dummy_file(Some(3), &sub_dir_1, "file_1");

        let file_path_2 = write_dummy_file(Some(4), &test_dir, "sub_dir_1_file_2");
        assert!(file_path_2.to_str().unwrap().starts_with(sub_dir_1.to_str().unwrap()));

        let size = compute_size(vec![sub_dir_1.clone(), file_path_2.clone()]).unwrap();
        assert_eq!(size, 7);

        let size = compute_size(vec![file_path_2, sub_dir_1]).unwrap();
        assert_eq!(size, 7);
    }

    #[test]
    fn test_compute_file_with_folder_name_starting_with_a_file_name() {
        let test_dir = TempDir::create("utils", current_function!());

        let file_path_2 = write_dummy_file(Some(4), &test_dir, "file_2");

        let sub_dir_1 = test_dir.join("file_2_sub_dir_1");
        std::fs::create_dir(&sub_dir_1).unwrap();
        write_dummy_file(Some(3), &sub_dir_1, "file_1");

        assert!(sub_dir_1.to_str().unwrap().starts_with(file_path_2.to_str().unwrap()));

        let size = compute_size(vec![sub_dir_1.clone(), file_path_2.clone()]).unwrap();
        assert_eq!(size, 7);

        let size = compute_size(vec![file_path_2, sub_dir_1]).unwrap();
        assert_eq!(size, 7);
    }
}
