use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use mithril_common::entities::CompressionAlgorithm;
use mithril_common::temp_dir_create;
use mithril_file_archiver::{ArchiveParameters, FileArchiver};

/// Assert that two files have exactly the same bytes.
///
/// SHA-256 hashes and file sizes are reported when they differ.
#[track_caller]
pub fn assert_files_are_byte_identical<E: AsRef<Path>, A: AsRef<Path>>(expected: E, actual: A) {
    let (expected_path, actual_path) = (expected.as_ref(), actual.as_ref());
    let expected_bytes = std::fs::read(expected_path).unwrap_or_else(|error| {
        panic!(
            "Could not read expected file '{}': {error}",
            expected_path.display()
        )
    });
    let actual_bytes = std::fs::read(actual_path).unwrap_or_else(|error| {
        panic!(
            "Could not read actual file '{}': {error}",
            actual_path.display()
        )
    });

    if expected_bytes != actual_bytes {
        let expected_hash = hex::encode(Sha256::digest(&expected_bytes));
        let actual_hash = hex::encode(Sha256::digest(&actual_bytes));

        panic!(
            "Files are not byte-identical:\n\
                 expected: '{}' ({} bytes, SHA-256: {})\n\
                 actual:   '{}' ({} bytes, SHA-256: {})",
            expected_path.display(),
            expected_bytes.len(),
            expected_hash,
            actual_path.display(),
            actual_bytes.len(),
            actual_hash,
        );
    }
}

/// **IMPORTANT** Default zstandard compression parameters are used.
pub fn file_archiver(work_dir: &Path) -> FileArchiver {
    FileArchiver::new_with_default_parameters(
        work_dir.join("verification"),
        slog::Logger::root(slog::Discard, slog::o!()),
    )
}

pub fn create_dir<P: AsRef<Path>>(base_dir: &Path, dir_name: P) -> PathBuf {
    let dir_path = base_dir.join(dir_name);
    std::fs::create_dir(&dir_path).unwrap();
    dir_path
}

pub fn create_file(root_dir: &Path, file_name: &str, size: Option<u64>) -> PathBuf {
    let path = root_dir.join(file_name);
    let mut file = File::create(&path).unwrap();

    write!(file, "This is a test file named '{file_name}'").unwrap();
    writeln!(file).unwrap();

    if let Some(file_size) = size {
        file.set_len(file_size).unwrap();
    }

    path
}

pub fn alter_file<F: FnOnce(&File)>(path: &Path, alter_fn: F) {
    let file = File::options().write(true).open(path).unwrap();
    alter_fn(&file);
}

pub fn archive_parameters(filename: &str, target_dir: &Path) -> ArchiveParameters {
    ArchiveParameters {
        archive_name_without_extension: filename.to_string(),
        target_directory: target_dir.to_path_buf(),
        compression_algorithm: CompressionAlgorithm::Zstandard,
    }
}

pub fn compute_file_sha256(path: &Path) -> String {
    let mut hasher = Sha256::new();

    if path.is_file() {
        hash_file(path, &mut hasher);
    } else {
        panic!("Path is not a file: {:?}", path.display());
    }

    hex::encode(hasher.finalize())
}

fn hash_file(path: &Path, hasher: &mut Sha256) {
    let mut file = File::open(path).unwrap();
    let mut buffer = [0; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }
}

#[test]
fn assert_files_are_byte_identical_succeed_with_identical_files() {
    let test_dir = temp_dir_create!();
    let content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    let reference_file_path = test_dir.join("reference_file");
    let mut reference_file = File::create_new(&reference_file_path).unwrap();
    reference_file.write_all(&content).unwrap();

    let identical_file_path = test_dir.join("altered_file");
    std::fs::copy(&reference_file_path, &identical_file_path).unwrap();

    assert_files_are_byte_identical(&reference_file_path, &identical_file_path);
}

#[test]
#[should_panic(expected = "Files are not byte-identical")]
fn assert_files_are_byte_identical_fails_if_one_byte_changes() {
    let test_dir = temp_dir_create!();
    let content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let altered_content = {
        let mut altered_content = content.clone();
        altered_content[0] = !altered_content[0];
        altered_content
    };

    let reference_file_path = test_dir.join("reference_file");
    let mut reference_file = File::create_new(&reference_file_path).unwrap();
    reference_file.write_all(&content).unwrap();

    let altered_file_path = test_dir.join("altered_file");
    let mut altered_file = File::create_new(&altered_file_path).unwrap();
    altered_file.write_all(&altered_content).unwrap();

    assert_files_are_byte_identical(&reference_file_path, &altered_file_path);
}
