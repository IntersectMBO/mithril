use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};

use mithril_client::MithrilResult;

use crate::utils::ArchiveUnpacker;

/// Kubo release archive, from which the Kubo binary is unpacked
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KuboArchive {
    path: PathBuf,
    binary_path_in_archive: &'static str,
}

impl KuboArchive {
    /// Constructs a new `KuboArchive`.
    pub fn new(path: PathBuf, binary_path_in_archive: &'static str) -> Self {
        Self {
            path,
            binary_path_in_archive,
        }
    }

    /// Path of the archive
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unpack the archive in `target_dir`, returning the path of the unpacked Kubo binary
    pub fn unpack_binary(&self, target_dir: &Path) -> MithrilResult<PathBuf> {
        ArchiveUnpacker::default()
            .unpack(&self.path, target_dir)
            .with_context(|| {
                format!(
                    "Could not unpack the Kubo archive '{}'",
                    self.path.display()
                )
            })?;
        let binary_path = target_dir.join(self.binary_path_in_archive);
        if !binary_path.is_file() {
            return Err(anyhow!(
                "No Kubo binary '{}' in the archive '{}'",
                self.binary_path_in_archive,
                self.path.display()
            ));
        }

        Ok(binary_path)
    }

    /// Kubo like tar.gz archive, written in `dir`, holding an executable `kubo/ipfs` binary with the
    /// given content
    #[cfg(test)]
    pub(super) fn fake(dir: &Path, binary_content: &[u8]) -> Self {
        use flate2::{Compression, write::GzEncoder};
        use tar::{Builder, Header};

        let archive_path = dir.join("kubo.tar.gz");
        let mut tar_builder = Builder::new(GzEncoder::new(
            std::fs::File::create(&archive_path).unwrap(),
            Compression::fast(),
        ));
        let mut header = Header::new_gnu();
        header.set_size(binary_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "kubo/ipfs", binary_content)
            .unwrap();
        tar_builder.into_inner().unwrap().finish().unwrap();

        Self::new(archive_path, "kubo/ipfs")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mithril_common::temp_dir_create;

    use super::*;

    const FAKE_BINARY_CONTENT: &[u8] = b"fake kubo binary";

    #[test]
    fn unpacks_the_binary_in_the_target_dir() {
        let test_dir = temp_dir_create!();
        let target_dir = test_dir.join("target");
        fs::create_dir(&target_dir).unwrap();

        let binary_path = KuboArchive::fake(&test_dir, FAKE_BINARY_CONTENT)
            .unpack_binary(&target_dir)
            .unwrap();

        assert_eq!(target_dir.join("kubo/ipfs"), binary_path);
        assert_eq!(FAKE_BINARY_CONTENT, fs::read(&binary_path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unpacked_binary_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let test_dir = temp_dir_create!();
        let target_dir = test_dir.join("target");
        fs::create_dir(&target_dir).unwrap();

        let binary_path = KuboArchive::fake(&test_dir, FAKE_BINARY_CONTENT)
            .unpack_binary(&target_dir)
            .unwrap();

        let mode = fs::metadata(binary_path).unwrap().permissions().mode();
        assert_eq!(
            0o100,
            mode & 0o100,
            "Binary should be executable, mode: {mode:o}"
        );
    }

    #[test]
    fn fails_when_the_binary_is_not_in_the_archive() {
        let test_dir = temp_dir_create!();
        let archive = KuboArchive::fake(&test_dir, FAKE_BINARY_CONTENT);

        KuboArchive::new(archive.path().to_path_buf(), "kubo/missing")
            .unpack_binary(&test_dir)
            .expect_err("Should fail when the binary is not in the archive");
    }

    #[test]
    fn fails_when_the_archive_can_not_be_unpacked() {
        let test_dir = temp_dir_create!();
        let archive_path = test_dir.join("kubo.tar.gz");
        fs::write(&archive_path, b"not an archive").unwrap();

        KuboArchive::new(archive_path, "kubo/ipfs")
            .unpack_binary(&test_dir)
            .expect_err("Should fail when the archive can not be unpacked");
    }
}
