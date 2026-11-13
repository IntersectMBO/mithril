use std::{fs::File, path::Path};

use anyhow::Context;
use flate2::read::GzDecoder;

use mithril_client::MithrilResult;
use mithril_client::file_downloader::{TarArchiveUnpacker, UnpackedFilePermissions};

use super::ArchiveFormat;

#[derive(Debug, Eq, PartialEq)]
pub struct TarGzUnpacker;

impl TarGzUnpacker {
    /// Permission bits removed from every unpacked file: group and other write. The execute bits
    /// are kept since the archive is a distribution of binaries.
    const UNPACKED_FILE_MODE_MASK: u32 = 0o022;
}

impl ArchiveFormat for TarGzUnpacker {
    fn unpack(&self, archive_path: &Path, unpack_dir: &Path) -> MithrilResult<()> {
        let archive = File::open(archive_path)
            .with_context(|| format!("Could not open archive file '{}'", archive_path.display()))?;
        let gzip_decoder = GzDecoder::new(archive);
        TarArchiveUnpacker::new(UnpackedFilePermissions::Masked(
            Self::UNPACKED_FILE_MODE_MASK,
        ))
        .unpack(gzip_decoder, unpack_dir)
        .with_context(|| {
            format!(
                "Could not unpack '{}' with 'Gzip' to directory '{}'",
                archive_path.display(),
                unpack_dir.display()
            )
        })?;

        Ok(())
    }

    fn supports(&self, path: &Path) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("gz")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType, Header};

    use mithril_common::{assert_dir_eq, temp_dir_create};

    use super::*;

    fn entry_header(raw_name: &[u8], entry_type: EntryType, size: usize, mode: u32) -> Header {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(size as u64);
        header.set_mode(mode);
        header.as_gnu_mut().unwrap().name[..raw_name.len()].copy_from_slice(raw_name);
        header.set_cksum();
        header
    }

    fn write_archive(archive_path: &Path, entries: &[(Header, &[u8])]) {
        let encoder = GzEncoder::new(File::create(archive_path).unwrap(), Compression::default());
        let mut tar_builder = Builder::new(encoder);
        for (header, content) in entries {
            tar_builder.append(header, *content).unwrap();
        }
        tar_builder.finish().unwrap();
    }

    fn unpack_sandbox(temp_dir: &Path) -> (PathBuf, PathBuf) {
        let unpack_dir = temp_dir.join("unpack");
        fs::create_dir_all(&unpack_dir).unwrap();
        (temp_dir.join("archive.tar.gz"), unpack_dir)
    }

    #[test]
    fn unpack_tar_archive_extracts_all_files() {
        let temp_dir = temp_dir_create!();
        let archive_path = temp_dir.join("archive.tar.gz");

        {
            let tar_gz_file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(tar_gz_file, Compression::default());
            let mut tar_builder = Builder::new(encoder);

            let content = b"root content";
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "root.txt", &content[..])
                .unwrap();

            let content = b"nested content";
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "nested/dir/nested-file.txt", &content[..])
                .unwrap();

            tar_builder.finish().unwrap();
        }

        TarGzUnpacker.unpack(&archive_path, &temp_dir).unwrap();

        assert_dir_eq! {
            &temp_dir,
            "* nested/
            ** dir/
            *** nested-file.txt
            * archive.tar.gz
            * root.txt"
        };

        let root_file_content = fs::read_to_string(temp_dir.join("root.txt")).unwrap();
        assert_eq!(root_file_content, "root content");

        let nested_file_content =
            fs::read_to_string(temp_dir.join("nested/dir/nested-file.txt")).unwrap();
        assert_eq!(nested_file_content, "nested content");
    }

    #[test]
    fn unpack_rejects_a_symlink_entry_and_creates_nothing() {
        let temp_dir = temp_dir_create!();
        let archive_path = temp_dir.join("archive.tar.gz");
        let unpack_dir = temp_dir.join("unpack");
        fs::create_dir_all(&unpack_dir).unwrap();

        {
            let tar_gz_file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(tar_gz_file, Compression::default());
            let mut tar_builder = Builder::new(encoder);

            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            tar_builder
                .append_link(&mut header, "link", "/outside/target")
                .unwrap();

            tar_builder.finish().unwrap();
        }

        TarGzUnpacker
            .unpack(&archive_path, &unpack_dir)
            .expect_err("a symlink entry must be rejected");

        assert!(
            fs::symlink_metadata(unpack_dir.join("link")).is_err(),
            "no entry is created for the rejected symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unpack_keeps_the_execute_bits_of_a_regular_file_and_removes_group_and_other_write() {
        let temp_dir = temp_dir_create!();
        let (archive_path, unpack_dir) = unpack_sandbox(&temp_dir);
        let content = b"binary content";
        write_archive(
            &archive_path,
            &[(
                entry_header(b"tool", EntryType::Regular, content.len(), 0o777),
                content.as_slice(),
            )],
        );

        TarGzUnpacker.unpack(&archive_path, &unpack_dir).unwrap();

        let mode = fs::metadata(unpack_dir.join("tool")).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            0o755, mode,
            "an unpacked binary must stay executable, without group or other write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unpack_drops_the_setuid_setgid_and_sticky_bits_of_a_regular_file() {
        let temp_dir = temp_dir_create!();
        let (archive_path, unpack_dir) = unpack_sandbox(&temp_dir);
        let content = b"binary content";
        write_archive(
            &archive_path,
            &[(
                entry_header(b"tool", EntryType::Regular, content.len(), 0o7777),
                content.as_slice(),
            )],
        );

        TarGzUnpacker.unpack(&archive_path, &unpack_dir).unwrap();

        let mode = fs::metadata(unpack_dir.join("tool")).unwrap().permissions().mode() & 0o7777;
        assert_eq!(0o755, mode);
    }

    #[test]
    fn supported_file_extension() {
        assert!(TarGzUnpacker.supports(Path::new("archive.tar.gz")));
        assert!(TarGzUnpacker.supports(Path::new("archive.gz")));
        assert!(!TarGzUnpacker.supports(Path::new("archive.tar")));
        assert!(!TarGzUnpacker.supports(Path::new("archive.whatever")));
    }
}
