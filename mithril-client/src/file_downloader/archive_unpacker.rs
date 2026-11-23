//! Unpacking of tar archives coming from untrusted locations.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    cell::Cell,
    fs, io,
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use anyhow::Context;
use tar::{Archive, EntryType};
use thiserror::Error;

use mithril_common::StdResult;

/// Reason why an archive entry is rejected when unpacking.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveEntryRejection {
    /// The entry is neither a regular file nor a directory.
    #[error("Rejected archive entry of unexpected type '{0:?}'")]
    UnexpectedEntryType(EntryType),

    /// The entry path is absolute or has a parent-directory (`..`) component.
    #[error("Rejected archive entry with an unsafe path {0:?}")]
    UnsafePath(PathBuf),

    /// The file entry path has no file name.
    #[error("Rejected archive entry {0:?}: it has no file name")]
    MissingFileName(PathBuf),

    /// The file entry could not be placed inside the destination directory.
    #[error("Rejected archive entry {0:?}: it could not be placed inside the destination")]
    OutsideDestination(PathBuf),

    /// An existing entry on the directory entry path is not a directory.
    #[error(
        "Rejected archive directory entry {0:?}: an existing entry on its path is not a directory"
    )]
    DirectoryPathThroughNonDirectory(PathBuf),

    /// The headers read before the entry, extension headers included, exceed this size in bytes.
    #[error("Rejected archive entry: its headers exceed {0} bytes")]
    OversizedHeaders(u64),
}

/// Error raised when an archive cannot be unpacked, before any of its entries is read.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveUnpackError {
    /// The destination directory does not exist or is not a directory.
    #[error("Destination directory {0:?} does not exist or is not a directory")]
    DestinationIsNotADirectory(PathBuf),
}

/// Permissions given to the files unpacked from an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnpackedFilePermissions {
    /// Every file gets the permission bits of this mode whatever its archived mode, the setuid,
    /// setgid and sticky bits are never set (Unix only).
    Fixed(u32),

    /// Every file keeps its archived mode without the bits of this mask (Unix only).
    Masked(u32),
}

/// Unpacker of tar archives that accepts only regular files and directories whose path stays
/// inside the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarArchiveUnpacker {
    file_permissions: UnpackedFilePermissions,
}

impl TarArchiveUnpacker {
    /// Maximum size in bytes of the headers read before an archive entry, its GNU long name,
    /// GNU long link and PAX extension headers included.
    pub const MAX_ENTRY_HEADERS_SIZE: u64 = 1024 * 1024;

    /// Create an unpacker that gives the provided permissions to the unpacked files.
    pub const fn new(file_permissions: UnpackedFilePermissions) -> Self {
        Self { file_permissions }
    }

    /// Unpack an uncompressed tar stream entry by entry into the destination directory, which
    /// must exist, else an [ArchiveUnpackError] error is returned.
    ///
    /// Only regular files and directories whose path stays inside the destination are accepted.
    /// Any other entry type (symbolic or hard link, FIFO, device node) and any entry with an
    /// absolute or parent-directory (`..`) path is rejected with an [ArchiveEntryRejection]
    /// error, so an archive cannot place a link or climb out of the destination directory.
    /// The headers read before an entry are limited to [Self::MAX_ENTRY_HEADERS_SIZE] bytes.
    pub fn unpack<R: io::Read>(&self, tar_stream: R, unpack_dir: &Path) -> StdResult<()> {
        if !unpack_dir.is_dir() {
            return Err(
                ArchiveUnpackError::DestinationIsNotADirectory(unpack_dir.to_path_buf()).into(),
            );
        }

        let headers_budget = Rc::new(EntryHeadersBudget::default());
        let mut archive = Archive::new(HeadersLimitedReader {
            tar_stream,
            headers_budget: headers_budget.clone(),
        });
        let mut entries = archive
            .entries()
            .with_context(|| "Could not read the archive entries")?;
        loop {
            headers_budget.start(Self::MAX_ENTRY_HEADERS_SIZE);
            let next_entry = entries.next();
            headers_budget.stop();
            let Some(entry) = next_entry else {
                break;
            };
            let mut entry = entry.map_err(|error| {
                if headers_budget.is_exhausted() {
                    ArchiveEntryRejection::OversizedHeaders(Self::MAX_ENTRY_HEADERS_SIZE).into()
                } else {
                    anyhow::Error::new(error).context("Could not read an archive entry")
                }
            })?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_pax_global_extensions() {
                continue;
            }
            let is_regular_file = entry_type.is_file() || entry_type.is_contiguous();
            if !(is_regular_file || entry_type.is_dir()) {
                return Err(ArchiveEntryRejection::UnexpectedEntryType(entry_type).into());
            }

            let path = entry
                .path()
                .with_context(|| "Could not read an archive entry path")?
                .into_owned();
            if path.components().any(|component| {
                matches!(
                    component,
                    Component::Prefix(_) | Component::RootDir | Component::ParentDir
                )
            }) {
                return Err(ArchiveEntryRejection::UnsafePath(path).into());
            }

            if entry_type.is_dir() || entry.path_bytes().ends_with(b"/") {
                Self::create_directory_entry(unpack_dir, &path)?;
                continue;
            }

            if !path
                .components()
                .any(|component| matches!(component, Component::Normal(_)))
            {
                return Err(ArchiveEntryRejection::MissingFileName(path).into());
            }

            entry.set_mask(match self.file_permissions {
                UnpackedFilePermissions::Masked(mask) => mask,
                UnpackedFilePermissions::Fixed(mode) => !mode,
            });
            if !entry
                .unpack_in(unpack_dir)
                .with_context(|| "Could not unpack an archive entry")?
            {
                return Err(ArchiveEntryRejection::OutsideDestination(path).into());
            }
            #[cfg(unix)]
            if let UnpackedFilePermissions::Fixed(mode) = self.file_permissions {
                let file_path = unpack_dir.join(&path);
                fs::set_permissions(&file_path, fs::Permissions::from_mode(mode & 0o777))
                    .with_context(|| format!("Could not set the permissions of {file_path:?}"))?;
            }
        }

        Ok(())
    }

    /// Create the directory of an archive entry without applying its archived mode, refusing to go
    /// through an existing entry that is not a directory.
    fn create_directory_entry(unpack_dir: &Path, relative_path: &Path) -> StdResult<()> {
        let mut current = unpack_dir.to_path_buf();
        for component in relative_path.components() {
            match component {
                Component::CurDir => continue,
                Component::Normal(name) => current.push(name),
                _ => {
                    return Err(
                        ArchiveEntryRejection::UnsafePath(relative_path.to_path_buf()).into(),
                    );
                }
            }
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(ArchiveEntryRejection::DirectoryPathThroughNonDirectory(
                        relative_path.to_path_buf(),
                    )
                    .into());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .with_context(|| format!("Could not create directory {current:?}"))?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("Could not read metadata of {current:?}"));
                }
            }
        }

        Ok(())
    }
}

/// Bytes left to read for the headers of the next archive entry.
///
/// The `tar` crate reads the extension headers of an entry in memory while it looks for that
/// entry, so the bytes read between two entries are limited, the content of an entry is not.
#[derive(Debug, Default)]
struct EntryHeadersBudget {
    remaining_bytes: Cell<Option<u64>>,
    exhausted: Cell<bool>,
}

impl EntryHeadersBudget {
    /// Limit the bytes read from now on to the given size, until [Self::stop] is called.
    fn start(&self, max_bytes: u64) {
        self.remaining_bytes.set(Some(max_bytes));
    }

    /// Stop limiting the bytes read.
    fn stop(&self) {
        self.remaining_bytes.set(None);
    }

    /// Account for bytes read, failing when they exceed the remaining budget.
    fn consume(&self, read_bytes: u64) -> io::Result<()> {
        if let Some(remaining_bytes) = self.remaining_bytes.get() {
            if read_bytes > remaining_bytes {
                self.exhausted.set(true);
                return Err(io::Error::other(
                    "the archive entry headers exceed their maximum size",
                ));
            }
            self.remaining_bytes.set(Some(remaining_bytes - read_bytes));
        }

        Ok(())
    }

    /// Tell if bytes were read beyond the budget.
    fn is_exhausted(&self) -> bool {
        self.exhausted.get()
    }
}

/// Reader of a tar stream that accounts every byte read in an [EntryHeadersBudget].
struct HeadersLimitedReader<R> {
    tar_stream: R,
    headers_budget: Rc<EntryHeadersBudget>,
}

impl<R: io::Read> io::Read for HeadersLimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read_bytes = self.tar_stream.read(buffer)?;
        self.headers_budget.consume(read_bytes as u64)?;

        Ok(read_bytes)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use tar::{Builder, Header};

    use mithril_common::temp_dir_create;

    use super::*;

    type ArchiveEntry = (Header, &'static [u8]);

    const CONTENT: &[u8] = b"content";

    fn entry(
        raw_name: &[u8],
        entry_type: EntryType,
        content: &'static [u8],
        mode: u32,
    ) -> ArchiveEntry {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(content.len() as u64);
        header.set_mode(mode);
        header.as_gnu_mut().unwrap().name[..raw_name.len()].copy_from_slice(raw_name);
        header.set_cksum();
        (header, content)
    }

    fn file_entry(raw_name: &[u8], mode: u32) -> ArchiveEntry {
        entry(raw_name, EntryType::Regular, CONTENT, mode)
    }

    fn directory_entry(raw_name: &[u8], mode: u32) -> ArchiveEntry {
        entry(raw_name, EntryType::Directory, &[], mode)
    }

    fn link_entry(raw_name: &[u8], entry_type: EntryType, target: &str) -> ArchiveEntry {
        let (mut header, content) = entry(raw_name, entry_type, &[], 0o777);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        (header, content)
    }

    fn sparse_entry(raw_name: &[u8]) -> ArchiveEntry {
        let (mut header, content) = entry(raw_name, EntryType::GNUSparse, CONTENT, 0o644);
        let gnu_header = header.as_gnu_mut().unwrap();
        gnu_header.set_real_size(content.len() as u64);
        gnu_header.sparse[0].set_offset(0);
        gnu_header.sparse[0].set_length(content.len() as u64);
        header.set_cksum();
        (header, content)
    }

    fn unpack(
        file_permissions: UnpackedFilePermissions,
        entries: &[ArchiveEntry],
        unpack_dir: &Path,
    ) -> StdResult<()> {
        let mut builder = Builder::new(Vec::new());
        for (header, content) in entries {
            builder.append(header, *content).unwrap();
        }
        let archive_bytes = builder.into_inner().unwrap();

        TarArchiveUnpacker::new(file_permissions).unpack(archive_bytes.as_slice(), unpack_dir)
    }

    fn unpack_database_files(entries: &[ArchiveEntry], unpack_dir: &Path) -> StdResult<()> {
        unpack(UnpackedFilePermissions::Fixed(0o644), entries, unpack_dir)
    }

    fn entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    const OVERSIZED_HEADER_PAYLOAD_SIZE: usize = 4 * 1024 * 1024;

    struct CountingReader {
        bytes: io::Cursor<Vec<u8>>,
        read_bytes: usize,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes: io::Cursor::new(bytes),
                read_bytes: 0,
            }
        }
    }

    impl io::Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read_bytes = self.bytes.read(buffer)?;
            self.read_bytes += read_bytes;
            Ok(read_bytes)
        }
    }

    fn archive_with_an_oversized_header(header_type: EntryType) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(header_type);
        header.set_size(OVERSIZED_HEADER_PAYLOAD_SIZE as u64);
        header.as_gnu_mut().unwrap().name[..13].copy_from_slice(b"././@LongLink");
        header.set_cksum();
        builder
            .append(
                &header,
                vec![b'a'; OVERSIZED_HEADER_PAYLOAD_SIZE].as_slice(),
            )
            .unwrap();
        let (file_header, file_content) = file_entry(b"00001.chunk", 0o644);
        builder.append(&file_header, file_content).unwrap();

        builder.into_inner().unwrap()
    }

    #[cfg(unix)]
    fn unpacked_mode(file_path: &Path) -> u32 {
        fs::metadata(file_path).unwrap().permissions().mode() & 0o7777
    }

    fn assert_rejected_without_creating_anything(
        expected_rejection: ArchiveEntryRejection,
        unpacked: StdResult<()>,
        unpack_dir: &Path,
    ) {
        let error = unpacked.expect_err("the entry must be rejected");

        assert_eq!(
            Some(&expected_rejection),
            error.downcast_ref::<ArchiveEntryRejection>()
        );
        assert!(
            entry_names(unpack_dir).is_empty(),
            "a rejected entry must create nothing"
        );
    }

    #[test]
    fn rejects_a_symlink_entry_and_creates_nothing() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(
            &[link_entry(b"link", EntryType::Symlink, "/outside/target")],
            &unpack_dir,
        );

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnexpectedEntryType(EntryType::Symlink),
            unpacked,
            &unpack_dir,
        );
    }

    #[test]
    fn rejects_a_hard_link_entry_and_creates_nothing() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(
            &[link_entry(b"hardlink", EntryType::Link, "00001.chunk")],
            &unpack_dir,
        );

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnexpectedEntryType(EntryType::Link),
            unpacked,
            &unpack_dir,
        );
    }

    #[test]
    fn rejects_a_gnu_sparse_entry_and_creates_nothing() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(&[sparse_entry(b"sparse.bin")], &unpack_dir);

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnexpectedEntryType(EntryType::GNUSparse),
            unpacked,
            &unpack_dir,
        );
    }

    #[test]
    fn rejects_a_regular_entry_with_an_empty_path_and_creates_nothing() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(&[file_entry(b".", 0o644)], &unpack_dir);

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::MissingFileName(PathBuf::from(".")),
            unpacked,
            &unpack_dir,
        );
    }

    #[test]
    fn rejects_an_entry_with_a_parent_directory_path_and_creates_nothing() {
        let sandbox = temp_dir_create!();
        let unpack_dir = sandbox.join("unpack");
        fs::create_dir(&unpack_dir).unwrap();

        let unpacked = unpack_database_files(&[file_entry(b"../escaped", 0o644)], &unpack_dir);

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnsafePath(PathBuf::from("../escaped")),
            unpacked,
            &unpack_dir,
        );
        assert!(!sandbox.join("escaped").exists());
    }

    #[test]
    fn rejects_an_entry_with_an_absolute_path_and_creates_nothing() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(&[file_entry(b"/tmp/escaped", 0o644)], &unpack_dir);

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnsafePath(PathBuf::from("/tmp/escaped")),
            unpacked,
            &unpack_dir,
        );
    }

    #[test]
    fn create_directory_entry_rejects_a_rooted_path() {
        let unpack_dir = temp_dir_create!();

        let created = TarArchiveUnpacker::create_directory_entry(&unpack_dir, Path::new("/evil"));

        assert_rejected_without_creating_anything(
            ArchiveEntryRejection::UnsafePath(PathBuf::from("/evil")),
            created,
            &unpack_dir,
        );
    }

    #[test]
    fn rejects_a_directory_entry_going_through_an_existing_file_and_keeps_the_file() {
        let unpack_dir = temp_dir_create!();

        let error = unpack_database_files(
            &[file_entry(b"a", 0o644), directory_entry(b"a/b/", 0o755)],
            &unpack_dir,
        )
        .expect_err("a directory entry going through a file must be rejected");

        assert_eq!(
            Some(&ArchiveEntryRejection::DirectoryPathThroughNonDirectory(
                PathBuf::from("a/b/")
            )),
            error.downcast_ref::<ArchiveEntryRejection>()
        );
        assert_eq!(vec!["a".to_string()], entry_names(&unpack_dir));
        assert_eq!(fs::read(unpack_dir.join("a")).unwrap(), CONTENT);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_directory_entry_going_through_an_existing_symlink() {
        let sandbox = temp_dir_create!();
        let unpack_dir = sandbox.join("unpack");
        let outside_dir = sandbox.join("outside");
        fs::create_dir(&unpack_dir).unwrap();
        fs::create_dir(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, unpack_dir.join("a")).unwrap();

        let error = unpack_database_files(&[directory_entry(b"a/b/", 0o755)], &unpack_dir)
            .expect_err("a directory entry going through a symlink must be rejected");

        assert_eq!(
            Some(&ArchiveEntryRejection::DirectoryPathThroughNonDirectory(
                PathBuf::from("a/b/")
            )),
            error.downcast_ref::<ArchiveEntryRejection>()
        );
        assert!(entry_names(&outside_dir).is_empty());
    }

    #[test]
    fn fails_when_the_destination_directory_does_not_exist() {
        let unpack_dir = temp_dir_create!().join("missing");

        let error = unpack_database_files(&[file_entry(b"00001.chunk", 0o644)], &unpack_dir)
            .expect_err("a missing destination directory must be rejected");

        assert_eq!(
            Some(&ArchiveUnpackError::DestinationIsNotADirectory(
                unpack_dir.clone()
            )),
            error.downcast_ref::<ArchiveUnpackError>()
        );
        assert!(!unpack_dir.exists());
    }

    #[test]
    fn escapes_control_characters_of_a_rejected_entry_path_in_the_error() {
        let unpack_dir = temp_dir_create!();

        let error = unpack_database_files(&[file_entry(b"../x\x1b[31m", 0o644)], &unpack_dir)
            .expect_err("a `..` path must be rejected");

        assert!(
            !error.to_string().contains('\x1b'),
            "the error must not carry raw control characters: {error:?}"
        );
    }

    #[test]
    fn unpacks_a_regular_file_entry() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(&[file_entry(b"00001.chunk", 0o644)], &unpack_dir)
            .expect("a regular file entry unpacks");

        assert_eq!(fs::read(unpack_dir.join("00001.chunk")).unwrap(), CONTENT);
    }

    #[test]
    fn unpacks_a_contiguous_file_entry() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(
            &[entry(b"contiguous.txt", EntryType::Continuous, CONTENT, 0o644)],
            &unpack_dir,
        )
        .expect("a contiguous entry is a regular file");

        assert_eq!(
            fs::read(unpack_dir.join("contiguous.txt")).unwrap(),
            CONTENT
        );
    }

    #[test]
    fn unpacks_a_directory_entry() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(&[directory_entry(b"immutable/", 0o755)], &unpack_dir)
            .expect("a directory entry unpacks");

        assert!(unpack_dir.join("immutable").is_dir());
    }

    #[test]
    fn skips_a_pax_global_header_entry() {
        let unpack_dir = temp_dir_create!();
        let pax_record = b"52 comment=0123456789abcdef0123456789abcdef01234567\n";

        unpack_database_files(
            &[
                entry(
                    b"pax_global_header",
                    EntryType::XGlobalHeader,
                    pax_record,
                    0o644,
                ),
                file_entry(b"root.txt", 0o644),
            ],
            &unpack_dir,
        )
        .expect("a pax global header carries no payload and must be skipped");

        assert_eq!(vec!["root.txt".to_string()], entry_names(&unpack_dir));
    }

    #[test]
    fn unpacks_a_file_entry_with_a_gnu_long_name() {
        let unpack_dir = temp_dir_create!();
        let long_name = "a".repeat(200);
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(CONTENT.len() as u64);
        builder.append_data(&mut header, &long_name, CONTENT).unwrap();
        let archive_bytes = builder.into_inner().unwrap();

        TarArchiveUnpacker::new(UnpackedFilePermissions::Fixed(0o644))
            .unpack(archive_bytes.as_slice(), &unpack_dir)
            .expect("a GNU long name within the headers size limit must be accepted");

        assert_eq!(vec![long_name], entry_names(&unpack_dir));
    }

    #[test]
    fn unpacks_a_file_entry_larger_than_the_headers_size_limit() {
        let unpack_dir = temp_dir_create!();
        let content = vec![b'a'; 2 * TarArchiveUnpacker::MAX_ENTRY_HEADERS_SIZE as usize];
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(content.len() as u64);
        builder
            .append_data(&mut header, "00001.chunk", content.as_slice())
            .unwrap();
        let archive_bytes = builder.into_inner().unwrap();

        TarArchiveUnpacker::new(UnpackedFilePermissions::Fixed(0o644))
            .unpack(archive_bytes.as_slice(), &unpack_dir)
            .expect("the content of an entry must not be limited by the headers size limit");

        assert_eq!(
            content.len() as u64,
            fs::metadata(unpack_dir.join("00001.chunk")).unwrap().len()
        );
    }

    #[test]
    fn stops_reading_an_oversized_gnu_long_name_header_before_its_end() {
        let unpack_dir = temp_dir_create!();
        let mut archive_reader =
            CountingReader::new(archive_with_an_oversized_header(EntryType::GNULongName));

        let error = TarArchiveUnpacker::new(UnpackedFilePermissions::Fixed(0o644))
            .unpack(&mut archive_reader, &unpack_dir)
            .expect_err("an oversized GNU long name header must be rejected");

        assert_eq!(
            Some(&ArchiveEntryRejection::OversizedHeaders(
                TarArchiveUnpacker::MAX_ENTRY_HEADERS_SIZE
            )),
            error.downcast_ref::<ArchiveEntryRejection>()
        );

        assert!(
            archive_reader.read_bytes < OVERSIZED_HEADER_PAYLOAD_SIZE / 2,
            "the unpacker must stop reading the header early, read {} bytes",
            archive_reader.read_bytes
        );
    }

    #[test]
    fn stops_reading_an_oversized_pax_extension_header_before_its_end() {
        let unpack_dir = temp_dir_create!();
        let mut archive_reader =
            CountingReader::new(archive_with_an_oversized_header(EntryType::XHeader));

        let error = TarArchiveUnpacker::new(UnpackedFilePermissions::Fixed(0o644))
            .unpack(&mut archive_reader, &unpack_dir)
            .expect_err("an oversized PAX extension header must be rejected");

        assert_eq!(
            Some(&ArchiveEntryRejection::OversizedHeaders(
                TarArchiveUnpacker::MAX_ENTRY_HEADERS_SIZE
            )),
            error.downcast_ref::<ArchiveEntryRejection>()
        );

        assert!(
            archive_reader.read_bytes < OVERSIZED_HEADER_PAYLOAD_SIZE / 2,
            "the unpacker must stop reading the header early, read {} bytes",
            archive_reader.read_bytes
        );
    }

    #[test]
    fn unpacks_a_file_under_a_directory_entry_without_owner_write_permission() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(
            &[
                directory_entry(b"immutable/", 0o555),
                file_entry(b"immutable/00001.chunk", 0o644),
            ],
            &unpack_dir,
        )
        .expect("a read-only directory entry must not block its own files");

        assert_eq!(
            fs::read(unpack_dir.join("immutable").join("00001.chunk")).unwrap(),
            CONTENT
        );
    }

    #[test]
    fn treats_a_file_entry_with_a_trailing_slash_as_a_directory_without_its_mode() {
        let unpack_dir = temp_dir_create!();

        let unpacked = unpack_database_files(
            &[
                entry(b"immutable/", EntryType::Regular, &[], 0o000),
                file_entry(b"immutable/00001.chunk", 0o644),
            ],
            &unpack_dir,
        );
        #[cfg(unix)]
        fs::set_permissions(
            unpack_dir.join("immutable"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        unpacked
            .expect("a file entry with a trailing slash is a directory and must not keep its mode");

        assert_eq!(
            fs::read(unpack_dir.join("immutable").join("00001.chunk")).unwrap(),
            CONTENT
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaces_the_archived_permissions_of_an_unpacked_regular_file() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(&[file_entry(b"00001.chunk", 0o777)], &unpack_dir).unwrap();

        assert_eq!(0o644, unpacked_mode(&unpack_dir.join("00001.chunk")));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_the_archived_permissions_of_a_regular_file_archived_without_any() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(&[file_entry(b"00001.chunk", 0o000)], &unpack_dir).unwrap();

        assert_eq!(
            0o644,
            unpacked_mode(&unpack_dir.join("00001.chunk")),
            "an archive must not make an unpacked file unreadable by its owner"
        );
    }

    #[cfg(unix)]
    #[test]
    fn drops_the_setuid_setgid_and_sticky_bits_of_an_unpacked_regular_file() {
        let unpack_dir = temp_dir_create!();

        unpack_database_files(&[file_entry(b"00001.chunk", 0o7777)], &unpack_dir).unwrap();

        assert_eq!(0o644, unpacked_mode(&unpack_dir.join("00001.chunk")));
    }

    #[cfg(unix)]
    #[test]
    fn fixed_permissions_never_set_the_setuid_setgid_and_sticky_bits() {
        let unpack_dir = temp_dir_create!();

        unpack(
            UnpackedFilePermissions::Fixed(0o7755),
            &[file_entry(b"tool", 0o644)],
            &unpack_dir,
        )
        .unwrap();

        assert_eq!(0o755, unpacked_mode(&unpack_dir.join("tool")));
    }

    #[cfg(unix)]
    #[test]
    fn masked_permissions_keep_the_archived_mode_without_the_masked_bits() {
        let unpack_dir = temp_dir_create!();

        unpack(
            UnpackedFilePermissions::Masked(0o022),
            &[file_entry(b"tool", 0o777)],
            &unpack_dir,
        )
        .unwrap();

        assert_eq!(0o755, unpacked_mode(&unpack_dir.join("tool")));
    }
}
