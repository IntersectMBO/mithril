# Mithril-file-archiver

**This is a work in progress** 🛠

An API to generate tar archives from files, directories, or serializable data (leveraging serde).

## Byte stability guarantees

Given identical archive entry paths, contents, and executable status, `FileArchiver` produces byte-identical `.tar.zst`
archives across runs and supported host systems, subject to the Windows limitation described below.

Archive bytes are unaffected by:

- The source base directory
- File creation and modification times
- File permissions other than the owner-execute bit on Unix
- The order in which entries are supplied
- Equivalent path spellings, such as `foo/` and `foo`, or `./foo.txt` and `foo.txt`
- The order in which non-overlapping appenders are chained

Entries are normalized and sorted by their archive paths. When chained appenders provide the same archive path, the
rightmost appender takes precedence.

This guarantee requires the following archive-format invariants to remain unchanged:

- Archive entry paths and contents
- The versions and behavior of the TAR and Zstandard libraries
- The Zstandard compression parameters, including the compression level and number of workers
- TAR header generation and metadata normalization
- JSON serialization output when using `AppenderData::from_json`

Changing one of these invariants can change the resulting bytes and must be treated as an intentional archive-format
change.
Such a change requires bumping the archive-format version and updating the golden hashes that pin the expected output.

### Windows limitation

Windows does not expose a Unix-style owner-execute bit. Consequently, the TAR library assigns mode `0644` to all regular
files on Windows, whereas on Unix it assigns `0755` to regular files whose owner-execute bit is set and `0644` to other
regular files.

Therefore, an archive containing an owner-executable regular file on Unix is not guaranteed to be byte-identical to an
archive created from the equivalent files on Windows.
Archives containing no such files are unaffected by this limitation.
