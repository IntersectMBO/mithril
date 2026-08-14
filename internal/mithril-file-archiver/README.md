# Mithril-file-archiver

**This is a work in progress** 🛠

An API to generate tar archives from files, directories, or serializable data (leveraging serde).

## Byte stability guarantees

Given identical archive entry paths and contents, `FileArchiver` produces byte-identical `.tar.zst` archives across
runs and supported host systems.

Archive bytes are unaffected by:

- The source base directory
- File creation and modification times
- File permissions
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
