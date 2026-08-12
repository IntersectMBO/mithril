# Mithril-file-archiver

**This is a work in progress** 🛠

An API to generate tar archives from files, directories, or serializable data (leveraging serde).

Produced archives are byte stable across systems as long as the following invariants do not change:

- The version of the zstandard compression library
- The parameters of the zstandard compression
