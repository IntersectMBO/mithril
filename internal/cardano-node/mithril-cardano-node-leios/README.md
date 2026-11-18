# Mithril-cardano-node-leios [![CI workflow](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml/badge.svg)](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/IntersectMBO/mithril/blob/main/LICENSE) [![Discord](https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square)](https://discord.gg/5kaErDKDRq)

**This is a work in progress** :hammer_and_wrench:

This crate provides the mechanisms that allow Mithril nodes to snapshot the Leios database of a Cardano node:

- reading the blocks of the immutable files that certify an endorser block, with the announcement of their predecessor
- taking a consistent copy of the `leios.imm.db` SQLite database of a running node
- checking that the copy holds the closure of every certified endorser block, through an adapter of the node database layout

## Usage

```rust
use mithril_cardano_node_leios::LeiosImmutableDatabaseSnapshotter;

let snapshotter = LeiosImmutableDatabaseSnapshotter::new(node_db_directory, semver::Version::new(11, 2, 0));

// Copies `leios.imm.db` into the target directory and checks the closures of the certifying blocks
// of the immutable files 0 to 41 of the node and of the copy of the immutable file 42
let snapshot_path = snapshotter.snapshot(&target_directory, 41, &copied_partial_immutable_directory)?;
```

## Adding a node database layout

When a node release changes the tables of `leios.imm.db`, add one file in `src/database/` implementing `LeiosImmutableDatabaseLayout` and map the first cardano-node version of that layout in `LeiosImmutableDatabaseLayoutProvider`.
