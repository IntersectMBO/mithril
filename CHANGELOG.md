# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

As a minor extension, we have adopted a slightly different versioning convention for the Mithril distributions (<https://mithril.network/doc/adr/3#decision>)

## Mithril Distribution [XXXX] - UNRELEASED

| Crate               | Version |
| ------------------- | ------- |
| mithril-aggregator  | `-`     |
| mithril-client      | `-`     |
| mithril-client-cli  | `-`     |
| mithril-client-wasm | `-`     |
| mithril-common      | `-`     |
| mithril-signer      | `-`     |
| mithril-stm         | `-`     |

## Mithril Distribution [2630.0] - 2026-08-03

- **REMOVED** support for `CardanoImmutableFilesFull` in Mithril signer and aggregator:
  - Use `CardanoDatabase` (also known as "cardano database v2") instead, which supports partial database restoration and
    verification of existing databases.
  - Signers no longer send signatures for this certificate type.
  - Aggregators no longer aggregate signatures for this certificate type.
  - Aggregators will discard signatures of this type received from older signers.

- Moved the repository to the `IntersectMBO` GitHub organization:
  - The genesis, era and ancillary verification key URLs of the `networks.json` file now target `IntersectMBO`.
  - The Docker images of the nodes are now published to the `ghcr.io/intersectmbo` namespace.
  - The legacy `input-output-hk` URLs and released images keep working. Refresh any pinned verification key URL or image reference at your next upgrade.

- DMQ node:
  - Implemented new message id format for the DMQ message to follow specification of the [CIP-0137](https://cips.cardano.org/cip/CIP-0137).
  - Added support for the DMQ node `0.7.0.0` stable version.
  - Promoted the DMQ node as stable (beta) on `release-mainnet` and `release-preprod` networks.
  - Added optional support for ledger peers declared with `SRV` records ([CIP-155](https://cips.cardano.org/cip/CIP-0155)).

- Gracefully handle unknown signed entity types across Mithril nodes for improved forward compatibility.

- Allow users to set the network genesis verification key when adding an aggregator in the Mithril Explorer.

- Added a new internal crate `mithril-merkle-tree` for the implementation of Merkle tree and merkelized map primitives used by Mithril nodes.

- Support for upcoming `Cardano node` `11.1` in the signer, aggregator and client.

- **UNSTABLE**:
  - Support for SNARK-friendly rigid protocol message openable in recursive circuit.
  - Support for SNARK-friendly genesis certificate primitives.
  - Support for dual-signature genesis certificate.
  - Support for ancillary prover and verifier data carried on certificates.
  - Support for stopping certificate chain verification early on full-chain certifying certificates.
  - Support for recursive (IVC) SNARK proofs for the certificate chain.

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.9.18`  |
| mithril-client      | `0.14.17` |
| mithril-client-cli  | `0.13.20` |
| mithril-client-wasm | `0.10.8`  |
| mithril-common      | `0.7.14`  |
| mithril-signer      | `1.1.6`   |
| mithril-stm         | `0.12.0`  |

## Mithril Distribution [2617.0] - 2026-04-29

- **STABLE**: the Mithril signer has reached its first stable version `1.0.0` and is now officially production-ready on the `release-mainnet` network.

- **REMOVED**: in Mithril client CLI and WASM:
  - The `cardano_db` function in the `Client` struct of the library and its WASM counterpart
  - The `--backend v1` flag of the `cardano-db` command in the CLI; use `--backend v2` instead.

- Support for `Cardano node` `11.0.1` in the signer and the aggregator.

- Support for `Cardano node` `10.6.2` in the signer and the aggregator.

- Support for `Cardano node` `10.7.1` in the signer, aggregator and client.

- Update `release-mainnet` network configuration to SNARK-friendly protocol parameters.

- Support for optional throttling of the Cardano transactions import in the signer and aggregator (enabled by default).

- Upgraded the release process to support release synchronization with the Cardano node releases.

- Implemented statically built Mithril nodes in CI:
  - **aggregator**, **signer**, **client**, and **relay** are statically built on both **GitHub** and **Hydra** CI pipelines using the `musl` target.
  - Feature updates:
    - `rustls` is now the default TLS feature for all nodes.
    - `num-integer-backend` is now the default feature in the `mithril-stm` library.
  - Memory allocator updates:
    - **Jemallocator** is now a default dependency (instead of an optional feature) on Linux.
    - **Mimalloc** is now a default dependency on Linux ARM64.
  - Docker base images have been upgraded to `debian:13-slim`.
  - `glibc` is no longer required thanks to statically linked binaries.

- Preliminary support for Cardano blocks and transactions certification:
  - Storage of Cardano blocks in the signer and aggregator `cardano_tx` SQLite database (⚠️ this will reset the `cardano-transaction` database and a new full scan of the Cardano chain will be triggered).
  - **UNSTABLE**:
    - Added new `CardanoBlocksTransactions` signed entity type for certifying both Cardano blocks and transactions.
    - Support for computing and sending signatures for the `CardanoBlocksTransactions` signed entity type in the signer.
    - Support for verifying and aggregating signatures for the `CardanoBlocksTransactions` signed entity type in the aggregator.
    - Support for computing proofs of inclusions for a list of Cardano blocks or transactions hashes in the aggregator; the proof includes extra metadata about the included blocks or transactions.
    - Support for signing with an interval lower than 15 blocks.

- **UNSTABLE**:
  - Support for **DMQ consumer deduplication** to prevent processing the same message multiple times upon reconnection to the DMQ server.
  - Support for SNARK-friendly signer registration.
  - Support for SNARK-friendly certificate chain.

| Crate               | Version  |
| ------------------- | -------- |
| mithril-aggregator  | `0.8.47` |
| mithril-client      | `0.14.5` |
| mithril-client-cli  | `0.13.9` |
| mithril-client-wasm | `0.10.4` |
| mithril-common      | `0.6.67` |
| mithril-signer      | `1.0.0`  |
| mithril-stm         | `0.10.5` |

## Mithril Distribution [2603.1] - 2026-01-29

- **BREAKING** changes in Mithril client CLI:
  - Progress bars and spinners are now outputted to stderr instead of stdout.

- **DEPRECATED** in Mithril client library, CLI and WASM:
  - The `cardano_db` function in the `Client` struct of the library and its WASM counterpart
  - The `snapshot` function has been removed from the `Client` struct of the library
  - The `--backend v1` flag of the `cardano-db` command in the CLI; use `--backend v2` instead.

- **Client library, CLI and WASM**:
  - Support for stable Cardano database v2 methods in the client WASM library.

  - Reworked the client CLI `snapshot-converter` command outputs:
    - Print all progress messages to stderr instead of stdout
    - Add support for `--json` parameter
    - Add a Docker run command in the final output to start the Cardano node with the converted ledger.

- **Aggregator**:
  - Superseded **CExplorer** API with **Blockfrost** API for pool names and tickers discovery mechanism
  - Removed optional `cexplorer_pools_url` configuration parameter
  - Added optional `blockfrost_parameters` configuration parameter (see documentation for details).

- Support for future **decentralization** of the configuration parameters of Mithril networks:
  - Added the `/protocol-configuration/{epoch}` route to fetch aggregator configuration for a given epoch
  - Refactored signer and aggregator (leader, follower) to read network configurations from a `MithrilNetworkConfigurationProvider`
  - Support for reading network configurations from the leader aggregator for follower aggregators

- Support for new **Lagrange** Mithril era.

- Support for removal of `cardano_transactions_signing_config` from the diffused Mithril network configuration.

- **UNSTABLE**:
  - Support for **DMQ protocol** in the signer, aggregator and relay.
  - Support for **aggregator discovery mechanism** in the client library and CLI.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.8.14`  |
| mithril-client      | `0.13.2`  |
| mithril-client-cli  | `0.12.38` |
| mithril-client-wasm | `0.9.11`  |
| mithril-common      | `0.6.43`  |
| mithril-signer      | `0.3.7`   |
| mithril-stm         | `0.9.5`   |

## Mithril Distribution [2543.1] - 2025-11-03

- Client library, CLI and WASM:
  - **DEPRECATED**: The `with_aggregator_client` and `new` functions have been deprecated in the `ClientBuilder` struct of the library.

  - Support for default incremental backend (`v2`) for Cardano database restoration in the client library and CLI.

  - Enhanced verification of a Cardano database which now provides a list of tampered and missing files in case of failure.

  - Support for artifacts retrieval by epoch for the Cardano database and Cardano stake distribution:
    - Support for listing of Cardano database snapshots for a given epoch, the latest epoch, or the latest epoch with offset in the library.

    - Support for listing of Cardano stake distribution snapshots for a given epoch, the latest epoch, or the latest epoch with offset in the library.

    - Support for `--epoch` optional parameter to `cardano-database snapshot list` commands snapshots, the given value can be a number, `latest`, or `latest-{offset}` in the CLI.

- Aggregator:
  - **BREAKING**: The deprecated field `next_cardano_transactions_signing_config` in the `/epoch-settings` route of the aggregator has been removed.

  - Added the `/artifact/cardano-database/epoch/{epoch}` route to fetch the list of Cardano database snapshots for a given epoch, `{epoch}` can be a number, `latest`, or `latest-{offset}`.

  - Enhanced the `/artifact/cardano-stake-distribution/epoch/{epoch}` route to support `latest` and `latest-{offset}` as `{epoch}` values.

- **UNSTABLE**:
  - Support for multiple aggregate signature proof systems in the STM library, aggregator and client.

  - Support for decentralization of the configuration parameters of Mithril networks.

  - Support for Haskell DMQ node and modifications of the DMQ protocol.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.90`  |
| mithril-client      | `0.12.34` |
| mithril-client-cli  | `0.12.33` |
| mithril-client-wasm | `0.9.7`   |
| mithril-common      | `0.6.25`  |
| mithril-signer      | `0.2.276` |
| mithril-stm         | `0.5.5`   |

## Mithril Distribution [2537.0] - 2025-09-17

- Client library, CLI and WASM:
  - Support for stable `cardano_database_v2` backend in the `mithril-client` library.

  - Support for stable `v2` backend of `cardano-db` command and decommission of the `cardano-db-v2` command in client CLI.

  - Support for stable `verify` command to verify an existing Cardano database in the client CLI.

  - Support for stable `tools utxo-hd` commands in client CLI.

  - Support for Mithril era transition in the client library, CLI and WASM.

- Support for `Cardano node` `10.5.1` in the signer and the aggregator.

- Refactored STM library for enhanced clarity, readability and maintainability.

- Added pre-built Linux ARM binaries in the distribution for the signer, client CLI, and aggregator.

- Added a `/certificate/genesis` route to the aggregator to fetch the latest genesis certificate.

- Support for loose enforcement of OpenAPI compatibility in HTTP clients of the Mithril nodes.

- Support for binary hex codec in the protocol keys and signatures.

- Support for multiple implementations of KES signature and verification operations.

- Support for the Rust `2024` edition (from `2021` edition).

- **UNSTABLE** :
  - Support for certificates chain synchronization between leader/follower aggregators.

  - Support for DMQ signature publisher in the signer and signature consumer in the aggregator.

  - Support for fake DMQ node implementation in the relay for testing purposes.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.84`  |
| mithril-client      | `0.12.30` |
| mithril-client-cli  | `0.12.30` |
| mithril-client-wasm | `0.9.5`   |
| mithril-common      | `0.6.17`  |
| mithril-signer      | `0.2.268` |
| mithril-stm         | `0.5.0`   |

## Mithril Distribution [2524.0] - 2025-06-16

- Support for `Cardano node` `10.4.1` in the signer and the aggregator.

- Support for recording client types origin (library, CLI and WASM) in the aggregator metrics.

- **UNSTABLE** :
  - New UTxO-HD snapshot converter command for client CLI:
    - Added the `tools utxo-hd snapshot-converter` command to the client CLI that converts a restored UTxO-HD snapshot to another flavor.
    - Support for converting to `LMDB` on-disk and `Legacy` in-memory flavors.

  - New api for client CLI partial cardano database restoration (aka Cardano DB V2):
    - Support for switching the backend with parameter `--backend [v1,v2]` to `cardano-database` snapshot list, snapshot show and download subcommands:
      - backend `v1` (default): support full database restoration only.
      - backend `v2` (require `--unstable`): support full and partial database restoration.
    - Added `--start`, `--end`, `--allow-override` to `cardano-database download` subcommand, supported only with `--backend v2`.
    - Deprecated `cardano-database-v2` subcommand.

  - Support for DMQ signature consumer and processor in the aggregator.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.58`  |
| mithril-client      | `0.12.11` |
| mithril-client-cli  | `0.12.11` |
| mithril-client-wasm | `0.9.1`   |
| mithril-common      | `0.5.35`  |
| mithril-signer      | `0.2.249` |
| mithril-stm         | `0.4.2`   |

## Mithril Distribution [2517.0] - 2025-05-05

- **BREAKING** changes in Mithril client CLI and library:
  - To fast bootstrap a Cardano node, the new `--include-ancillary` option has been added to the _Cardano node database_ command in the Mithril client CLI.
  - Without this option, only final immutable files are downloaded, and the ledger state must be computed from the genesis block when the Cardano node starts.
  - The `--include-ancillary` option requires the usage of an **ancillary verification key** (`--ancillary-verification-key` or `ANCILLARY_VERIFICATION_KEY`) which is specified in the [Networks configuration](https://mithril.network/doc/manual/getting-started/network-configurations) page.
  - Clients from distribution [`2513`](#mithril-distribution-25130---2025-03-28) and earlier are **not compatible** with this change and **must be updated**.

- Support for `Cardano node` `10.3.1` in the signer and the aggregator.

- Support for ancillary files signature for _Cardano node database_ and _Cardano node database v2_ certification with IOG key.

- Support for origin tags in Mithril client library, CLI and WASM to record the origin of client requests.

- **UNSTABLE** implement support for leader/follower registration in the infrastructure.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.44`  |
| mithril-client      | `0.12.0`  |
| mithril-client-cli  | `0.12.0`  |
| mithril-client-wasm | `0.9.0`   |
| mithril-common      | `0.5.27`  |
| mithril-signer      | `0.2.243` |
| mithril-stm         | `0.3.45`  |

## Mithril Distribution [2513.0] - 2025-03-28

- **BREAKING** changes in Mithril nodes:
  - Upgraded the minimum required `glibc` version from `2.31` to `2.35` for the pre-built Linux binaries
  - Mithril signer with versions `<=0.2.200` **must be updated** following the cleanup of `Thales` era legacy code
  - Mithril client library `with_snapshot_uploader` function has been renamed to `with_file_uploader`.

- Support for `Cardano node` `10.2.1` in the signer and the aggregator.

- End support for **macOS x64 pre-built binaries** for the client CLI.

- Cardano database full certification:
  - Creation of two separate archives for the immutable files and for the ancillary files.
  - Added a signed manifest file to the ancillary archive (contains the list of all files in the archive and their sha256 hashes).
  - Added client validation of the signature of the manifest file and the integrity of the files in the archive after downloading an ancillary archive.

- **UNSTABLE** Implement a follower signer registration mode in the aggregator.

- **UNSTABLE** Cardano database incremental certification:
  - Implement the client library for the signed entity type `CardanoDatabase` (download and prove snapshot).
  - Implement the client CLI commands for the signed entity type `CardanoDatabase` (snapshot list, snapshot show and download commands).
  - Implement an example crate for the signed entity type `CardanoDatabase`.
  - Lighter ancillary archive by only including what's strictly necessary: the latest ledger file and the last immutable file trio.
  - Added a signed manifest file to the ancillary archive (contains the list of all files in the archive and their sha256 hashes).
  - Added client validation of the signature of the manifest file and the integrity of the files in the archive after downloading an ancillary archive.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.23`  |
| mithril-client      | `0.11.17` |
| mithril-client-cli  | `0.11.11` |
| mithril-client-wasm | `0.8.6`   |
| mithril-common      | `0.5.14`  |
| mithril-signer      | `0.2.237` |
| mithril-stm         | `0.3.42`  |

## Mithril Distribution [2506.0] - 2025-02-14

- :warning: **SECURITY**: This distribution embeds a fix for the **Mithril certificate chain could be manipulated by an adversarial signer** security advisory [GHSA-724h-fpm5-4qvr](https://github.com/input-output-hk/mithril/security/advisories/GHSA-724h-fpm5-4qvr). All users running a **client library, client CLI or client WASM** are strongly encouraged to update them to the latest version.

- Support for `Cardano node` `10.1.4` in the signer and the aggregator.

- Remove support for `Thales` era in the signer and the aggregator.

- Build and publish both a `stable` version (for release networks) and an `unstable` version (for testing networks) of the explorer.

- Activate aggregator HTTP responses compression by the reverse proxy in the infrastructure.

- Support certification of the protocol parameters and epoch in the certificate chain.

- **UNSTABLE** Cardano database incremental certification:
  - Implement the artifact routes of the aggregator for the signed entity type `CardanoDatabase`.
  - Implement the immutable file digests route in the aggregator.
  - Implement the artifact ancillary builder in the aggregator.
  - Implement the artifact immutable builder in the aggregator.
  - Implement the artifact digest builder in the aggregator.
  - Implement the client library for the the signed entity type `CardanoDatabase` (list snapshots and get snapshot detail).
  - Implement the client library functions for the the signed entity type `CardanoDatabase` within the WASM library.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.7.1`   |
| mithril-client      | `0.11.1`  |
| mithril-client-cli  | `0.11.0`  |
| mithril-client-wasm | `0.8.1`   |
| mithril-common      | `0.5.0`   |
| mithril-signer      | `0.2.228` |
| mithril-stm         | `0.3.37`  |

## Mithril Distribution [2450.0] - 2024-12-17

- **BREAKING** changes in Mithril client library, CLI, and WASM:
  - Remove deprecated `network` field from the internal `CardanoDbBeacon`.
  - The Mithril certificates of type `CardanoImmutableFilesFull` can't be verified anymore with the previous clients.
  - Clients from distribution [`2445`](#mithril-distribution-24450---2024-11-07) and earlier must be updated.
  - Aggregators from distribution [`2445`](#mithril-distribution-24450---2024-11-07) and earlier must be updated and [`recompute their certificate hashes`](./docs/runbook/recompute-certificates-hash).

- Add Node.js and bundler targets to the Mithril client WASM library npm package.

- Add a one line shell installation script for the Mithril nodes.

- Add execution rights to pre-built binaries of the Mithril nodes packaged with GitHub releases.

- Implement the `/status` route on the aggregator's REST API to provide information about its current status.

- Implement a new `genesis generate-keypair` command in aggregator CLI to generate a new genesis keypair.

- Update to Rust `1.83`.

- **UNSTABLE** Cardano database incremental certification:
  - Implement the new signed entity type `CardanoDatabase`.
  - Implement the signable builder for the signed entity type `CardanoDatabase`.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.6.0`   |
| mithril-client      | `0.10.4`  |
| mithril-client-cli  | `0.10.5`  |
| mithril-client-wasm | `0.7.2`   |
| mithril-common      | `0.4.96`  |
| mithril-signer      | `0.2.221` |
| mithril-stm         | `0.3.34`  |

## Mithril Distribution [2445.0] - 2024-11-07

- **BREAKING** changes in Mithril client library, CLI, and WASM:
  - Remove deprecated `beacon` field from Mithril certificates.
  - Clients from distribution [`2430`](#mithril-distribution-24300---2024-07-30) and above are compatible with this change.

- Support for Prometheus metrics endpoint in aggregator.

- Support for stable Cardano stake distribution client library, CLI and WASM.

- Support for `Cardano node` `10.1.2` in the signer and the aggregator.

- Deprecate `protocol` and `next_protocol` in favor of `signer_registration_protocol` in the `/epoch-settings` route.

- Fix an issue that caused unnecessary re-scan of the Cardano chain when importing transactions.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.102` |
| mithril-client      | `0.10.1`  |
| mithril-client-cli  | `0.10.1`  |
| mithril-client-wasm | `0.6.1`   |
| mithril-common      | `0.4.79`  |
| mithril-signer      | `0.2.209` |
| mithril-stm         | `0.3.31`  |

## Mithril Distribution [2442.0] - 2024-10-21

- Decentralization of the signature orchestration:
  - Optimizations of the state machine used by the signer to create individual signatures.

  - Support for buffering of incoming single signatures by the aggregator if it can not aggregate them yet.

  - Expose the Cardano transactions signing configuration for the current and upcoming epoch via the `/epoch-settings` route.

  - Signer computes what to sign independently of the aggregator.

  - Deprecate aggregator `/certificate-pending` route as the signer does not need it anymore.

- Support for new `Pythagoras` Mithril era.

- Support for signing the protocol parameters in the Genesis certificate.

- Refactor the builder of the protocol messages, and add support for protocol parameters and epoch parts.

- Support for `Cardano node` `9.2.1` in the signer and the aggregator.

- Support for stable Cardano transaction client library, CLI and WASM.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.83`  |
| mithril-client      | `0.9.2`   |
| mithril-client-cli  | `0.9.15`  |
| mithril-client-wasm | `0.5.2`   |
| mithril-common      | `0.4.69`  |
| mithril-signer      | `0.2.200` |
| mithril-stm         | `0.3.30`  |

## Mithril Distribution [2437.1] - 2024-09-23

- **BREAKING** changes in Mithril client WASM:
  - Implementation of seamless transition from **unstable** to **stable** features.
  - A new `unstable` option in the client allows the usage of unstable features.
  - The previous `client.unstable` implementation is not supported anymore and must be replaced with `client`.

- Support for Mithril nodes footprint support in Prometheus monitoring in infrastructure.

- Add support for custom HTTP headers in Mithril client WASM library.

- Support `file://` URLs for snapshot locations in Mithril client.

- Add feature options `num-integer-backend` and `rug-backend` for `mithril-common` and `mithril-client` crates. Allows to disable `rug-backend` and avoid `LGPL` license usage.

- Post `Chang` hard fork cleanup of the CI, devnet and infrastructure.

- Cardano transactions certification (stable for signer and aggregator):
  - Support for Mithril signer memory optimization when signing Cardano transactions with multiple Merkle tree storage backends.
  - Support infinite preloading of Cardano transactions in signer.
  - Fix Cardano transactions rollbacks creating panics in signer and aggregator.

- Cardano stake distribution certification (stable for signer and aggregator):
  - Implement the signable and artifact builders for the signed entity type `CardanoStakeDistribution`.
  - Implement the HTTP routes related to the signed entity type `CardanoStakeDistribution` on the aggregator REST API.
  - Added support in the `mithril-client` library for retrieving `CardanoStakeDistribution` by epoch or by hash, and for listing all available `CardanoStakeDistribution`.
  - Implement `CardanoStakeDistribution` commands under the `--unstable` flag in the Mithril client CLI to list all available `CardanoStakeDistribution` and to download artifact by epoch or hash.
  - Implement `mithril-client` library functions related to `CardanoStakeDistribution` within the WASM library.
  - Add new tab Cardano Stake Distribution in the explorer.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.63`  |
| mithril-client      | `0.8.18`  |
| mithril-client-cli  | `0.9.12`  |
| mithril-client-wasm | `0.4.1`   |
| mithril-common      | `0.4.51`  |
| mithril-signer      | `0.2.182` |
| mithril-stm         | `0.3.29`  |

## Mithril Distribution [2430.0] - 2024-07-30

- `mithril-aggregator` node produces artifact for different signed entity types in parallel.

- Fix `Agency is theirs` error in the `ChainReader` when the underlying `Chain sync` client does not have agency.

- Support for `Cardano node` `9.1.0` in the signer and the aggregator.

- Support better disk configuration in terraform deployments with the CI/CD workflows.

- **UNSTABLE** Cardano transactions certification:
  - Make Cardano transaction signing settings configurable via the CD.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.50`  |
| mithril-client      | `0.8.10`  |
| mithril-client-cli  | `0.9.9`   |
| mithril-client-wasm | `0.3.8`   |
| mithril-common      | `0.4.38`  |
| mithril-signer      | `0.2.170` |
| mithril-stm         | `0.3.26`  |

## Mithril Distribution [2428.0] - 2024-07-15

- Provide a feature to the `mithril-client` crate to allow selection of the TLS implementation used by the dependent `reqwest` crate.

- Implement a reset mechanism for mutable resources returned to a pool (`ResourcePool`) to keep it in a consistent state.

- Implement a lock mechanism on `SignedEntityType` to prevent concurrent work on a same entity type.

- Extended CI build and test steps for MacOS `arm64` runners and include pre-built binaries for MacOS `arm64` in the releases.

- Add a regularly run upkeep task to the `mithril-aggregator` and `mithril-signer` to clean up stale data and optimize their databases.

- Support for `Cardano node` `9.0.0` in the signer and the aggregator.

- Refactor the Cardano node configuration in the infrastructure.

- Add prettier configuration to standardize the code formatting in the repository.

- Field `beacon` becomes optional in `CertificatePendingMessage` response of `/certificate-pending` route.

- **UNSTABLE** Cardano transactions certification:
  - Optimize the performances of the computation of the proof with a Merkle map.
  - Handle rollback events from the Cardano chain by removing stale data.
  - Preload Cardano transactions and Block Range Roots at signer & aggregator startup.
  - Chunk the Cardano transactions import in `mithril-signer` to reduce disk footprint by running the pruning process more frequently.
  - Add a database connection pool on the Cardano transaction repository for increased performances of the prover.
  - Import Cardano transactions with Chain Sync mini protocol and Pallas chain reader.
  - Avoid aggregator and signer being blocked when importing the Cardano transactions.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.40`  |
| mithril-client      | `0.8.7`   |
| mithril-client-cli  | `0.9.6`   |
| mithril-client-wasm | `0.3.7`   |
| mithril-common      | `0.4.29`  |
| mithril-signer      | `0.2.161` |
| mithril-stm         | `0.3.24`  |

## Mithril Distribution [2423.0] - 2024-06-12

- **BREAKING** changes in Mithril client CLI:
  - The deprecated `snapshot` command is removed from the Mithril client CLI
  - Use the `cardano-db snapshot` command instead.

- Update website and explorer user interface to use the new mithril logo.

- **UNSTABLE** Cardano transactions certification:
  - Support computation of the Cardano Transactions signature and proving with the pre-computed Block Range Merkle Roots retrieved from the database.
  - Prune Cardano Transactions from the signer database after the Block Range Merkle Roots have been computed.
  - Implement a Chain Reader which retrieves blocks from the Cardano chain with Pallas through the `chainsync` mini-protocol.
  - Implement a Resource Pool and use it for caching Block Range Merkle maps used by the Cardano transactions prover and improving the throughput.
  - Change the beacon of the Cardano Transactions to a block number instead of an immutable file number.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.16`  |
| mithril-client      | `0.8.3`   |
| mithril-client-cli  | `0.9.2`   |
| mithril-client-wasm | `0.3.3`   |
| mithril-common      | `0.4.13`  |
| mithril-signer      | `0.2.141` |
| mithril-stm         | `0.3.22`  |

## Mithril Distribution [2418.1] - 2024-05-13

- **BREAKING** changes in Mithril client CLI:
  - Certificate chain structure has been modified to remove coupling with immutable file number.
  - Client needs to be updated to verify certificate chain.

- Support incremental import for Cardano Transactions instead of scanning the whole immutable database for every signing round.

- Chain observers support the retrieval of the current Cardano chain point.

- Deprecate `portable` feature of `mithril-stm` and `mithril-client`:
  - Instead, always enable BLST `portable` feature in `mithril-stm` for runtime check of intel ADX instruction set.
  - `portable` feature now has no effect and should be removed from crate dependencies.
  - Removed it from all other crates (including `mithril-common`).

- Switched memory allocator to `jemallocator` on signer and aggregator to avoid memory fragmentation when signing transactions (which lead to RES memory not being properly returned to the OS).

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.5.0`   |
| mithril-client      | `0.8.0`   |
| mithril-client-cli  | `0.8.0`   |
| mithril-client-wasm | `0.3.0`   |
| mithril-common      | `0.4.0`   |
| mithril-signer      | `0.2.130` |
| mithril-stm         | `0.3.19`  |

## Mithril Distribution [2412.0] - 2024-03-26

- **GitHub release**: <https://github.com/input-output-hk/mithril/releases/tag/2412.0>

- _DEPRECATED_ the `snapshot` command in the Mithril client CLI:
  - Renamed to `cardano-db snapshot`.
  - Will be **removed** in **2** distributions.

- Support for `Prometheus` endpoint for metrics in signer ([setup guide](https://mithril.network/doc/next/manual/getting-started/run-signer-node#activate-prometheus-endpoint)).

- Full support for chain observer with `Pallas` in signer and aggregator.

- Support for `Cardano node` `8.9.0` in the signer and the aggregator.

- Bug fixes and performance improvements.

- Crates versions:

| Crate               | Version   |
| ------------------- | --------- |
| mithril-aggregator  | `0.4.49`  |
| mithril-client      | `0.6.9`   |
| mithril-client-cli  | `0.7.6`   |
| mithril-client-wasm | `0.2.5`   |
| mithril-common      | `0.3.21`  |
| mithril-signer      | `0.2.116` |
| mithril-stm         | `0.3.17`  |
