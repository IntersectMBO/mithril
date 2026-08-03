---
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

import CompiledBinaries from '../../../compiled-binaries.mdx'

# Mithril client node

:::info

Mithril client is responsible for restoring the **Cardano** blockchain on an empty node from a certified snapshot.

:::

:::tip

- For more information about the **Mithril network**, please see
  the [architecture](../../../mithril/advanced/mithril-network/architecture.md) overview

- For more information about the **Mithril client** node, please
  see [this overview](../../../mithril/advanced/mithril-network/client.md)

- Check out the [`Bootstrap a Cardano node`](../../getting-started/bootstrap-cardano-node.md) guide.

:::

:::info

The Mithril network configurations are available in the [**Network configurations**](../../getting-started/network-configurations.md) section of the user manual.

:::

## Resources

|          Node          |                                      Source repository                                      |                                  Rust documentation                                   |                                       Docker packages                                        |                         Network configurations                         |
| :--------------------: | :-----------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------: |
| **Mithril client CLI** | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/tree/main/mithril-client-cli) | [:arrow_upper_right:](https://mithril.network/rust-doc/mithril_client_cli/index.html) | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/pkgs/container/mithril-client) | [:arrow_upper_right:](../../getting-started/network-configurations.md) |

## Prerequisites

<Tabs groupId="system" queryString>
<TabItem value="linux-mac" label="Linux / Mac">
- Install the latest stable version of the [correctly configured](https://www.rust-lang.org/learn/get-started) Rust
  toolchain

- Install build tools `build-essential` and `m4`; for example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`

- Install OpenSSL development libraries; for example, on Ubuntu/Debian/Mint, run `apt install libssl-dev`.

</TabItem>
<TabItem value="windows" label="Windows">
:::info
All Windows commands below are run on PowerShell 5.
:::

- Install [Visual Studio C++ Build tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (required by the Rust toolchain).

- Install the latest stable version of the [correctly configured](https://www.rust-lang.org/learn/get-started) Rust
  toolchain

</TabItem>
</Tabs>

## Download the source file

Download the source file from GitHub (HTTPS):

```bash
git clone https://github.com/IntersectMBO/mithril.git
```

Or (SSH):

```bash
git clone git@github.com:IntersectMBO/mithril.git
```

Switch to the desired branch/tag:

```bash
# Replace **YOUR_BUILD_BRANCH_OR_TAG** with the appropriate branch or tag name
# Please refer to the [**Network configurations**](http://mithril.network/manual/getting-started/network-configurations) section of the user manual
git checkout **YOUR_BUILD_BRANCH_OR_TAG**
```

Change the directory:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  cd mithril/mithril-client-cli
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cd mithril\mithril-client-cli
  ```
  </TabItem>
</Tabs>

## Development testing and building

Run tests:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make test
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo test
  ```
  </TabItem>
</Tabs>

Create the help menu:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make help
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo run -- -h
  ```
  </TabItem>
</Tabs>

Generate the Rust documentation:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make doc
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo doc --no-deps --open
  ```
  </TabItem>
</Tabs>

Run in debug mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make debug
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo run
  ```
  </TabItem>
</Tabs>

## Building for release and running the binary

Build and run in release mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make run
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo build --release; copy ..\target\release\mithril-client.exe .; .\mithril-client
  ```
  </TabItem>
</Tabs>

Or, build only in release mode:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make build
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo build --release; copy ..\target\release\mithril-client.exe .
  ```
  </TabItem>
</Tabs>

Display the help menu:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-client --help
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  .\mithril-client --help
  ```
  </TabItem>
</Tabs>

You should see:

```bash
This program shows, downloads and verifies certified blockchain artifacts.

Usage: mithril-client [OPTIONS] <COMMAND>

Commands:
  cardano-db                  Cardano db management (alias: cdb)
  mithril-stake-distribution  Mithril stake distribution management (alias: msd)
  cardano-transaction         Cardano transactions management (alias: ctx)
  cardano-stake-distribution  Cardano stake distribution management (alias: csd)
  tools                       Tools commands
  help                        Print this message or the help of the given subcommand(s)

Options:
      --run-mode <RUN_MODE>
          Run Mode

          [env: RUN_MODE=]
          [default: dev]

  -v, --verbose...
          Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)

      --config-directory <CONFIG_DIRECTORY>
          Directory where configuration file is located

          [default: ./config]

      --aggregator-endpoint <AGGREGATOR_ENDPOINT>
          Override configuration Aggregator endpoint URL.

          Either the full URL of the aggregator endpoint (e.g., "https://aggregator.release-preprod.api.mithril.network/aggregator") or a string formatted as "auto:<mithril_network>" to use automatic discovery (e.g., "auto:release-preprod") (unstable).

          [env: AGGREGATOR_ENDPOINT=]

      --json
          Enable JSON output for command results

      --log-format-json
          Enable JSON output for logs displayed according to verbosity level

      --log-output <LOG_OUTPUT>
          Redirect the logs to a file

      --unstable
          Enable unstable commands

      --origin-tag <ORIGIN_TAG>
          Request origin tag

      --era <ERA>
          Override the Mithril era

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Run in release mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-client
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  .\mithril-client
  ```
  </TabItem>
</Tabs>

Run in release mode with a specific mode:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-client --run-mode preview
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  .\mithril-client --run-mode preview
  ```
  </TabItem>
</Tabs>

Run in release mode with a custom configuration using environment variables:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  GENESIS_VERIFICATION_KEY=$(wget -q -O - **YOUR_GENESIS_VERIFICATION_KEY**) AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT** ./mithril-client
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  $env:GENESIS_VERIFICATION_KEY = curl.exe --silent - **YOUR_GENESIS_VERIFICATION_KEY**; $env:AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**; .\mithril-client
  ```
  </TabItem>
</Tabs>

:::tip

To display results in JSON format for the `list` and `show` commands, simply use the `--json` (or `-j`) option:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-client cardano-db snapshot list --json
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  .\mithril-client cardano-db snapshot list --json
  ```
  </TabItem>
</Tabs>

:::

:::tip

If you wish to delve deeper and access several levels of logs from the Mithril client, use the following:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

## Download the pre-built binary

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  <CompiledBinaries  node="mithril-client"/>
  </TabItem>
  <TabItem value="windows" label="Windows">
  :::info
  Each distribution (pre-)release comes with pre-compiled binaries ready to use.
  You can download them from the distribution (pre-)release distribution page on GitHub that depends on the Mithril network you
  are targeting.
  These links are available in the **Build from** field in the [**network configurations**](/manual/getting-started/network-configurations) table.
  :::
  </TabItem>
</Tabs>

## Run a Docker container

### Registry image

A list of available images on the registry can be
found [here](https://github.com/IntersectMBO/mithril/pkgs/container/mithril-client).

To prepare the environment variables, retrieve the values from the **Mithril networks** section.

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  export MITHRIL_IMAGE_ID=**YOUR_MITHRIL_IMAGE_ID**
  export AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**
  export GENESIS_VERIFICATION_KEY=$(wget -q -O - **YOUR_GENESIS_VERIFICATION_KEY**)
  export SNAPSHOT_DIGEST=latest
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  $env:MITHRIL_IMAGE_ID="**YOUR_MITHRIL_IMAGE_ID**"
  $env:AGGREGATOR_ENDPOINT="**YOUR_AGGREGATOR_ENDPOINT**"
  $env:GENESIS_VERIFICATION_KEY = curl.exe --silent - **YOUR_GENESIS_VERIFICATION_KEY**
  $env:SNAPSHOT_DIGEST="latest"
  ```
  </TabItem>
</Tabs>

Here is an example configuration for the `release-preprod` network and the `latest` stable Docker image:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  export MITHRIL_IMAGE_ID=latest
  export AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator
  export GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)
  export SNAPSHOT_DIGEST=latest
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  $env:MITHRIL_IMAGE_ID="latest"
  $env:AGGREGATOR_ENDPOINT="https://aggregator.release-preprod.api.mithril.network/aggregator"
  $env:GENESIS_VERIFICATION_KEY = curl.exe --silent - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey
  $env:SNAPSHOT_DIGEST="latest"
  ```
  </TabItem>
</Tabs>

Proceed by creating a shell function for the Mithril client:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  mithril_client () {
    docker run --rm -e GENESIS_VERIFICATION_KEY=$GENESIS_VERIFICATION_KEY -e AGGREGATOR_ENDPOINT=$AGGREGATOR_ENDPOINT --name='mithril-client' -v $(pwd):/app/data -w /app/data -u $(id -u) ghcr.io/intersectmbo/mithril-client:$MITHRIL_IMAGE_ID $@
  }
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  function mithril_client {
    docker run --rm -e GENESIS_VERIFICATION_KEY=$env:GENESIS_VERIFICATION_KEY -e AGGREGATOR_ENDPOINT=$env:AGGREGATOR_ENDPOINT --name='mithril-client' -v ${PWD}:/app/data -w /app/data ghcr.io/intersectmbo/mithril-client:$env:MITHRIL_IMAGE_ID $args
  }
  ```
  </TabItem>
</Tabs>

Now you can use the `mithril_client` functions:

```bash
# 1- Help
mithril_client help

# 2- List Cardano db snapshots
mithril_client cardano-db snapshot list

# 3- Show detailed information about a Cardano db snapshot
mithril_client cardano-db snapshot show $CARDANO_DB_DIGEST

# 4- Download the given Cardano db and verify the certificate
mithril_client cardano-db download --include-ancillary --ancillary-verification-key $ANCILLARY_VERIFICATION_KEY $CARDANO_DB_DIGEST

# 5- List Mithril stake distributions
mithril_client mithril-stake-distribution list

# 6- Download and verify the given Mithril stake distribution
mithril_client mithril-stake-distribution download $MITHRIL_STAKE_DISTRIBUTION_ARTIFACT_HASH

# 7- List Cardano transaction snapshots
mithril_client cardano-transaction snapshot list

# 8- Show detailed information about a Cardano transaction snapshot
mithril_client cardano-transaction snapshot show $CARDANO_TRANSACTION_SNAPSHOT_HASH

# 9- Certify that the given list of transactions hashes are included in the Cardano transactions set
mithril_client cardano-transaction certify $TRANSACTION_HASH_1,$TRANSACTION_HASH_2

# 10- List Cardano stake distributions
mithril_client cardano-stake-distribution list

# 11 - Download and verify the given Cardano stake distribution from its hash or epoch
mithril_client cardano-stake-distribution download $UNIQUE_IDENTIFIER
```

## Subcommands

Here are the subcommands available:

### Cardano DB

| Subcommand        | Performed action                                            |
| ----------------- | ----------------------------------------------------------- |
| **download**      | Downloads and restores a cardano-db snapshot                |
| **verify**        | Verifies an existing Cardano database (`v2` backend only)   |
| **help**          | Prints this message or the help for the given subcommand(s) |
| **snapshot list** | Lists available cardano-db snapshots                        |
| **snapshot show** | Shows information about a cardano-db snapshot               |

### Mithril stake distribution

| Subcommand   | Performed action                                            |
| ------------ | ----------------------------------------------------------- |
| **download** | Downloads and verifies Mithril stake distribution           |
| **help**     | Prints this message or the help for the given subcommand(s) |
| **list**     | Lists available Mithril stake distributions                 |

### Cardano transactions

| Subcommand        | Performed action                                                                              |
| ----------------- | --------------------------------------------------------------------------------------------- |
| **certify**       | Certifies that given list of transactions hashes are included in the Cardano transactions set |
| **snapshot list** | Lists available Cardano transactions snapshots                                                |
| **snapshot show** | Shows information about a Cardano transactions snapshot                                       |
| **help**          | Prints this message or the help for the given subcommand(s)                                   |

### Cardano stake distribution

| Subcommand   | Performed action                                            |
| ------------ | ----------------------------------------------------------- |
| **download** | Downloads and verifies Cardano stake distribution           |
| **help**     | Prints this message or the help for the given subcommand(s) |
| **list**     | Lists available Cardano stake distributions                 |

### Tools

| Subcommand              | Performed action                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------- |
| **utxo-hd**             | UTxO-HD related commands (e.g., converting a ledger state snapshot to another flavor) |
| **discover-aggregator** | Aggregator discovery command (unstable)                                               |
| **help**                | Prints this message or the help for the given subcommand(s)                           |

## Configuration parameters

The configuration parameters can be set in either of the following ways:

1. In a configuration file, depending on the `--run-mode` parameter. If the runtime mode is `testnet`, the file is
   located in `./conf/testnet.json`.

2. The value can be overridden by an environment variable with the parameter name in uppercase.

Here is a list of the available parameters:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                        | Default value | Example                                                                                                                 |     Mandatory      |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------ | ------------- | ----------------------------------------------------------------------------------------------------------------------- | :----------------: |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level                                                    | -             | Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace` | :heavy_check_mark: |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                           | `false`       | -                                                                                                                       |         -          |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                           | `dev`         | -                                                                                                                       | :heavy_check_mark: |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                     | -             | `https://aggregator.pre-release-preview.api.mithril.network/aggregator`                                                 | :heavy_check_mark: |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                             | `false`       | -                                                                                                                       |         -          |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level | `false`       | -                                                                                                                       |         -          |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                        | -             | -                                                                                                                       |         -          |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                 | -             | -                                                                                                                       |         -          |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                           | -             | -                                                                                                                       |         -          |
| `version`             | `--version`             |         `-V`         | -                     | Print version                                                      | -             | `./mithril-client.log`                                                                                                  |         -          |

`cardano-db snapshot show` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                                                                                       | Default value | Example |     Mandatory      |
| --------------------- | ----------------------- | :------------------: | --------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `backend`             | `--backend`             |         `-b`         | -                     | Backend to use, either: `v1` (deprecated, full database restoration only) or `v2` (default, full or partial database restoration) | `v2`          | -       |         -          |
| `digest`              | -                       |          -           | -                     | Digest of the Cardano db snapshot to show or `latest` for the latest artifact                                                     | -             | -       | :heavy_check_mark: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                                                                                          | `dev`         | -       |         -          |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                                                   | `0`           | -       |         -          |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                                                                                     | `./config`    | -       |         -          |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                                                                    | -             | -       |         -          |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                                                                                            | `false`       | -       |         -          |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                                                                | `false`       | -       |         -          |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                                                                                       | -             | -       |         -          |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                                                                                          | `false`       | -       |         -          |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                                                                                | -             | -       |         -          |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                                                                                          | -             | -       |         -          |
| `help`                | `--help`                |         `-h`         | -                     | Print help (see more with '--help')                                                                                               | -             | -       |         -          |

`cardano-db snapshot list` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                                                                                                                    | Default value | Example | Mandatory |
| --------------------- | ----------------------- | :------------------: | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :-------: |
| `backend`             | `--backend`             |         `-b`         | -                     | Backend to use, either: `v1` (deprecated, full database restoration only) or `v2` (default, full or partial database restoration)                              | `v2`          | -       |     -     |
| `epoch`               | `--epoch`               |          -           | -                     | [backend `v2` only] Epoch of the Cardano db snapshots to list, or `latest` for the latest artifact, or `latest-X` for the artifact of the latest epoch minus X | -             | -       |     -     |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                                                                                                                       | `dev`         | -       |     -     |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                                                                                | `0`           | -       |     -     |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                                                                                                                  | `./config`    | -       |     -     |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                                                                                                 | -             | -       |     -     |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                                                                                                                         | `false`       | -       |     -     |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                                                                                             | `false`       | -       |     -     |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                                                                                                                    | -             | -       |     -     |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                                                                                                                       | `false`       | -       |     -     |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                                                                                                             | -             | -       |     -     |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                                                                                                                       | -             | -       |     -     |
| `help`                | `--help`                |         `-h`         | -                     | Print help (see more with '--help')                                                                                                                            | -             | -       |     -     |

`cardano-db download` command:

| Parameter                    | Command line (long)            | Command line (short) | Environment variable         | Description                                                                                                                         | Default value | Example |     Mandatory      |
| ---------------------------- | ------------------------------ | :------------------: | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `backend`                    | `--backend`                    |         `-b`         | -                            | Backend to use, either: `v1` (deprecated, full database restoration only) or `v2` (default, full or partial database restoration)   | `v2`          | -       |         -          |
| `digest`                     | -                              |          -           | -                            | Digest of the Cardano db snapshot to download or `latest` for the latest artifact                                                   | -             | -       | :heavy_check_mark: |
| `download_dir`               | `--download-dir`               |          -           | -                            | Directory where the immutable and ancillary files will be downloaded                                                                | -             | -       |         -          |
| `genesis_verification_key`   | `--genesis-verification-key`   |          -           | `GENESIS_VERIFICATION_KEY`   | Genesis verification key to check the certificate chain                                                                             | -             | -       | :heavy_check_mark: |
| `include_ancillary`          | `--include-ancillary`          |          -           | -                            | Include ancillary files in the download, if set the `ancillary_verification_key` is required in order to verify the ancillary files | `false`       | -       |         -          |
| `ancillary_verification_key` | `--ancillary-verification-key` |          -           | `ANCILLARY_VERIFICATION_KEY` | Ancillary verification key to verify the ancillary files                                                                            | -             | -       |         -          |
| `start`                      | `--start`                      |          -           | -                            | [backend `v2` only] The first immutable file number to download                                                                     | -             | -       |         -          |
| `end`                        | `--end`                        |          -           | -                            | [backend `v2` only] The last immutable file number to download                                                                      | -             | -       |         -          |
| `allow_override`             | `--allow-override`             |          -           | -                            | [backend `v2` only] Allow existing files in the download directory to be overridden                                                 | `false`       | -       |         -          |
| `run_mode`                   | `--run-mode`                   |          -           | `RUN_MODE`                   | Run Mode                                                                                                                            | `dev`         | -       |         -          |
| `verbose`                    | `--verbose`                    |         `-v`         | -                            | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                                                     | `0`           | -       |         -          |
| `config_directory`           | `--config-directory`           |          -           | -                            | Directory where configuration file is located                                                                                       | `./config`    | -       |         -          |
| `aggregator_endpoint`        | `--aggregator-endpoint`        |          -           | `AGGREGATOR_ENDPOINT`        | Override configuration Aggregator endpoint URL                                                                                      | -             | -       |         -          |
| `json`                       | `--json`                       |          -           | -                            | Enable JSON output for command results                                                                                              | `false`       | -       |         -          |
| `log_format_json`            | `--log-format-json`            |          -           | -                            | Enable JSON output for logs displayed according to verbosity level                                                                  | `false`       | -       |         -          |
| `log_output`                 | `--log-output`                 |          -           | -                            | Redirect the logs to a file                                                                                                         | -             | -       |         -          |
| `unstable`                   | `--unstable`                   |          -           | -                            | Enable unstable commands                                                                                                            | `false`       | -       |         -          |
| `origin_tag`                 | `--origin-tag`                 |          -           | -                            | Request origin tag                                                                                                                  | -             | -       |         -          |
| `era`                        | `--era`                        |          -           | -                            | Override the Mithril era                                                                                                            | -             | -       |         -          |
| `help`                       | `--help`                       |         `-h`         | -                            | Print help (see more with '--help')                                                                                                 | -             | -       |         -          |

`cardano-db verify` command (`v2` backend only):

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                                                                             | Default value | Example |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `backend`                  | `--backend`                  |         `-b`         | -                          | Backend to use, either: `v1` (not supported for verify command) or `v2` (default, full or partial database restoration) | `v2`          | -       |         -          |
| `digest`                   | -                            |          -           | -                          | Digest of the Cardano db snapshot to verify or `latest` for the latest artifact                                         | -             | -       | :heavy_check_mark: |
| `db_dir`                   | `--db-dir`                   |          -           | -                          | Directory from where the immutable will be verified                                                                     | -             | -       |         -          |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | `GENESIS_VERIFICATION_KEY` | Genesis verification key to check the certificate chain                                                                 | -             | -       |         -          |
| `start`                    | `--start`                    |          -           | -                          | The first immutable file number to verify                                                                               | -             | -       |         -          |
| `end`                      | `--end`                      |          -           | -                          | The last immutable file number to verify                                                                                | -             | -       |         -          |
| `allow_missing`            | `--allow-missing`            |          -           | -                          | If set, the verification will not fail if some immutable files are missing                                              | `false`       | -       |         -          |
| `run_mode`                 | `--run-mode`                 |          -           | `RUN_MODE`                 | Run Mode                                                                                                                | `dev`         | -       |         -          |
| `verbose`                  | `--verbose`                  |         `-v`         | -                          | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                                         | `0`           | -       |         -          |
| `config_directory`         | `--config-directory`         |          -           | -                          | Directory where configuration file is located                                                                           | `./config`    | -       |         -          |
| `aggregator_endpoint`      | `--aggregator-endpoint`      |          -           | `AGGREGATOR_ENDPOINT`      | Override configuration Aggregator endpoint URL                                                                          | -             | -       |         -          |
| `json`                     | `--json`                     |          -           | -                          | Enable JSON output for command results                                                                                  | `false`       | -       |         -          |
| `log_format_json`          | `--log-format-json`          |          -           | -                          | Enable JSON output for logs displayed according to verbosity level                                                      | `false`       | -       |         -          |
| `log_output`               | `--log-output`               |          -           | -                          | Redirect the logs to a file                                                                                             | -             | -       |         -          |
| `unstable`                 | `--unstable`                 |          -           | -                          | Enable unstable commands                                                                                                | `false`       | -       |         -          |
| `origin_tag`               | `--origin-tag`               |          -           | -                          | Request origin tag                                                                                                      | -             | -       |         -          |
| `era`                      | `--era`                      |          -           | -                          | Override the Mithril era                                                                                                | -             | -       |         -          |
| `help`                     | `--help`                     |         `-h`         | -                          | Print help (see more with '--help')                                                                                     | -             | -       |         -          |

`mithril-stake-distribution list` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                        | Default value | Example | Mandatory |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------ | ------------- | ------- | :-------: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                           | `dev`         | -       |     -     |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)    | `0`           | -       |     -     |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                      | `./config`    | -       |     -     |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                     | -             | -       |     -     |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                             | `false`       | -       |     -     |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level | `false`       | -       |     -     |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                        | -             | -       |     -     |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                           | `false`       | -       |     -     |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                 | -             | -       |     -     |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                           | -             | -       |     -     |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                         | -             | -       |     -     |

`mithril-stake-distribution download` command:

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                                          | Default value | Example |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | ------------------------------------------------------------------------------------ | ------------- | ------- | :----------------: |
| `artifact_hash`            | -                            |          -           | -                          | Hash of the Mithril stake distribution artifact, or `latest` for the latest artifact | -             | -       | :heavy_check_mark: |
| `download_dir`             | `--download-dir`             |          -           | -                          | Directory where the Mithril stake distribution will be downloaded                    | -             | -       |         -          |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | `GENESIS_VERIFICATION_KEY` | Genesis verification key to check the certificate chain                              | -             | -       | :heavy_check_mark: |
| `run_mode`                 | `--run-mode`                 |          -           | `RUN_MODE`                 | Run Mode                                                                             | `dev`         | -       |         -          |
| `verbose`                  | `--verbose`                  |         `-v`         | -                          | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                      | `0`           | -       |         -          |
| `config_directory`         | `--config-directory`         |          -           | -                          | Directory where configuration file is located                                        | `./config`    | -       |         -          |
| `aggregator_endpoint`      | `--aggregator-endpoint`      |          -           | `AGGREGATOR_ENDPOINT`      | Override configuration Aggregator endpoint URL                                       | -             | -       |         -          |
| `json`                     | `--json`                     |          -           | -                          | Enable JSON output for command results                                               | `false`       | -       |         -          |
| `log_format_json`          | `--log-format-json`          |          -           | -                          | Enable JSON output for logs displayed according to verbosity level                   | `false`       | -       |         -          |
| `log_output`               | `--log-output`               |          -           | -                          | Redirect the logs to a file                                                          | -             | -       |         -          |
| `unstable`                 | `--unstable`                 |          -           | -                          | Enable unstable commands                                                             | `false`       | -       |         -          |
| `origin_tag`               | `--origin-tag`               |          -           | -                          | Request origin tag                                                                   | -             | -       |         -          |
| `era`                      | `--era`                      |          -           | -                          | Override the Mithril era                                                             | -             | -       |         -          |
| `help`                     | `--help`                     |         `-h`         | -                          | Print help (see more with '--help')                                                  | -             | -       |         -          |

`cardano-transaction snapshot show` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                                                      | Default value | Example |     Mandatory      |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------------------------------------ | ------------- | ------- | :----------------: |
| `backend`             | `--backend`             |         `-b`         | -                     | Backend to use, either: `v1` (default) or `v2` (unstable, with additional information in output) | `v1`          | -       |         -          |
| `hash`                | -                       |          -           | -                     | Hash of the Cardano transaction snapshot to show or `latest` for the latest artifact             | -             | -       | :heavy_check_mark: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                                                         | `dev`         | -       |         -          |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                  | `0`           | -       |         -          |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                                                    | `./config`    | -       |         -          |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                                   | -             | -       |         -          |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                                                           | `false`       | -       |         -          |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                               | `false`       | -       |         -          |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                                                      | -             | -       |         -          |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                                                         | `false`       | -       |         -          |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                                               | -             | -       |         -          |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                                                         | -             | -       |         -          |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                                                       | -             | -       |         -          |

`cardano-transaction snapshot list` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                                                      | Default value | Example | Mandatory |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------------------------------------ | ------------- | ------- | :-------: |
| `backend`             | `--backend`             |         `-b`         | -                     | Backend to use, either: `v1` (default) or `v2` (unstable, with additional information in output) | `v1`          | -       |     -     |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                                                         | `dev`         | -       |     -     |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                  | `0`           | -       |     -     |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                                                    | `./config`    | -       |     -     |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                                   | -             | -       |     -     |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                                                           | `false`       | -       |     -     |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                               | `false`       | -       |     -     |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                                                      | -             | -       |     -     |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                                                         | `false`       | -       |     -     |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                                               | -             | -       |     -     |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                                                         | -             | -       |     -     |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                                                       | -             | -       |     -     |

`cardano-transaction certify` command:

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                                                      | Default value | Example |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | ------------------------------------------------------------------------------------------------ | ------------- | ------- | :----------------: |
| `backend`                  | `--backend`                  |         `-b`         | -                          | Backend to use, either: `v1` (default) or `v2` (unstable, with additional information in output) | `v1`          | -       |         -          |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | `GENESIS_VERIFICATION_KEY` | Genesis verification key to check the certificate chain                                          | -             | -       | :heavy_check_mark: |
| `transactions_hashes`      | -                            |          -           | -                          | Hashes of the transactions to certify                                                            | -             | -       | :heavy_check_mark: |
| `run_mode`                 | `--run-mode`                 |          -           | `RUN_MODE`                 | Run Mode                                                                                         | `dev`         | -       |         -          |
| `verbose`                  | `--verbose`                  |         `-v`         | -                          | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                  | `0`           | -       |         -          |
| `config_directory`         | `--config-directory`         |          -           | -                          | Directory where configuration file is located                                                    | `./config`    | -       |         -          |
| `aggregator_endpoint`      | `--aggregator-endpoint`      |          -           | `AGGREGATOR_ENDPOINT`      | Override configuration Aggregator endpoint URL                                                   | -             | -       |         -          |
| `json`                     | `--json`                     |          -           | -                          | Enable JSON output for command results                                                           | `false`       | -       |         -          |
| `log_format_json`          | `--log-format-json`          |          -           | -                          | Enable JSON output for logs displayed according to verbosity level                               | `false`       | -       |         -          |
| `log_output`               | `--log-output`               |          -           | -                          | Redirect the logs to a file                                                                      | -             | -       |         -          |
| `unstable`                 | `--unstable`                 |          -           | -                          | Enable unstable commands                                                                         | `false`       | -       |         -          |
| `origin_tag`               | `--origin-tag`               |          -           | -                          | Request origin tag                                                                               | -             | -       |         -          |
| `era`                      | `--era`                      |          -           | -                          | Override the Mithril era                                                                         | -             | -       |         -          |
| `help`                     | `--help`                     |         `-h`         | -                          | Print help                                                                                       | -             | -       |         -          |

`cardano-block snapshot show` command:

:::warning

This command is unstable.

:::

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                                                  | Default value | Example |     Mandatory      |
| --------------------- | ----------------------- | :------------------: | --------------------- | -------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `hash`                | -                       |          -           | -                     | Hash of the Cardano blocks transactions snapshot to show or `latest` for the latest artifact | -             | -       | :heavy_check_mark: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                                                     | `dev`         | -       |         -          |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                              | `0`           | -       |         -          |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                                                | `./config`    | -       |         -          |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                               | -             | -       |         -          |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                                                       | `false`       | -       |         -          |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                           | `false`       | -       |         -          |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                                                  | -             | -       |         -          |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                                                     | `false`       | -       |         -          |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                                           | -             | -       |         -          |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                                                     | -             | -       |         -          |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                                                   | -             | -       |         -          |

`cardano-block snapshot list` command:

:::warning

This command is unstable.

:::

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                        | Default value | Example | Mandatory |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------ | ------------- | ------- | :-------: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                           | `dev`         | -       |     -     |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)    | `0`           | -       |     -     |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                      | `./config`    | -       |     -     |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                     | -             | -       |     -     |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                             | `false`       | -       |     -     |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level | `false`       | -       |     -     |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                        | -             | -       |     -     |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                           | `false`       | -       |     -     |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                 | -             | -       |     -     |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                           | -             | -       |     -     |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                         | -             | -       |     -     |

`cardano-block certify` command:

:::warning

This command is unstable.

:::

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                        | Default value | Example |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | ------------------------------------------------------------------ | ------------- | ------- | :----------------: |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | `GENESIS_VERIFICATION_KEY` | Genesis verification key to check the certificate chain            | -             | -       | :heavy_check_mark: |
| `blocks_hashes`            | -                            |          -           | -                          | Hashes of the blocks to certify                                    | -             | -       | :heavy_check_mark: |
| `run_mode`                 | `--run-mode`                 |          -           | `RUN_MODE`                 | Run Mode                                                           | `dev`         | -       |         -          |
| `verbose`                  | `--verbose`                  |         `-v`         | -                          | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)    | `0`           | -       |         -          |
| `config_directory`         | `--config-directory`         |          -           | -                          | Directory where configuration file is located                      | `./config`    | -       |         -          |
| `aggregator_endpoint`      | `--aggregator-endpoint`      |          -           | `AGGREGATOR_ENDPOINT`      | Override configuration Aggregator endpoint URL                     | -             | -       |         -          |
| `json`                     | `--json`                     |          -           | -                          | Enable JSON output for command results                             | `false`       | -       |         -          |
| `log_format_json`          | `--log-format-json`          |          -           | -                          | Enable JSON output for logs displayed according to verbosity level | `false`       | -       |         -          |
| `log_output`               | `--log-output`               |          -           | -                          | Redirect the logs to a file                                        | -             | -       |         -          |
| `unstable`                 | `--unstable`                 |          -           | -                          | Enable unstable commands                                           | `false`       | -       |         -          |
| `origin_tag`               | `--origin-tag`               |          -           | -                          | Request origin tag                                                 | -             | -       |         -          |
| `era`                      | `--era`                      |          -           | -                          | Override the Mithril era                                           | -             | -       |         -          |
| `help`                     | `--help`                     |         `-h`         | -                          | Print help                                                         | -             | -       |         -          |

`cardano-stake-distribution list` command:

| Parameter             | Command line (long)     | Command line (short) | Environment variable  | Description                                                        | Default value | Example | Mandatory |
| --------------------- | ----------------------- | :------------------: | --------------------- | ------------------------------------------------------------------ | ------------- | ------- | :-------: |
| `run_mode`            | `--run-mode`            |          -           | `RUN_MODE`            | Run Mode                                                           | `dev`         | -       |     -     |
| `verbose`             | `--verbose`             |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)    | `0`           | -       |     -     |
| `config_directory`    | `--config-directory`    |          -           | -                     | Directory where configuration file is located                      | `./config`    | -       |     -     |
| `aggregator_endpoint` | `--aggregator-endpoint` |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                     | -             | -       |     -     |
| `json`                | `--json`                |          -           | -                     | Enable JSON output for command results                             | `false`       | -       |     -     |
| `log_format_json`     | `--log-format-json`     |          -           | -                     | Enable JSON output for logs displayed according to verbosity level | `false`       | -       |     -     |
| `log_output`          | `--log-output`          |          -           | -                     | Redirect the logs to a file                                        | -             | -       |     -     |
| `unstable`            | `--unstable`            |          -           | -                     | Enable unstable commands                                           | `false`       | -       |     -     |
| `origin_tag`          | `--origin-tag`          |          -           | -                     | Request origin tag                                                 | -             | -       |     -     |
| `era`                 | `--era`                 |          -           | -                     | Override the Mithril era                                           | -             | -       |     -     |
| `help`                | `--help`                |         `-h`         | -                     | Print help                                                         | -             | -       |     -     |

`cardano-stake-distribution download` command:

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                                                   | Default value | Example |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | --------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `unique_identifier`        | -                            |          -           | -                          | Hash or Epoch of the Cardano stake distribution artifact, or `latest` for the latest artifact | -             | -       | :heavy_check_mark: |
| `download_dir`             | `--download-dir`             |          -           | -                          | Directory where the Cardano stake distribution will be downloaded                             | -             | -       |         -          |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | `GENESIS_VERIFICATION_KEY` | Genesis verification key to check the certificate chain                                       | -             | -       | :heavy_check_mark: |
| `run_mode`                 | `--run-mode`                 |          -           | `RUN_MODE`                 | Run Mode                                                                                      | `dev`         | -       |         -          |
| `verbose`                  | `--verbose`                  |         `-v`         | -                          | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                               | `0`           | -       |         -          |
| `config_directory`         | `--config-directory`         |          -           | -                          | Directory where configuration file is located                                                 | `./config`    | -       |         -          |
| `aggregator_endpoint`      | `--aggregator-endpoint`      |          -           | `AGGREGATOR_ENDPOINT`      | Override configuration Aggregator endpoint URL                                                | -             | -       |         -          |
| `json`                     | `--json`                     |          -           | -                          | Enable JSON output for command results                                                        | `false`       | -       |         -          |
| `log_format_json`          | `--log-format-json`          |          -           | -                          | Enable JSON output for logs displayed according to verbosity level                            | `false`       | -       |         -          |
| `log_output`               | `--log-output`               |          -           | -                          | Redirect the logs to a file                                                                   | -             | -       |         -          |
| `unstable`                 | `--unstable`                 |          -           | -                          | Enable unstable commands                                                                      | `false`       | -       |         -          |
| `origin_tag`               | `--origin-tag`               |          -           | -                          | Request origin tag                                                                            | -             | -       |         -          |
| `era`                      | `--era`                      |          -           | -                          | Override the Mithril era                                                                      | -             | -       |         -          |
| `help`                     | `--help`                     |         `-h`         | -                          | Print help (see more with '--help')                                                           | -             | -       |         -          |

`tools utxo-hd snapshot-converter` command:

:::warning

This command is not compatible with **Linux ARM environments**.

:::

| Parameter              | Command line (long)      | Command line (short) | Environment variable  | Description                                                                                                                                             | Default value | Example |     Mandatory      |
| ---------------------- | ------------------------ | :------------------: | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `db_directory`         | `--db-directory`         |          -           | -                     | Path to the Cardano node database directory                                                                                                             | -             | -       | :heavy_check_mark: |
| `cardano_node_version` | `--cardano-node-version` |          -           | -                     | Cardano node version of the Mithril signed snapshot (`latest` and `pre-release` are also supported to download the latest or pre-release distribution). | -             | -       | :heavy_check_mark: |
| `cardano_network`      | `--cardano-network`      |          -           | -                     | Cardano network                                                                                                                                         | -             | -       |         -          |
| `binary-path`          | `--binary-path`          |          -           | -                     | Path to the Cardano snapshot converter binary                                                                                                           | -             | -       |         -          |
| `config-path`          | `--config-path`          |          -           | -                     | Path to JSON configuration file for the Cardano snapshot converter                                                                                      | -             | -       |         -          |
| `utxo_hd_flavor`       | `--utxo-hd-flavor`       |          -           | -                     | UTxO-HD flavor to convert the ledger snapshot to (`Legacy`, `LMDB` or `LSM`)                                                                            | -             | -       | :heavy_check_mark: |
| `commit`               | `--commit`               |          -           | -                     | Replaces the current ledger state in the `db_directory`.                                                                                                | `false`       | -       |         -          |
| `github_token`         | `--github-token`         |          -           | `GITHUB_TOKEN`        | GitHub token for authenticated API calls                                                                                                                | -             | -       |         -          |
| `run_mode`             | `--run-mode`             |          -           | `RUN_MODE`            | Run Mode                                                                                                                                                | `dev`         | -       |         -          |
| `verbose`              | `--verbose`              |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)                                                                                         | `0`           | -       |         -          |
| `config_directory`     | `--config-directory`     |          -           | -                     | Directory where configuration file is located                                                                                                           | `./config`    | -       |         -          |
| `aggregator_endpoint`  | `--aggregator-endpoint`  |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                                                                                                          | -             | -       |         -          |
| `json`                 | `--json`                 |          -           | -                     | Enable JSON output for command results                                                                                                                  | `false`       | -       |         -          |
| `log_format_json`      | `--log-format-json`      |          -           | -                     | Enable JSON output for logs displayed according to verbosity level                                                                                      | `false`       | -       |         -          |
| `log_output`           | `--log-output`           |          -           | -                     | Redirect the logs to a file                                                                                                                             | -             | -       |         -          |
| `unstable`             | `--unstable`             |          -           | -                     | Enable unstable commands                                                                                                                                | `false`       | -       |         -          |
| `origin_tag`           | `--origin-tag`           |          -           | -                     | Request origin tag                                                                                                                                      | -             | -       |         -          |
| `era`                  | `--era`                  |          -           | -                     | Override the Mithril era                                                                                                                                | -             | -       |         -          |
| `help`                 | `--help`                 |         `-h`         | -                     | Print help (see more with '--help')                                                                                                                     | -             | -       |         -          |

`mithril-client tools discover-aggregator` command:

:::warning

This command is unstable.

:::

| Parameter                   | Command line (long)           | Command line (short) | Environment variable  | Description                                                        | Default value | Example |     Mandatory      |
| --------------------------- | ----------------------------- | :------------------: | --------------------- | ------------------------------------------------------------------ | ------------- | ------- | :----------------: |
| `network`                   | -                             |          -           | -                     | Mithril network name                                               | -             | -       | :heavy_check_mark: |
| `max_entries`               | `--max-entries`               |          -           | -                     | Maximum number of entries to retrieve                              | `1`           | -       |         -          |
| `signed_entity_types`       | `--signed-entity-types`       |          -           | -                     | Signed entity types to consider for the discovery                  | -             | -       |         -          |
| `aggregate_signature_types` | `--aggregate-signature-types` |          -           | -                     | Aggregate signature types to consider for the discovery            | -             | -       |         -          |
| `run_mode`                  | `--run-mode`                  |          -           | `RUN_MODE`            | Run Mode                                                           | `dev`         | -       |         -          |
| `verbose`                   | `--verbose`                   |         `-v`         | -                     | Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)    | `0`           | -       |         -          |
| `config_directory`          | `--config-directory`          |          -           | -                     | Directory where configuration file is located                      | `./config`    | -       |         -          |
| `aggregator_endpoint`       | `--aggregator-endpoint`       |          -           | `AGGREGATOR_ENDPOINT` | Override configuration Aggregator endpoint URL                     | -             | -       |         -          |
| `json`                      | `--json`                      |          -           | -                     | Enable JSON output for command results                             | `false`       | -       |         -          |
| `log_format_json`           | `--log-format-json`           |          -           | -                     | Enable JSON output for logs displayed according to verbosity level | `false`       | -       |         -          |
| `log_output`                | `--log-output`                |          -           | -                     | Redirect the logs to a file                                        | -             | -       |         -          |
| `unstable`                  | `--unstable`                  |          -           | -                     | Enable unstable commands                                           | `false`       | -       |         -          |
| `origin_tag`                | `--origin-tag`                |          -           | -                     | Request origin tag                                                 | -             | -       |         -          |
| `era`                       | `--era`                       |          -           | -                     | Override the Mithril era                                           | -             | -       |         -          |
| `help`                      | `--help`                      |         `-h`         | -                     | Print help (see more with '--help')                                | -             | -       |         -          |
