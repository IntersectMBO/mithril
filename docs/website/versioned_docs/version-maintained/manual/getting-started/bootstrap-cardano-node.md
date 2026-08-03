---
sidebar_position: 3
---

import CompiledBinaries from '../../compiled-binaries.mdx'

# Bootstrap a Cardano node

:::info

With the **Mithril client** connected to a **Mithril aggregator**, you can restore a full Cardano node on the `mainnet` in less than **20 minutes**!

:::

## Set up the environment

Before proceeding with the installation, ensure that you have the following prerequisites in place:

1. **Install a [correctly configured](https://www.rust-lang.org/learn/get-started) Rust toolchain**: make sure you have the latest stable version of Rust installed.

2. **Install build tools `build-essential` and `m4`**: on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`.

3. **Install OpenSSL development libraries**: on Ubuntu/Debian/Mint, run the following command to install the required OpenSSL development libraries:

```
sudo apt install libssl-dev
```

3. **Install other requirements**: make sure you have all the additional dependencies and requirements specified for the project:

```bash
sudo apt-get install make build-essential m4 docker jq
```

## Download the source file

You can download the source file from GitHub (HTTPS):

```bash
git clone https://github.com/IntersectMBO/mithril.git
```

Or (SSH):

```bash
git clone git@github.com:IntersectMBO/mithril.git
```

## Build the Mithril client binary

To build the Mithril client binary, switch to the desired branch/tag:

```bash
# Replace **YOUR_BUILD_BRANCH_OR_TAG** with the appropriate branch or tag name
# Please refer to the [**Network configurations**](http://mithril.network/manual/getting-started/network-configurations) section of the user manual
git checkout **YOUR_BUILD_BRANCH_OR_TAG**
```

Change the directory:

```bash
cd mithril/mithril-client-cli
```

Run tests (optional):

```bash
make test
```

Build the executable:

```bash
make build
```

## Verify the binary

### Verify the version

To check if the version of the Mithril signer binary is correct, use the following command:

```bash
./mithril-client -V
```

You should see something like:

```bash
mithril-client 0.7.6
```

:warning: Verify that the version displayed corresponds to the version specified in the content of the release/pre-release notes (refer to the **Build from** column in the 'Mithril networks' section).

### Verify the build

To verify that the Mithril client binary is functioning correctly, run the following command to display its help menu:

```bash
./mithril-client -h
```

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

:::tip

To display results in JSON format for the `list` and `show` commands of the Mithril client, you can use the `--json` option:

```bash
./mithril-client cardano-db snapshot list --json
```

:::

:::tip

If you wish to delve deeper and access several levels of logs from the Mithril client, you can use the following:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

## Download the pre-built binary

<CompiledBinaries  node="mithril-client"/>

## Run the Docker container

The list of available images on the registry is listed [here](https://github.com/IntersectMBO/mithril/pkgs/container/mithril-client).

Prepare an environment variable with the selected Docker image:

```bash
export MITHRIL_IMAGE_ID=**YOUR_MITHRIL_IMAGE_ID**
```

Here is an example configuration for the `latest` stable Docker image:

```bash
export MITHRIL_IMAGE_ID=latest
```

Then, create a shell function for the Mithril client:

```bash
mithril_client () {
  docker run --rm -e GENESIS_VERIFICATION_KEY=$GENESIS_VERIFICATION_KEY -e AGGREGATOR_ENDPOINT=$AGGREGATOR_ENDPOINT --name='mithril-client' -v $(pwd):/app/data -w /app/data -u $(id -u) ghcr.io/intersectmbo/mithril-client:$MITHRIL_IMAGE_ID $@
}
```

You can now use the `mithril_client` function:

```bash
# 1- Help
mithril_client help

# 2- List snapshots
mithril_client cardano-db snapshot list
```

:::tip

In the following part of the document, you will need to replace the `./mithril-client` commands with `mithril_client` to use the above shell function.

:::

## MSYS2 Windows build

To build the `mithril-client` executable on MSYS2 (see
[MSYS2's webpage](https://www.msys2.org/) for installation instructions), the
following packages have to be installed:

```bash
pacman --noconfirm -S base-devel mingw-w64-<env>-x86_64-toolchain mingw-w64-<env>-x86_64-openssl
```

Where `env` has to be replaced with your particular
[environment](https://www.msys2.org/docs/environments/) of choice, for example,
`ucrt` if running in the `UCRT64` environment. Use `pacman -Ss <package name>`
to search for packages if unsure.

:::note

If you encounter the following error:

```
    This perl implementation doesn't produce Unix like paths (with forward slash
    directory separators). Please use an implementation that matches your
    building platform.
```

make sure that the `perl` in `/usr/bin/perl.exe` (from the `perl` package) comes
before the `perl` in `/<env>/bin/perl.exe` (from the
`mingw-w64-<env>-x86_64-perl` package).

:::

From here, you have to run the `rustup-init.exe` binary from
[rustup](https://rustup.rs/) and follow along these steps:

```bash
Rust Visual C++ prerequisites

Rust requires a linker and Windows API libraries, but they don't seem to be
available.

These components can be acquired through a Visual Studio installer.

1) Quick install via the Visual Studio Community installer
   (free for individuals, academic uses, and open source).

2) Manually install the prerequisites
   (for enterprise and advanced users).

3) Don't install the prerequisites
   (if you're targeting the GNU ABI).

>3


Welcome to Rust!

This will download and install the official compiler for the Rust
programming language, and its package manager, Cargo.

Rustup metadata and toolchains will be installed into the Rustup
home directory, located at:

  C:\Users\<User>\.rustup

This can be modified with the RUSTUP_HOME environment variable.

The Cargo home directory is located at:

  C:\Users\<User>\.cargo

This can be modified with the CARGO_HOME environment variable.

The cargo, rustc, rustup and other commands will be added to
Cargo's bin directory, located at:

  C:\Users\<User>\.cargo\bin

This path will then be added to your PATH environment variable by
modifying the HKEY_CURRENT_USER/Environment/PATH registry key.

You can uninstall at any time with rustup self uninstall and
these changes will be reverted.

Current installation options:


   default host triple: x86_64-pc-windows-msvc
     default toolchain: stable (default)
               profile: default
  modify PATH variable: yes

1) Proceed with standard installation (default - just press enter)
2) Customize installation
3) Cancel installation
>2

I'm going to ask you about the value of each of these installation options.
You may simply press the Enter key to leave unchanged.

Default host triple? [x86_64-pc-windows-msvc]
x86_64-pc-windows-gnu

Default toolchain? (stable/beta/nightly/none) [stable]


Profile (which tools and data to install)? (minimal/default/complete) [default]


Modify PATH variable? (Y/n)



Current installation options:


   default host triple: x86_64-pc-windows-gnu
     default toolchain: stable
               profile: default
  modify PATH variable: yes

1) Proceed with selected options (default - just press enter)
2) Customize installation
3) Cancel installation
>1
```

Once the Rust toolchain is installed, one can build the executable normally:

```bash
cd mithril-client-cli
make build
```

This will produce a binary `mithril-client.exe` on the current directory. It can
be invoked the same way as in Linux, with `./mithril-client`.

## Bootstrap a Cardano node from a testnet Mithril Cardano DB snapshot

### Step 1: Prepare some useful variables

```bash
# Cardano network
export CARDANO_NETWORK=**YOUR_CARDANO_NETWORK**

# Aggregator API endpoint URL
export AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**

# Genesis verification key
export GENESIS_VERIFICATION_KEY=$(wget -q -O - **YOUR_GENESIS_VERIFICATION_KEY**)

# Ancillary verification key
export ANCILLARY_VERIFICATION_KEY=$(wget -q -O - **YOUR_ANCILLARY_VERIFICATION_KEY**)

# Digest of the latest produced cardano db snapshot for convenience of the demo
# You can also modify this variable and set it to the value of the digest of a snapshot that you can retrieve at step 2
export SNAPSHOT_DIGEST=latest
```

:::tip

In the following commands, we will use the following environment variables:

```bash
# Cardano network
export CARDANO_NETWORK=preview

# Aggregator API endpoint URL
export AGGREGATOR_ENDPOINT=https://aggregator.pre-release-preview.api.mithril.network/aggregator

# Genesis verification key
export GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/genesis.vkey)

# Ancillary verification key
export ANCILLARY_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/ancillary.vkey)

# Digest of the latest produced cardano db snapshot for convenience of the demo
export SNAPSHOT_DIGEST=latest
```

:::

### Step 2: Select a Cardano DB snapshot

List the available Cardano db snapshots with which you can bootstrap a Cardano node:

```bash
./mithril-client cardano-db snapshot list
```

You will see a list of snapshots:

```bash
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
| Epoch | Immutable | Network | Digest                                                           |     Size | Locations |                           Created |
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
| 916   | 18323     | preview | a1b5e6f43521fd9c5f55e3d6bf27dc4a62f43980681cb67e28cc40582a0d1974 | 3.14 GiB | 1         | 2025-04-28 08:40:34.353548187 UTC |
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
| 916   | 18322     | preview | 1d5172a41f400a61cb7504a6f83f5c40b0f24908aa116bfe150652ccf17ae21d | 3.13 GiB | 1         | 2025-04-28 07:22:51.737425114 UTC |
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
| 916   | 18321     | preview | 9cd5131547a7ee1e70bbeb2bb3172392aa4f92748664294619f9a65c41fcb6d1 | 3.13 GiB | 1         | 2025-04-28 06:26:46.276160645 UTC |
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
| 916   | 18320     | preview | 550bc24850f69117e2adb6974d910bf9ec97c6ac322e6eac5d5012502e8eb05f | 3.13 GiB | 1         | 2025-04-28 05:18:16.835951479 UTC |
+-------+-----------+---------+------------------------------------------------------------------+----------+-----------+-----------------------------------+
…
```

:::warning

If you restore a Cardano node with a version not included in the [advertised range of compatible versions](network-configurations.md), it may take extra time due to ledger computations or even crash the node.

:::

### Step 3: Show Cardano DB snapshot details

To get more details from a specific snapshot (optional), run:

```bash
./mithril-client cardano-db snapshot show $SNAPSHOT_DIGEST
```

You will see more information about the snapshot:

```bash
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Epoch                 | 916                                                                                                                                                                                                             |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Immutable File Number | 18323                                                                                                                                                                                                           |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Network               | preview                                                                                                                                                                                                         |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Digest                | a1b5e6f43521fd9c5f55e3d6bf27dc4a62f43980681cb67e28cc40582a0d1974                                                                                                                                                |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Size                  | 3.14 GiB                                                                                                                                                                                                        |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Cardano node version  | 11.0.1                                                                                                                                                                                                          |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Location              | https://storage.googleapis.com/cdn.aggregator.pre-release-preview.api.mithril.network/cardano-immutable-files-full/preview-e916-i18323.a1b5e6f43521fd9c5f55e3d6bf27dc4a62f43980681cb67e28cc40582a0d1974.tar.zst |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Created               | 2025-04-28 08:40:34.353548187 UTC                                                                                                                                                                               |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Compression Algorithm | Zstandard                                                                                                                                                                                                       |
+-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

### Step 4: Download the selected Cardano DB snapshot

To download the selected snapshot from the remote location to your remote location, run:

```bash
./mithril-client cardano-db download --include-ancillary $SNAPSHOT_DIGEST
```

:::warning

To enable fast boostrap, ancillary files must be downloaded by using the `--include-ancillary` option.

Ancillary files contain files that can't be currently signed by the Mithril protocol: the last ledger state snapshot
and the last immutable file.

For additional security, ancillary files are signed using `Ed25519` and the signature is checked against the provided
`ANCILLARY_VERIFICATION_KEY`.

:::

You will see that the selected snapshot archive has been downloaded locally unpacked and that the associated certificate is valid:

```bash
1/7 - Checking local disk info…
2/7 - Fetching the certificate and verifying the certificate chain…
  Certificate chain validated
3/7 - Downloading and unpacking the cardano db snapshot
   [00:19:21] [###########################################################################################################] Files: 24,348/24,348 (0.0s)
   [00:00:01] [###########################################################################################] 165.88 MiB/165.88 MiB (0.0s)
4/7 - Downloading and verifying digests…
5/7 - Verifying the cardano database
6/7 - Computing the cardano db snapshot message
7/7 - Verifying the cardano db signature
Cardano database snapshot '188f65fc7d3bbf30a59ab05ce4ec6649cec96a1b51b909ca0d1702555e8605d0' archives have been successfully unpacked. Immutable files have been successfully verified with Mithril.

    Files in the directory 'db' can be used to run a Cardano node with version >= 11.0.1.

    If you are using the Cardano Docker image, you can restore a Cardano node with:

    docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="/home/mithril/data/testnet/a1b5e6f43521fd9c5f55e3d6bf27dc4a62f43980681cb67e28cc40582a0d1974/db",target=/data/db/ -e NETWORK=preview ghcr.io/intersectmbo/cardano-node:11.0.1


Upgrade and replace the restored ledger state snapshot to 'LMDB' flavor by running the command:

    mithril-client tools utxo-hd snapshot-converter --db-directory db --cardano-node-version 11.0.1 --utxo-hd-flavor LMDB --commit
```

### Step 5 (optional): Convert the ledger state snapshot to another flavor

After restoring a snapshot with the `--include-ancillary` option, the ledger state is in the `InMemory` format. You can convert it to another UTxO-HD flavor (e.g., `LMDB` or `Legacy`) using the Mithril client `tools utxo-hd snapshot-converter` command.

To do so, run the following command:

```
mithril-client tools utxo-hd snapshot-converter --db-directory db --cardano-node-version latest --utxo-hd-flavor LMDB
```

Or, to convert it to the `Legacy` flavor:

```
mithril-client tools utxo-hd snapshot-converter --db-directory db --cardano-node-version latest --utxo-hd-flavor Legacy
```

Use the `--commit` option to replace the current ledger state with the converted snapshot.

You can also replace `latest` with a specific Cardano node version tag which will be used to download the corresponding Cardano node distribution and extract the `snapshot-converter` binary tool.

### Step 6: Launch a Cardano node from the restored Cardano DB snapshot

Launch an empty Cardano node and make it live in minutes!

```bash
docker run -v cardano-node-ipc:/ipc -v cardano-node-data:/data --mount type=bind,source="$(pwd)/data/testnet/$SNAPSHOT_DIGEST/db",target=/data/db/ -e NETWORK=$CARDANO_NETWORK ghcr.io/intersectmbo/cardano-node:11.0.1
```

You will see the Cardano node start by validating the files ingested from the snapshot archive. Then, it will synchronize with the other network nodes and start adding blocks:

```bash
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:53:40.06 UTC] Chain extended, new tip: 7ae33b2f4bc8b84e77dfd539f0f6e7f59b293e96f62fdcfdb17cbd7a006fe5c0 at slot 63081906
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:55:08.30 UTC] Chain extended, new tip: 6b4ccd2bec5e3862b23ea0f7c2f342a3659cecdcfdaf04551179df3839be6213 at slot 63092090
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:55:21.36 UTC] Chain extended, new tip: 6e95eb82da5a38544e6ef430a2733f6014c3c10527003b9d3bdc534f6a2ce81f at slot 63092103
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:55:39.04 UTC] Chain extended, new tip: a662672ec4b988022e135cb0b7e440f5fbffe8e205771d13a566a418f7021ba7 at slot 63092121
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:55:45.18 UTC] Chain extended, new tip: 2a0f2e6f218a08f4e0bc4668285d8e792fd7ec62f05880bd5b2d23d6bce20dfb at slot 63092127
[c995d1df:cardano.node.ChainDB:Notice:322] [2022-07-10 13:56:18.05 UTC] Chain extended, new tip: ab9ef8af92ec062ec59a10da588e238ba8840705c095ebd5cd5da7ab9ea9c8e1 at slot 63092160
```
