---
sidebar_position: 2
---

import CompiledBinaries from '../../../compiled-binaries.mdx'

# Mithril signer node

:::info

Mithril signer is responsible for producing individual signatures that are collected and aggregated by the **Mithril aggregator**.

:::

:::tip

- For more information about the **Mithril network**, please see the [architecture](../../../mithril/advanced/mithril-network/architecture.md) overview

- For more information about the **Mithril signer** node, please see [this overview](../../../mithril/advanced/mithril-network/signer.md)

- Check out the [`Run a Mithril signer node`](../../operate/run-signer-node.md) guide.

:::

:::info

The Mithril network configurations are available in the [**Network configurations**](../../getting-started/network-configurations.md) section of the user manual.

:::

## Resources

|        Node        |                                    Source repository                                    |                                Rust documentation                                 |                                       Docker packages                                        |                         Network configurations                         |
| :----------------: | :-------------------------------------------------------------------------------------: | :-------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------: |
| **Mithril signer** | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/tree/main/mithril-signer) | [:arrow_upper_right:](https://mithril.network/rust-doc/mithril_signer/index.html) | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/pkgs/container/mithril-signer) | [:arrow_upper_right:](../../getting-started/network-configurations.md) |

## Prerequisites

- Install the latest stable version of the [correctly configured](https://www.rust-lang.org/learn/get-started) Rust toolchain

- Install build tools `build-essential` and `m4`; for example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`

- Install OpenSSL development libraries; for example, on Ubuntu/Debian/Mint, run `apt install libssl-dev`.

## Download the source file

You can download the source file from GitHub (HTTPS):

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

```bash
cd mithril/mithril-signer
```

## Development testing and building

Run tests:

```bash
make test
```

Create the help menu:

```bash
make help
```

Generate the Rust documentation:

```bash
make doc
```

Run in debug mode with the default configuration:

```bash
make debug
```

## Building for release and running the binary

To build and run in release mode with the default configuration:

```bash
make run
```

Or, you can build only in release mode:

```bash
make build
```

Display the help menu:

```bash
./mithril-signer --help
```

You should see:

```bash
An implementation of a Mithril signer

Usage: mithril-signer [OPTIONS]

Options:
  -r, --run-mode <RUN_MODE>
          Run Mode

          [env: RUN_MODE=]
          [default: dev]

  -v, --verbose...
          Verbosity level, add more v to increase

  -c, --configuration-dir <CONFIGURATION_DIR>
          Directory where the configuration file is located

          [default: ./config]

      --disable-digests-cache
          Disable immutables digests cache

      --reset-digests-cache
          If set the existing immutables digests cache will be reset.

          Will be ignored if set in conjunction with `--disable-digests-cache`.

      --enable-metrics-server
          Enable metrics HTTP server (Prometheus endpoint on /metrics)

          [env: ENABLE_METRICS_SERVER=]

      --metrics-server-ip <METRICS_SERVER_IP>
          Metrics HTTP server IP

          [env: METRICS_SERVER_IP=]
          [default: 0.0.0.0]

      --metrics-server-port <METRICS_SERVER_PORT>
          Metrics HTTP server listening port

          [env: METRICS_SERVER_PORT=]
          [default: 9090]

      --allow-unparsable-block
          If set no error is returned in case of unparsable block and an error log is written instead.

          Will be ignored on (pre)production networks.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Run in release mode with the default configuration:

```bash
./mithril-signer
```

Run in release mode using a specific mode:

```bash
./mithril-signer -r preview
```

Run in release mode with a custom configuration using environment variables:

```bash
NETWORK=**YOUR_CARDANO_NETWORK** AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT** ./mithril-signer
```

:::tip

If you wish to delve deeper and access several levels of logs from the Mithril signer, use the following:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

## Download the pre-built binary

<CompiledBinaries  node="mithril-signer"/>

## Configuration parameters

The configuration parameters can be set in either of the following ways:

1. In a configuration file, depending on the `--run-mode` parameter. If the runtime mode is `testnet`, the file is located in `./conf/testnet.json`.
2. The value can be overridden by an environment variable with the parameter name in uppercase.

Here is a list of the available parameters:

| Parameter                                                        | Command line (long)                        | Command line (short) | Environment variable                                             | Description                                                                                                                                                                                      | Default value | Example                                                                                                                 |                                                                                     Mandatory                                                                                     |
| ---------------------------------------------------------------- | ------------------------------------------ | :------------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- | ----------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| `verbose`                                                        | `--verbose`                                |         `-v`         | `VERBOSE`                                                        | Verbosity level                                                                                                                                                                                  | -             | Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace` |                                                                                :heavy_check_mark:                                                                                 |
| `run_mode`                                                       | `--run-mode`                               |         `-r`         | `RUN_MODE`                                                       | Runtime mode                                                                                                                                                                                     | `dev`         | -                                                                                                                       |                                                                                :heavy_check_mark:                                                                                 |
| `cardano_cli_path`                                               | -                                          |          -           | `CARDANO_CLI_PATH`                                               | Cardano CLI tool path                                                                                                                                                                            | -             | `cardano-cli`                                                                                                           |                                                                                :heavy_check_mark:                                                                                 |
| `cardano_node_socket_path`                                       | -                                          |          -           | `CARDANO_NODE_SOCKET_PATH`                                       | Path of the socket opened by the Cardano node                                                                                                                                                    | -             | `/ipc/node.socket`                                                                                                      |                                                                                :heavy_check_mark:                                                                                 |
| `db_directory`                                                   | `--db-directory`                           |          -           | `DB_DIRECTORY`                                                   | Directory to snapshot from the **Cardano node**                                                                                                                                                  | `/db`         | -                                                                                                                       |                                                                                :heavy_check_mark:                                                                                 |
| `network`                                                        | -                                          |          -           | `NETWORK`                                                        | Cardano network                                                                                                                                                                                  | -             | `mainnet` or `preprod` or `devnet`                                                                                      |                                                                                :heavy_check_mark:                                                                                 |
| `network_magic`                                                  | -                                          |          -           | `NETWORK_MAGIC`                                                  | Cardano network magic number (for `testnet` and `devnet`)                                                                                                                                        | -             | `1097911063` or `42`                                                                                                    |                                                                                         -                                                                                         |
| `party_id`                                                       | -                                          |          -           | `PARTY_ID`                                                       | Party Id of the signer, usually the `Pool Id` of the SPO                                                                                                                                         | -             | `pool1pxaqe80sqpde7902er5kf6v0c7y0sv6d5g676766v2h829fvs3x`                                                              | Mandatory in `pool Id declaration mode` where the owner is not verified (decommissioned, only available when built with `allow_skip_signer_certification` feature, for test only) |
| `run_interval`                                                   | -                                          |          -           | `RUN_INTERVAL`                                                   | Interval between two runtime cycles in ms                                                                                                                                                        | -             | `60000`                                                                                                                 |                                                                                :heavy_check_mark:                                                                                 |
| `aggregator_endpoint`                                            | -                                          |          -           | `AGGREGATOR_ENDPOINT`                                            | Aggregator node endpoint                                                                                                                                                                         | -             | `https://aggregator.pre-release-preview.api.mithril.network/aggregator`                                                 |                                                                                :heavy_check_mark:                                                                                 |
| `data_stores_directory`                                          | -                                          |          -           | `DATA_STORES_DIRECTORY`                                          | Directory to store signer data (stake, protocol initializers, ...)                                                                                                                               | -             | `./mithril-signer/stores`                                                                                               |                                                                                :heavy_check_mark:                                                                                 |
| `store_retention_limit`                                          | -                                          |          -           | `STORE_RETENTION_LIMIT`                                          | Maximum number of records in stores. If not set, no limit is set.                                                                                                                                | -             | -                                                                                                                       |                                                                                         -                                                                                         |
| `kes_secret_key_path`                                            | -                                          |          -           | `KES_SECRET_KEY_PATH`                                            | Path to the `Cardano KES secret key` file. Mandatory in `Pool Id certification mode` where the owner is verified (experimental, soon to be stable & preferred mode)                              | -             | -                                                                                                                       |                                                                                         -                                                                                         |
| `operational_certificate_path`                                   | -                                          |          -           | `OPERATIONAL_CERTIFICATE_PATH`                                   | Path to the `Cardano operational certificate` file. Mandatory in `Pool Id certification mode` where the owner is verified (experimental, soon to be stable & preferred mode)                     | -             | -                                                                                                                       |                                                                                         -                                                                                         |
| `era_reader_adapter_type`                                        | `--era-reader-adapter-type`                |          -           | `ERA_READER_ADAPTER_TYPE`                                        | Era reader adapter type that can be `cardano-chain`, `file` or `bootstrap`.                                                                                                                      | `bootstrap`   | -                                                                                                                       |                                                                                         -                                                                                         |
| `era_reader_adapter_params`                                      | `--era-reader-adapter-params`              |          -           | `ERA_READER_ADAPTER_PARAMS`                                      | Era reader adapter params that is an optional JSON encoded parameters structure that is expected depending on the `era_reader_adapter_type` parameter                                            | -             | -                                                                                                                       |                                                                                         -                                                                                         |
| `enable_metrics_server`                                          | `--enable-metrics-server`                  |          -           | `ENABLE_METRICS_SERVER`                                          | Enable metrics HTTP server (Prometheus endpoint on /metrics)                                                                                                                                     | `false`       | -                                                                                                                       |                                                                                         -                                                                                         |
| `metrics_server_ip`                                              | `--metrics-server-ip`                      |          -           | `METRICS_SERVER_IP`                                              | Metrics HTTP server IP                                                                                                                                                                           | `0.0.0.0`     | -                                                                                                                       |                                                                                         -                                                                                         |
| `metrics_server_port`                                            | `--metrics-server-port`                    |          -           | `METRICS_SERVER_PORT`                                            | Metrics HTTP server listening port                                                                                                                                                               | `9090`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `allow_unparsable_block`                                         | `--allow-unparsable-block`                 |          -           | `ALLOW_UNPARSABLE_BLOCK`                                         | If set no error is returned in case of unparsable block and an error log is written instead. Will be ignored on (pre)production networks.                                                        | `false`       | -                                                                                                                       |                                                                                         -                                                                                         |
| `enable_transaction_pruning`                                     | -                                          |          -           | `ENABLE_TRANSACTION_PRUNING`                                     | If set, the signer will prune the cardano transactions in database older than the [network_security_parameter]                                                                                   |
| `network_security_parameter`                                     | -                                          |          -           | `NETWORK_SECURITY_PARAMETER`                                     | Also known as `k`, it defines the number of blocks that are required for the blockchain to be considered final, preventing any further rollback `[default: 2160]`.                               | `2160`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `preload_security_parameter`                                     | -                                          |          -           | `PRELOAD_SECURITY_PARAMETER`                                     | Blocks offset, from the tip of the chain, to exclude during the cardano transactions preload `[default: 3000]`.                                                                                  | `3000`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `transactions_import_block_chunk_size`                           | -                                          |          -           | `TRANSACTIONS_IMPORT_BLOCK_CHUNK_SIZE`                           | Chunk size for importing transactions, combined with transaction pruning it reduces the storage footprint of the signer by reducing the number of transactions stored on disk at any given time. | `1500`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `cardano_transactions_block_streamer_max_roll_forwards_per_poll` | -                                          |          -           | `CARDANO_TRANSACTIONS_BLOCK_STREAMER_MAX_ROLL_FORWARDS_PER_POLL` | The maximum number of roll forwards during a poll of the block streamer when importing transactions.                                                                                             | `1000`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `preloading_refresh_interval_in_seconds`                         | `--preloading-refresh-interval-in-seconds` |          -           | `PRELOADING_REFRESH_INTERVAL_IN_SECONDS`                         | The preloading refresh interval in seconds.                                                                                                                                                      | `7200`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `signature_publisher_retry_attempts`                             | `--signature-publisher-retry-attempts`     |          -           | `SIGNATURE_PUBLISHER_RETRY_ATTEMPTS`                             | Number of retry attempts when publishing the signature.                                                                                                                                          | `3`           | -                                                                                                                       |                                                                                         -                                                                                         |
| `signature_publisher_retry_delay_ms`                             | `--signature-publisher-retry-delay-ms`     |          -           | `SIGNATURE_PUBLISHER_RETRY_DELAY_MS`                             | Delay (in milliseconds) between two retry attempts when publishing the signature.                                                                                                                | `2000`        | -                                                                                                                       |                                                                                         -                                                                                         |
| `signature_publisher_delayer_delay_ms`                           | `--signature-publisher-delayer-delay-ms`   |          -           | `SIGNATURE_PUBLISHER_DELAYER_DELAY_MS`                           | Delay (in milliseconds) between two separate publications done by the delayer signature publisher.                                                                                               | `10000`       | -                                                                                                                       |                                                                                         -                                                                                         |
