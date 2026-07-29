---
sidebar_position: 1
---

import CompiledBinaries from '../../../compiled-binaries.mdx'

# Mithril aggregator node

:::info

Mithril aggregator is responsible for collecting individual signatures from the Mithril signers and aggregating them into a multi-signature. With this capability, the Mithril aggregator can provide certified snapshots of the Cardano blockchain.

:::

:::tip

- For more information about the **Mithril network**, please see the [architecture](../../../mithril/advanced/mithril-network/architecture.md) overview

- For more information about the **Mithril aggregator**, please see the [aggregator node](../../../mithril/advanced/mithril-network/aggregator.md) overview.

:::

:::info

The Mithril network configurations are available in the [**Network configurations**](../../getting-started/network-configurations.md) section of the user manual.

:::

## Resources

|          Node          |                                      Source repository                                      |                                  Rust documentation                                   |                                         Docker packages                                          |                                                                REST API                                                                |                         Network configurations                         |
| :--------------------: | :-----------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------: |
| **Mithril aggregator** | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/tree/main/mithril-aggregator) | [:arrow_upper_right:](https://mithril.network/rust-doc/mithril_aggregator/index.html) | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/pkgs/container/mithril-aggregator) | [current&nbsp;:arrow_upper_right:](/doc/aggregator-api/current)<br />[next&nbsp;🚧&nbsp;:arrow_upper_right:](/doc/aggregator-api/next) | [:arrow_upper_right:](../../getting-started/network-configurations.md) |

## Prerequisites

- Install the latest stable version of the [correctly configured](https://www.rust-lang.org/learn/get-started) Rust toolchain

- Install build tools `build-essential` and `m4`; for example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`

- Install OpenSSL development libraries; for example, on Ubuntu/Debian/Mint, run `apt install libssl-dev`.

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

```bash
cd mithril/mithril-aggregator
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

To run in debug mode with the default configuration, use the following command:

```bash
make debug
```

## Building for release and running the binary 'serve' command

To build and run in release mode with the default configuration:

```bash
make run
```

Or, build only in release mode:

```bash
make build
```

Display the help menu:

```bash
./mithril-aggregator --help
```

You should see:

```bash
Mithril aggregator node

Usage: mithril-aggregator [OPTIONS] <COMMAND>

Commands:
  genesis   Genesis tools
  era       Era tools
  serve     Server runtime mode
  tools     List of tools to upkeep the aggregator
  database  Database tools
  help      Print this message or the help of the given subcommand(s)

Options:
  -r, --run-mode <RUN_MODE>
          Run Mode [default: dev]
  -v, --verbose...
          Verbosity level
      --db-directory <DB_DIRECTORY>
          Directory of the Cardano node files
      --config-directory <CONFIG_DIRECTORY>
          Directory where configuration file is located [default: ./config]
  -h, --help
          Print help
  -V, --version
          Print version
```

Run the 'serve' command in release mode with the default configuration:

```bash
./mithril-aggregator serve
```

Run the 'serve' command in release with a specific mode:

```bash
./mithril-aggregator -r preview serve
```

Run the 'serve' command in release mode with a custom configuration using environment variables:

```bash
GENESIS_VERIFICATION_KEY=$(wget -q -O - **YOUR_GENESIS_VERIFICATION_KEY**) RUN_INTERVAL=60000 NETWORK=**YOUR_CARDANO_NETWORK** ./mithril-aggregator serve
```

## Building for release and running the binary 'genesis' command

Build in release mode with the default configuration:

```bash
make build
```

Display the help menu:

```bash
./mithril-aggregator genesis --help
```

You should see:

```bash
Genesis tools

Usage: mithril-aggregator genesis <COMMAND>

Commands:
  export            Genesis certificate export command
  import            Genesis certificate import command
  sign              Genesis certificate sign command
  bootstrap         Genesis certificate bootstrap command
  generate-keypair  Genesis keypair generation command
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### Bootstrap sub-command (test-only)

You can run the 'genesis bootstrap' command in release mode with the default configuration, but **only in test mode**. This will enable the Mithril aggregator node to bootstrap a `genesis certificate`. After completing this operation, the Mithril aggregator will be able to produce new snapshots and certificates.

First, export the environment variables:

```bash
export NETWORK=**CARDANO_NETWORK**
export NETWORK_MAGIC=**NETWORK_MAGIC**
export DATA_STORES_DIRECTORY=**DATA_STORES_DIRECTORY**
export CARDANO_NODE_SOCKET_PATH=**CARDANO_NODE_SOCKET_PATH**
export CHAIN_OBSERVER_TYPE=**CHAIN_OBSERVER_TYPE**
```

Then, execute the following command:

```bash
./mithril-aggregator genesis bootstrap
```

You can use a specific `genesis secret key` (only in test mode):

```bash
./mithril-aggregator genesis bootstrap --genesis-secret-key **YOUR_SECRET_KEY*
```

### Export sub-command

You can run the 'genesis export' command in release mode. This allows the Mithril aggregator node to export the `genesis payload` that needs to be signed (and later reimported) for the `genesis certificate`. The signature of the `genesis payload` must be done manually by the owner of the `genesis secret key`.

First, export the environment variables:

```bash
export NETWORK=**CARDANO_NETWORK**
export NETWORK_MAGIC=**NETWORK_MAGIC**
export DATA_STORES_DIRECTORY=**DATA_STORES_DIRECTORY**
export CARDANO_NODE_SOCKET_PATH=**CARDANO_NODE_SOCKET_PATH**
export CHAIN_OBSERVER_TYPE=**CHAIN_OBSERVER_TYPE**
```

Then, execute the following command:

```bash
./mithril-aggregator genesis export --target-path **YOUR_TARGET_PATH**
```

### Sign sub-command

You can run the 'genesis sign' command in release mode. This allows the Mithril aggregator node to sign the `genesis payload` that needs to be reimported. The signature of the `genesis payload` must be done manually by the owner of the `genesis secret key`.

```bash
./mithril-aggregator genesis sign --to-sign-payload-path **TO_SIGN_PAYLOAD_PATH** --target-signed-payload-path **TARGET_SIGNED_PAYLOAD_PATH** --genesis-secret-key-path **GENESIS_SECRET_KEY_PATH**
```

### Import sub-command

Run the 'genesis import' command in release mode. This allows the aggregator node to import the signed payload of the `genesis certificate` and store it. After this operation, the aggregator will be able to produce new snapshots and certificates.

First, export the environment variables:

```bash
export NETWORK=**CARDANO_NETWORK**
export NETWORK_MAGIC=**NETWORK_MAGIC**
export DATA_STORES_DIRECTORY=**DATA_STORES_DIRECTORY**
export CARDANO_NODE_SOCKET_PATH=**CARDANO_NODE_SOCKET_PATH**
export CHAIN_OBSERVER_TYPE=**CHAIN_OBSERVER_TYPE**
```

Then, execute the following command:

```bash
./mithril-aggregator genesis import --signed-payload-path **YOUR_SIGNED_PAYLOAD_PATH** --genesis-verification-key **YOUR_GENESIS_VERIFICATION_KEY**
```

## Building for release and running the binary 'era' command

Build in release mode using the default configuration:

```bash
make build
```

Display the help menu:

```bash
./mithril-aggregator era --help
```

You should see:

```bash
Era tools

Usage: mithril-aggregator era <COMMAND>

Commands:
  list               Era list command
  generate-tx-datum  Era tx datum generate command
  generate-keypair   Era keypair generation command
  help               Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Run the 'era list' command to list the supported eras embedded in the binary:

```bash
./mithril-aggregator era list
```

You should see something like:

```bash
Supported Eras:
[
    Thales,
]
```

:::tip

To display results in `JSON` format for the `list` command, simply use the `--json` option:

```bash
./mithril-aggregator era list --json
```

You should see something like:

```bash
["thales"]
```

:::

You can run 'era generate-tx-datum' to create the transaction datum file that will be stored on the Cardano chain, providing era markers to the 'cardano-chain' era reader adapter.

**Case 1**: If there is only one supported era in the code, create the datum file:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch **EPOCH_AT_WHICH_CURRENT_ERA_STARTS** --era-markers-secret-key **YOUR_ERA_ACTIVATION_SECRET_KEY** --target-path **TARGET_PATH**
```

You should see something like:

```bash
{"constructor":0,"fields":[{"bytes":"5b7b226e223a227468616c6573222c2265223a317d5d"},{"bytes":"a58fe8e336f465ded3bba7c5a7afe5b5a26f2fb65b7c4e6e742e680645f13df28bf2b63a61cc72d9c826be490e2c1f1098d955df503580a4e899b5173884e30e"}]}
```

**Case 2**: If there are two supported eras in the code and the activation epoch of the upcoming era is not yet known, run the command:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch **EPOCH_AT_WHICH_CURRENT_ERA_STARTS** --era-markers-secret-key **YOUR_ERA_ACTIVATION_SECRET_KEY** --target-path **TARGET_PATH**
```

**Case 3**: If there are two supported eras in the code and the activation epoch of the era switch is known to be at the following epoch, run the command:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch **EPOCH_AT_WHICH_CURRENT_ERA_STARTS** --next-era-epoch **EPOCH_AT_WHICH_NEXT_ERA_STARTS** --era-markers-secret-key **YOUR_ERA_ACTIVATION_SECRET_KEY** --target-path **TARGET_PATH**
```

## Building for release and running the binary 'tools' command

Build in release mode using the default configuration:

```bash
make build
```

Display the help menu:

```bash
./mithril-aggregator tools --help
```

You should see:

```bash
List of tools to upkeep the aggregator

Usage: mithril-aggregator tools <COMMAND>

Commands:
  recompute-certificates-hash  Load all certificates in the database to recompute their hash and update all related entities
  help                         Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Run the 'tools recompute-certificates-hash' command in release mode with the default configuration. This allows the Mithril aggregator node to recompute all of its certificate hashes, which is useful to avoid a chain re-genesis after an update that changes the structure of the certificates.

```bash
./mithril-aggregator tools recompute-certificates-hash
```

## Building for release and running the binary 'database' command

Build in release mode using the default configuration:

```bash
make build
```

Display the help menu:

```bash
./mithril-aggregator database --help
```

You should see:

```bash
Database tools

Usage: mithril-aggregator database <COMMAND>

Commands:
  migrate  Migrate databases located in the given stores directory
  vacuum   Vacuum the aggregator main database
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Run the 'database migrate' command in release mode, which allows the Mithril aggregator node to migrate all databases
located in the given stores directory.

```bash
./mithril-aggregator database migrate --stores-directory **YOUR_STORES_DIRECTORY**
```

Run the 'database vacuum' command in release mode, which allows the Mithril aggregator node to
[vacuum](https://www.sqlite.org/lang_vacuum.html) the main database.

```bash
./mithril-aggregator database vacuum --stores-directory **YOUR_STORES_DIRECTORY**
```

:::tip

If you wish to delve deeper and access several levels of logs from the Mithril aggregator, use the following:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

## Download the pre-built binary

<CompiledBinaries  node="mithril-aggregator"/>

## Subcommands

Here are the available subcommands:

| Subcommand                            | Performed action                                                                                                                          |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **serve**                             | The aggregator runs its HTTP server in nominal mode and orchestrates multi-signature production                                           |
| **help**                              | Prints this message or the help of the given subcommand(s)                                                                                |
| **genesis export**                    | Exports genesis payload to sign with genesis secret key                                                                                   |
| **genesis sign**                      | Signs the genesis payload with the genesis secret key                                                                                     |
| **genesis import**                    | Imports the genesis signature (the payload signed with the genesis secret key) and creates and imports a genesis certificate in the store |
| **genesis bootstrap**                 | Bootstraps a genesis certificate (test only usage)                                                                                        |
| **genesis generate-keypair**          | Generates a genesis keypair                                                                                                               |
| **era list**                          | Lists the supported eras                                                                                                                  |
| **era generate-tx-datum**             | Generates the era markers transaction datum to be stored on-chain                                                                         |
| **era generate-keypair**              | Generates an era keypair                                                                                                                  |
| **database migrate**                  | Migrate databases located in the given stores directory                                                                                   |
| **database vacuum**                   | Vacuum the aggregator main database                                                                                                       |
| **tools recompute-certificates-hash** | Loads all certificates in the database, recomputing their hash, and updating all related entities                                         |

## Configuration parameters

The configuration parameters can be set in either of the following ways:

1. In a configuration file, depending on the `--run-mode` parameter. If the runtime mode is `testnet`, the file is located in `./conf/testnet.json`.

2. The value can be overridden by an environment variable with the parameter name in uppercase.

Here is a list of the available parameters for the serve command:

| Parameter                      | Command line (long)  | Command line (short) | Environment variable                                                                 | Description                                                                        | Default value              | Example                                                                                                                 |     Mandatory      |
| ------------------------------ | -------------------- | :------------------: | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | :----------------: |
| `cardano_cli_path`             | -                    |          -           | `CARDANO_CLI_PATH`                                                                   | Cardano CLI tool path                                                              | -                          | `cardano-cli`                                                                                                           | :heavy_check_mark: |
| `cardano_node_socket_path`     | -                    |          -           | `CARDANO_NODE_SOCKET_PATH`                                                           | Path of the socket opened by the Cardano node                                      | -                          | `/ipc/node.socket`                                                                                                      | :heavy_check_mark: |
| `config_directory`             | `--config-directory` |          -           | -                                                                                    | Directory of the configuration file                                                | `./config`                 | -                                                                                                                       |         -          |
| `data_stores_directory`        | -                    |          -           | `data_stores_directory`                                                              | Directory to store aggregator databases                                            | -                          | `./mithril-aggregator/stores`                                                                                           | :heavy_check_mark: |
| `db_directory`                 | `--db-directory`     |          -           | `DB_DIRECTORY`                                                                       | Directory of the **Cardano node** stores                                           | `/db`                      | -                                                                                                                       | :heavy_check_mark: |
| `genesis_verification_key`     | -                    |          -           | `GENESIS_VERIFICATION_KEY`                                                           | Genesis verification key                                                           | -                          | -                                                                                                                       | :heavy_check_mark: |
| `network`                      | -                    |          -           | `NETWORK`                                                                            | Cardano network                                                                    | -                          | `mainnet` or `preprod` or `devnet`                                                                                      | :heavy_check_mark: |
| `network_magic`                | -                    |          -           | `NETWORK_MAGIC`                                                                      | Cardano network magic number (for `testnet` and `devnet`)                          | -                          | `1097911063` or `42`                                                                                                    |         -          |
| `protocol_parameters`          | -                    |          -           | `PROTOCOL_PARAMETERS__K`, `PROTOCOL_PARAMETERS__M`, and `PROTOCOL_PARAMETERS__PHI_F` | Mithril protocol parameters                                                        | -                          | `{ k: 5, m: 100, phi_f: 0.65 }`                                                                                         | :heavy_check_mark: |
| `run_mode`                     | `--run-mode`         |         `-r`         | `RUN_MODE`                                                                           | Runtime mode                                                                       | `dev`                      | -                                                                                                                       | :heavy_check_mark: |
| `store_retention_limit`        | -                    |          -           | `STORE_RETENTION_LIMIT`                                                              | Maximum number of records in stores. If not set, no limit is set.                  | -                          | -                                                                                                                       |         -          |
| `custom_origin_tag_white_list` | -                    |          -           | `CUSTOM_ORIGIN_TAG_WHITE_LIST`                                                       | Custom origin tag of client request added to the whitelist (comma separated list). | `EXPLORER,BENCHMARK,CI,NA` | `EXAMPLE`                                                                                                               |         -          |
| `verbose`                      | `--verbose`          |         `-v`         | `VERBOSE`                                                                            | Verbosity level                                                                    | -                          | Parsed from the number of occurrences: `-v` for `Warning`, `-vv` for `Info`, `-vvv` for `Debug` and `-vvvv` for `Trace` | :heavy_check_mark: |

`serve` command:

| Parameter                                                        | Command line (long)                                                | Command line (short) | Environment variable                                                                                                    | Description                                                                                                                                                                                                                                                        | Default value                             | Example                                                                                                                                                                                                                                                                                          |                    Mandatory                    |
| ---------------------------------------------------------------- | ------------------------------------------------------------------ | :------------------: | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------: |
| `server_ip`                                                      | `--server-ip`                                                      |          -           | `SERVER_IP`                                                                                                             | Listening server IP                                                                                                                                                                                                                                                | `0.0.0.0`                                 | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `server_port`                                                    | `--server-port`                                                    |          -           | `SERVER_PORT`                                                                                                           | Listening server port                                                                                                                                                                                                                                              | `8080`                                    | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `public_server_url`                                              | -                                                                  |          -           | `PUBLIC_SERVER_URL`                                                                                                     | Public URL of the aggregator                                                                                                                                                                                                                                       | -                                         | `https://aggregator.release-mainnet.api.mithril.network/aggregator`                                                                                                                                                                                                                              |                        -                        |
| `snapshot_directory`                                             | `--snapshot-directory`                                             |          -           | `SNAPSHOT_DIRECTORY`                                                                                                    | Directory to store local snapshots of the **Cardano node**                                                                                                                                                                                                         | `.`                                       | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `snapshot_uploader_type`                                         | -                                                                  |          -           | `SNAPSHOT_UPLOADER_TYPE`                                                                                                | Type of snapshot uploader to use                                                                                                                                                                                                                                   | -                                         | `gcp` or `local`                                                                                                                                                                                                                                                                                 |               :heavy_check_mark:                |
| `snapshot_bucket_name`                                           | -                                                                  |          -           | `SNAPSHOT_BUCKET_NAME`                                                                                                  | Name of the bucket where the snapshots are stored                                                                                                                                                                                                                  | -                                         | `snapshot-bucket`                                                                                                                                                                                                                                                                                |  Required if `snapshot_uploader_type` is `gcp`  |
| `snapshot_use_cdn_domain`                                        | -                                                                  |          -           | `SNAPSHOT_USE_CDN_DOMAIN`                                                                                               | Use CDN domain for constructing snapshot url                                                                                                                                                                                                                       | `false`                                   | -                                                                                                                                                                                                                                                                                                | To be used if `snapshot_uploader_type` is `gcp` |
| `run_interval`                                                   | -                                                                  |          -           | `RUN_INTERVAL`                                                                                                          | Interval between two runtime cycles in ms                                                                                                                                                                                                                          | -                                         | `60000`                                                                                                                                                                                                                                                                                          |               :heavy_check_mark:                |
| `chain_observer_type`                                            | `--chain-observer-type`                                            |          -           | `CHAIN_OBSERVER_TYPE`                                                                                                   | Chain observer type that can be `cardano-cli`, `pallas` or `fake`.                                                                                                                                                                                                 | `pallas`                                  | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `era_reader_adapter_type`                                        | `--era-reader-adapter-type`                                        |          -           | `ERA_READER_ADAPTER_TYPE`                                                                                               | Era reader adapter type that can be `cardano-chain`, `file` or `bootstrap`.                                                                                                                                                                                        | `bootstrap`                               | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `era_reader_adapter_params`                                      | `--era-reader-adapter-params`                                      |          -           | `ERA_READER_ADAPTER_PARAMS`                                                                                             | Era reader adapter params that is an optional JSON encoded parameters structure that is expected depending on the `era_reader_adapter_type` parameter                                                                                                              | -                                         | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `ancillary_files_signer_config`                                  | -                                                                  |          -           | `ANCILLARY_FILES_SIGNER_CONFIG`                                                                                         | Configuration of the ancillary files signer<br/><br/>Can either be a secret key or a key stored in a Google Cloud Platform KMS account.<br/><br/>**IMPORTANT**: The cryptographic scheme used is ED25519                                                           | -                                         | - secret-key:<br/>`{ "type": "secret-key", "secret_key": "136372c3138312c3138382c3130352c3233312c3135" }`<br/>- Gcp kms:<br/>`{ "type": "gcp-kms", "resource_name": "projects/project_name/locations/_location_name/keyRings/key_ring_name/cryptoKeys/key_name/cryptoKeyVersions/key_version" }` |                        -                        |
| `signed_entity_types`                                            | `--signed-entity-types`                                            |          -           | `SIGNED_ENTITY_TYPES`                                                                                                   | Signed entity types parameters (discriminants names in an ordered comma separated list)                                                                                                                                                                            | -                                         | `MithrilStakeDistribution,CardanoStakeDistribution,CardanoDatabase,CardanoTransactions`                                                                                                                                                                                                          |                        -                        |
| `snapshot_compression_algorithm`                                 | `--snapshot-compression-algorithm`                                 |          -           | `SNAPSHOT_COMPRESSION_ALGORITHM`                                                                                        | Compression algorithm of the snapshot archive                                                                                                                                                                                                                      | `zstandard`                               | `gzip` or `zstandard`                                                                                                                                                                                                                                                                            |                        -                        |
| `zstandard_parameters`                                           | -                                                                  |          -           | `ZSTANDARD_PARAMETERS__LEVEL` and `ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS`                                             | Zstandard specific parameters                                                                                                                                                                                                                                      | -                                         | `{ level: 9, number_of_workers: 4 }`                                                                                                                                                                                                                                                             |                        -                        |
| `blockfrost_parameters`                                          | -                                                                  |          -           | `BLOCKFROST_PARAMETERS`                                                                                                 | Optional parameters to connect to the Blockfrost API. Used to fetch the ticker and name of<br/>the registered stake pools.<br/><br/>`base_url` (optional) allows you to override the default URL, which is otherwise automatically determined from the project ID. | -                                         | `{ "project_id": "preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ" }`<br/>or `{ "project_id": "preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ", "base_url": "https://your-custom-blockfrost-server.io/api/v0/" }`                                                                                               |                        -                        |
| `signer_importer_run_interval`                                   | -                                                                  |          -           | `SIGNER_IMPORTER_RUN_INTERVAL`                                                                                          | Time interval at which the pools names and ticker in blockfrost will be imported (in minutes).                                                                                                                                                                     | `720`                                     | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `allow_unparsable_block`                                         | `--allow-unparsable-block`                                         |          -           | `ALLOW_UNPARSABLE_BLOCK`                                                                                                | If set no error is returned in case of unparsable block and an error log is written instead. Will be ignored on (pre)production networks.                                                                                                                          | `false`                                   | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `cardano_blocks_transactions_signing_config`                     | -                                                                  |          -           | `CARDANO_BLOCKS_TRANSACTIONS_SIGNING_CONFIG__SECURITY_PARAMETER` and `CARDANO_BLOCKS_TRANSACTIONS_SIGNING_CONFIG__STEP` | Cardano blocks and transactions signing configuration                                                                                                                                                                                                              | `{ security_parameter: 3000, step: 120 }` | `{ security_parameter: 3000, step: 120 }`                                                                                                                                                                                                                                                        |                        -                        |
| `cardano_transactions_signing_config`                            | -                                                                  |          -           | `CARDANO_TRANSACTIONS_SIGNING_CONFIG__SECURITY_PARAMETER` and `CARDANO_TRANSACTIONS_SIGNING_CONFIG__STEP`               | Cardano transactions signing configuration                                                                                                                                                                                                                         | `{ security_parameter: 3000, step: 120 }` | `{ security_parameter: 3000, step: 120 }`                                                                                                                                                                                                                                                        |                        -                        |
| `cardano_transactions_prover_cache_pool_size`                    | `--cardano-transactions-prover-cache-pool-size`                    |          -           | `CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE`                                                                           | Cardano transactions prover cache pool size                                                                                                                                                                                                                        | `10`                                      | `10`                                                                                                                                                                                                                                                                                             |                        -                        |
| `cardano_transactions_database_connection_pool_size`             | `--cardano-transactions-database-connection-pool-size`             |          -           | `CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE`                                                                    | Cardano transactions database connection pool size                                                                                                                                                                                                                 | `10`                                      | `10`                                                                                                                                                                                                                                                                                             |                        -                        |
| `cardano_prover_max_hashes_allowed_by_request`                   | `--cardano-prover-max-hashes-allowed-by-request`                   |          -           | `CARDANO_PROVER_MAX_HASHES_ALLOWED_BY_REQUEST`                                                                          | Maximum number of hashes allowed by request to the Cardano prover (applies to both transaction hashes and block hashes)                                                                                                                                            | `100`                                     | `100`                                                                                                                                                                                                                                                                                            |                        -                        |
| `cardano_transactions_block_streamer_max_roll_forwards_per_poll` | `--cardano-transactions-block-streamer-max-roll-forwards-per-poll` |          -           | `CARDANO_TRANSACTIONS_BLOCK_STREAMER_MAX_ROLL_FORWARDS_PER_POLL`                                                        | Maximum number of roll forwards during a poll of the block streamer when importing transactions                                                                                                                                                                    | `1000`                                    | `1000`                                                                                                                                                                                                                                                                                           |                        -                        |
| `preload_security_parameter`                                     | -                                                                  |          -           | `PRELOAD_SECURITY_PARAMETER`                                                                                            | Blocks offset, from the tip of the chain, to exclude during the cardano transactions preload<br/>`[default: 2160]`.                                                                                                                                                | `2160`                                    | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `enable_metrics_server`                                          | `--enable-metrics-server`                                          |          -           | `ENABLE_METRICS_SERVER`                                                                                                 | Enable metrics HTTP server (Prometheus endpoint on /metrics)                                                                                                                                                                                                       | `false`                                   | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `metrics_server_ip`                                              | `--metrics-server-ip`                                              |          -           | `METRICS_SERVER_IP`                                                                                                     | Metrics HTTP server IP                                                                                                                                                                                                                                             | `0.0.0.0`                                 | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `metrics_server_port`                                            | `--metrics-server-port`                                            |          -           | `METRICS_SERVER_PORT`                                                                                                   | Metrics HTTP server listening port                                                                                                                                                                                                                                 | `9090`                                    | -                                                                                                                                                                                                                                                                                                |                        -                        |
| `persist_usage_report_interval_in_seconds`                       |                                                                    |          -           | `PERSIST_USAGE_REPORT_INTERVAL_IN_SECONDS`                                                                              | Duration in seconds between two recording of usage metrics                                                                                                                                                                                                         | `10`                                      | `5`                                                                                                                                                                                                                                                                                              |                        -                        |
| `leader_aggregator_endpoint`                                     | `--leader-aggregator-endpoint`                                     |          -           | `LEADER_AGGREGATOR_ENDPOINT`                                                                                            | Leader aggregator endpoint (used with unstable feature)                                                                                                                                                                                                            | -                                         | `https://aggregator.pre-release-preview.api.mithril.network/aggregator`                                                                                                                                                                                                                          |                        -                        |
| `aggregate_signature_type`                                       | -                                                                  |          -           | `AGGREGATE_SIGNATURE_TYPE`                                                                                              | Aggregate signature type used to create certificates                                                                                                                                                                                                               | `Concatenation`                           | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |
| `signature_processor_wait_delay_on_error_ms`                     | -                                                                  |          -           | `SIGNATURE_PROCESSOR_WAIT_DELAY_ON_ERROR_MS`                                                                            | Delay to wait between two signature processing attempts after an error                                                                                                                                                                                             | `1000`                                    | -                                                                                                                                                                                                                                                                                                |               :heavy_check_mark:                |

`genesis bootstrap` command:

| Parameter                  | Command line (long)    | Command line (short) | Environment variable       | Description                                                                            | Default value | Example                            |     Mandatory      |
| -------------------------- | ---------------------- | :------------------: | -------------------------- | -------------------------------------------------------------------------------------- | ------------- | ---------------------------------- | :----------------: |
| `genesis_secret_key`       | `--genesis-secret-key` |          -           | `GENESIS_SECRET_KEY`       | Genesis Secret Key (test only)                                                         | -             | -                                  | :heavy_check_mark: |
| `mithril_era`              | `--mithril-era`        |          -           | -                          | Mithril era to use for the genesis certificate                                         | -             | -                                  |         -          |
| `help`                     | `--help`               |         `-h`         | -                          | Print help (see more with '--help')                                                    | -             | -                                  |         -          |
| `cardano_cli_path`         | -                      |          -           | `CARDANO_CLI_PATH`         | Cardano CLI tool path                                                                  | -             | `cardano-cli`                      |         -          |
| `cardano_node_socket_path` | -                      |          -           | `CARDANO_NODE_SOCKET_PATH` | Path of the socket opened by the Cardano node                                          | -             | `/ipc/node.socket`                 | :heavy_check_mark: |
| `network_magic`            | -                      |          -           | `NETWORK_MAGIC`            | Cardano Network Magic number<br/><br/>useful for TestNet & DevNet                      | -             | `1097911063` or `42`               |         -          |
| `network`                  | -                      |          -           | `NETWORK`                  | Cardano network                                                                        | -             | `mainnet` or `preprod` or `devnet` | :heavy_check_mark: |
| `chain_observer_type`      | -                      |          -           | `CHAIN_OBSERVER_TYPE`      | Cardano chain observer type                                                            | -             | -                                  | :heavy_check_mark: |
| `data_stores_directory`    | -                      |          -           | `DATA_STORES_DIRECTORY`    | Directory to store aggregator data (Certificates, Snapshots, Protocol Parameters, ...) | -             | `./mithril-aggregator/stores`      | :heavy_check_mark: |

`genesis export` command:

| Parameter                  | Command line (long) | Command line (short) | Environment variable       | Description                                                                            | Default value | Example                            |     Mandatory      |
| -------------------------- | ------------------- | :------------------: | -------------------------- | -------------------------------------------------------------------------------------- | ------------- | ---------------------------------- | :----------------: |
| `target_path`              | `--target-path`     |          -           | -                          | Target path                                                                            | -             | -                                  | :heavy_check_mark: |
| `mithril_era`              | `--mithril-era`     |          -           | -                          | Mithril era to use for the genesis certificate                                         | -             | -                                  |         -          |
| `help`                     | `--help`            |         `-h`         | -                          | Print help (see more with '--help')                                                    | -             | -                                  |         -          |
| `cardano_cli_path`         | -                   |          -           | `CARDANO_CLI_PATH`         | Cardano CLI tool path                                                                  | -             | `cardano-cli`                      |         -          |
| `cardano_node_socket_path` | -                   |          -           | `CARDANO_NODE_SOCKET_PATH` | Path of the socket opened by the Cardano node                                          | -             | `/ipc/node.socket`                 | :heavy_check_mark: |
| `network_magic`            | -                   |          -           | `NETWORK_MAGIC`            | Cardano Network Magic number<br/><br/>useful for TestNet & DevNet                      | -             | `1097911063` or `42`               |         -          |
| `network`                  | -                   |          -           | `NETWORK`                  | Cardano network                                                                        | -             | `mainnet` or `preprod` or `devnet` | :heavy_check_mark: |
| `chain_observer_type`      | -                   |          -           | `CHAIN_OBSERVER_TYPE`      | Cardano chain observer type                                                            | -             | -                                  | :heavy_check_mark: |
| `data_stores_directory`    | -                   |          -           | `DATA_STORES_DIRECTORY`    | Directory to store aggregator data (Certificates, Snapshots, Protocol Parameters, ...) | -             | `./mithril-aggregator/stores`      | :heavy_check_mark: |

`genesis import` command:

| Parameter                  | Command line (long)          | Command line (short) | Environment variable       | Description                                                        | Default value | Example                            |     Mandatory      |
| -------------------------- | ---------------------------- | :------------------: | -------------------------- | ------------------------------------------------------------------ | ------------- | ---------------------------------- | :----------------: |
| `signed_payload_path`      | `--signed-payload-path`      |          -           | -                          | Path of the payload to import.                                     | -             | -                                  | :heavy_check_mark: |
| `genesis_verification_key` | `--genesis-verification-key` |          -           | -                          | Genesis verification key                                           | -             | -                                  | :heavy_check_mark: |
| `mithril_era`              | `--mithril-era`              |          -           | -                          | Mithril era to use for the genesis certificate                     | -             | -                                  |         -          |
| `data_stores_directory`    | -                            |          -           | `DATA_STORES_DIRECTORY`    | Directory to store aggregator databases                            | -             | `./mithril-aggregator/stores`      | :heavy_check_mark: |
| `cardano_node_socket_path` | -                            |          -           | `CARDANO_NODE_SOCKET_PATH` | Path of the socket opened by the Cardano node                      | -             | `/ipc/node.socket`                 | :heavy_check_mark: |
| `cardano_cli_path`         | -                            |          -           | `CARDANO_CLI_PATH`         | Cardano CLI tool path                                              | -             | `cardano-cli`                      |         -          |
| `chain_observer_type`      | -                            |          -           | `CHAIN_OBSERVER_TYPE`      | Chain observer type that can be `cardano-cli`, `pallas` or `fake`. | `pallas`      | -                                  | :heavy_check_mark: |
| `network`                  | -                            |          -           | `NETWORK`                  | Cardano network                                                    | -             | `mainnet` or `preprod` or `devnet` | :heavy_check_mark: |
| `network_magic`            | -                            |          -           | `NETWORK_MAGIC`            | Cardano network magic number (for `testnet` and `devnet`)          | -             | `1097911063` or `42`               |         -          |

`genesis sign` command:

| Parameter                    | Command line (long)            | Command line (short) | Environment variable | Description                                    | Default value | Example | Mandatory |
| ---------------------------- | ------------------------------ | :------------------: | -------------------- | ---------------------------------------------- | ------------- | ------- | :-------: |
| `to_sign_payload_path`       | `--to-sign-payload-path`       |          -           | -                    | Path of the payload to sign.                   | -             | -       |     -     |
| `target_signed_payload_path` | `--target-signed-payload-path` |          -           | -                    | Path of the signed payload to export.          | -             | -       |     -     |
| `genesis_secret_key_path`    | `--genesis-secret-key-path`    |          -           | -                    | Path of the genesis secret key.                | -             | -       |     -     |
| `mithril_era`                | `--mithril-era`                |          -           | -                    | Mithril era to use for the genesis certificate | -             | -       |     -     |

`genesis generate-keypair` command:

| Parameter     | Command line (long) | Command line (short) | Environment variable | Description                           | Default value | Example |     Mandatory      |
| ------------- | ------------------- | :------------------: | -------------------- | ------------------------------------- | ------------- | ------- | :----------------: |
| `target_path` | `--target-path`     |          -           | -                    | Target path for the generated keypair | -             | -       | :heavy_check_mark: |

`era list` command:

| Parameter | Command line (long) | Command line (short) | Environment variable | Description                                   | Default value | Example | Mandatory |
| --------- | ------------------- | :------------------: | -------------------- | --------------------------------------------- | ------------- | ------- | :-------: |
| `json`    | `--json`            |          -           | -                    | Export the supported era list to JSON format. | -             | -       |     -     |

`era generate-tx-datum` command:

| Parameter                | Command line (long)        | Command line (short) | Environment variable     | Description                                                                                                                                                                              | Default value | Example |     Mandatory      |
| ------------------------ | -------------------------- | :------------------: | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `current_era_epoch`      | `--current-era-epoch`      |          -           | `CURRENT_ERA_EPOCH`      | Epoch at which current era starts.                                                                                                                                                       | -             | -       | :heavy_check_mark: |
| `next_era_epoch`         | `--next-era-epoch`         |          -           | `NEXT_ERA_EPOCH`         | Epoch at which the next era starts. If not specified and an upcoming era is available, it will announce the next era. If specified, it must be strictly greater than `current-epoch-era` | -             | -       |         -          |
| `era_markers_secret_key` | `--era-markers-secret-key` |          -           | `ERA_MARKERS_SECRET_KEY` | Era markers secret key that is used to verify the authenticity of the era markers on the chain.                                                                                          | -             | -       | :heavy_check_mark: |
| `target_path`            | `--target-path`            |          -           | -                        | Path of the file to export the payload to.                                                                                                                                               | -             | -       |         -          |

`era generate-keypair` command:

| Parameter     | Command line (long) | Command line (short) | Environment variable | Description                           | Default value | Example |     Mandatory      |
| ------------- | ------------------- | :------------------: | -------------------- | ------------------------------------- | ------------- | ------- | :----------------: |
| `target_path` | `--target-path`     |          -           | -                    | Target path for the generated keypair | -             | -       | :heavy_check_mark: |

`database migrate` command:

| Parameter          | Command line (long)  | Command line (short) | Environment variable | Description                                              | Default value | Example |     Mandatory      |
| ------------------ | -------------------- | :------------------: | -------------------- | -------------------------------------------------------- | ------------- | ------- | :----------------: |
| `stores_directory` | `--stores-directory` |          -           | `STORES_DIRECTORY`   | Location of the stores directory for migrating databases | -             | -       | :heavy_check_mark: |

`database vacuum` command:

| Parameter          | Command line (long)  | Command line (short) | Environment variable | Description                                                      | Default value | Example |     Mandatory      |
| ------------------ | -------------------- | :------------------: | -------------------- | ---------------------------------------------------------------- | ------------- | ------- | :----------------: |
| `stores_directory` | `--stores-directory` |          -           | `STORES_DIRECTORY`   | Location of the stores directory for vacuuming the main database | -             | -       | :heavy_check_mark: |

`tools recompute-certificates-hash` command:

| Parameter               | Command line (long) | Command line (short) | Environment variable    | Description                             | Default value | Example |     Mandatory      |
| ----------------------- | ------------------- | :------------------: | ----------------------- | --------------------------------------- | ------------- | ------- | :----------------: |
| `data_stores_directory` | -                   |          -           | `DATA_STORES_DIRECTORY` | Directory to store aggregator databases | -             | -       | :heavy_check_mark: |
