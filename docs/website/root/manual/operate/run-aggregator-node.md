---
sidebar_position: 4
---

import CompiledBinaries from '../../compiled-binaries.mdx'

# Run a Mithril aggregator node

:::danger

Running multiple Mithril aggregators on a Mithril network is enabled by the DMQ protocol, which is currently **unstable** and not suitable for production use.

:::

:::info

You don't need to be a Cardano SPO to run a Mithril aggregator node.

:::

:::tip

For more information about the **Mithril protocol**, see the [About Mithril](../../mithril/intro.md) section.

:::

On a Mithril network, there exist two types of aggregator nodes:

- **Leader aggregator node**: this node is managed by the entity that generates genesis certificates of the Mithril network (Input Output for all networks specified in the [Network configurations](../getting-started/network-configurations.md). It is responsible for collecting signer registrations (which is still a centralized process) and broadcasting them to other nodes of the network. It provides also a bootstrap point for other aggregator nodes to synchronize the certificate chain.
- **Follower aggregator node**: this node is managed by any entity willing to contribute to the Mithril network reliability or to provide additional availability guarantees to an infrastructure (eg, for a bridge powered by Mithril). This document explains how to set up and run such a follower Mithril aggregator node.

:::info

The follower aggregator listens to signatures diffused by the SPOs' Mithril signer nodes and produces Mithril certificates accordingly. Until the DMQ protocol is stabilized and widely deployed (at least **60%** of stake registered in the Mithril protocol operating it), the follower aggregator will not be able to produce certificates.

:::

Every follower aggregator node is free to select the types of data it wants to support certification for:

- **Cardano database v2**<sup>(\*)</sup>
- **Cardano transactions**
- **Cardano stake distribution**.

_<sup>(\*)</sup>: requires access to GCP to store Cardano database and may incur costs._

:::tip

For more information about the **supported data**, see the [Mithril certification](../../mithril/advanced/mithril-certification/README.mdx) section.

:::

## Prerequisites

:::info

Note that this guide works only on a Linux machine.

:::

- Operate a **Cardano full node**

- To access the file system of the **Cardano full node**, you will need the following permissions:

  - Read rights on the `Database` folder (specified by the `--database-path` setting of the **Cardano node**)
  - Read and write rights on the `Inter Process Communication` file (typically defined by the `CARDANO_NODE_SOCKET_PATH` environment variable used to launch the **Cardano node**)

- Install a correctly configured Rust toolchain (latest stable version); you can follow the instructions provided [here](https://www.rust-lang.org/learn/get-started)

- Install build tools `build-essential` and `m4`; for example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`

- Install OpenSSL development libraries; for example, on Ubuntu/Debian/Mint, run `apt install libssl-dev`

- Install a recent version of `jq` (version 1.6+) by running `apt install jq`.

## Hardware

Running a Mithril aggregator node requires sufficient hardware resources. We recommend using a virtual machine or dedicated server with the following specifications:

- **CPU**:
  - For test networks (`preprod`, `preview`): At least 4 vCPUs
  - For `mainnet`: At least 8 vCPUs
- **RAM**:
  - For test networks (`preprod`, `preview`): 16 GB minimum, 32 GB recommended
  - For `mainnet`: 32 GB minimum, 64 GB recommended
- **Storage**: At least 500 GB of disk space.

:::info

The actual resource requirements may vary depending on the signed entity types you choose to support. Supporting Cardano database snapshots and transaction certification will require more storage and processing power than supporting only stake distributions.

:::

## Set up the Mithril aggregator node

:::info

Compare the version of your Cardano node with the minimum supported versions listed in the [`networks.json`](https://github.com/IntersectMBO/mithril/blob/main/networks.json) file to verify its compatibility with the Mithril aggregator.

First, check the version of your Cardano node by running the following command:

```bash
cardano-node --version
```

Then, refer to the minimum supported versions listed in the [`networks.json`](https://github.com/IntersectMBO/mithril/blob/main/networks.json) file.

You can also fetch the minimum supported version for your network using the command below:

```bash
wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json | jq -r '."**YOUR_CARDANO_NETWORK**"."cardano-minimum-version"."mithril-aggregator"'
```

Here is an example for `preprod`:

```bash
wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json | jq -r '."preprod"."cardano-minimum-version"."mithril-aggregator"'
```

:::

### Building your own Mithril aggregator executable

#### Download the source file

To download the source from GitHub (HTTPS), run:

```bash
git clone https://github.com/IntersectMBO/mithril.git
```

Or (SSH):

```bash
git clone git@github.com:IntersectMBO/mithril.git
```

#### Build the Mithril aggregator binary

First, switch to build a branch/tag:

```bash
# **YOUR_BUILD_BRANCH_OR_TAG** depends on the Mithril network you target,
# please refer to the **Build from** column of the **Mithril networks** section
git checkout **YOUR_BUILD_BRANCH_OR_TAG**
```

Then, change the directory:

```bash
cd mithril/mithril-aggregator
```

Run tests (optional):

```bash
make test
```

Finally, build the executable:

```bash
make build
```

### Download the pre-built binary

<CompiledBinaries node="mithril-aggregator"/>

### Verifying the binary

#### Verify the version of the binary

You can check if the Mithril aggregator binary is running the correct version by running:

```bash
./mithril-aggregator -V
```

You should see something like:

```bash
mithril-aggregator 0.2.0
```

:warning: Please verify that the displayed version matches the version described in the release/pre-release notes (refer to the **Build from** column in the **Mithril networks** section).

#### Verify the build

Check if the Mithril aggregator binary is working correctly by running the help function:

```bash
./mithril-aggregator -h
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
          Run mode [default: dev]
  -v, --verbose...
          Verbosity level
      --db-directory <DB_DIRECTORY>
          Directory of the Cardano node files
      --config-directory <CONFIG_DIRECTORY>
          Directory where the configuration file is located [default: ./config]
  -h, --help
          Print help
  -V, --version
          Print version
```

:::tip

If you wish to delve deeper, you can access logs at various levels from the Mithril aggregator:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

### Installing the service

#### Move the executable

To move the executable to /opt/mithril, run:

```bash
sudo mkdir -p /opt/mithril
sudo mv mithril-aggregator /opt/mithril
```

#### Set up the service

:::caution

- `User=cardano`:
  Replace this value with the correct user. We assume that the user running the **Cardano node** is `cardano`. The **Mithril aggregator** must run with the same user as the **Cardano node** to access the database and socket files.

The configuration values for the `/opt/mithril/mithril-aggregator.env` file are described below:

**Base configuration** values are:

- `SIGNED_ENTITY_TYPES`: Comma-separated list of signed entity types to certify (eg, `MithrilStakeDistribution,CardanoStakeDistribution,CardanoDatabase,CardanoTransactions`)
- `SERVER_PORT`: Listening server port (default: `8080`)
- `PUBLIC_SERVER_URL`: Public URL of your aggregator (eg, `https://aggregator.example.com/aggregator`)
- `LEADER_AGGREGATOR_ENDPOINT`: Endpoint of the leader aggregator to synchronize with (required for follower aggregators, can be found in the [Network configurations](../getting-started/network-configurations.md))
- `RUN_INTERVAL`: Interval between two runtime cycles in milliseconds (eg, `60000` for 60 seconds)
- `AGGREGATE_SIGNATURE_TYPE`: Type of aggregate signature to use (default: `Concatenation`)
- `STORE_RETENTION_LIMIT`: Maximum number of records to keep in internal stores. If not set, no limit is applied. A value of `5` is recommended to limit disk usage
- `NETWORK`: Cardano network name (eg, `mainnet`, `preprod`, or `preview`)
- `NETWORK_MAGIC`: Cardano network magic number (required only if not using `mainnet`, `preprod` or `preview`)
- `CARDANO_NODE_SOCKET_PATH`: Path to the IPC file of the Cardano node
- `CARDANO_NODE_VERSION`: Version of the Cardano node running (eg, `10.5.0`)
- `CHAIN_OBSERVER_TYPE`: Type of chain observer (default: `pallas`)
- `ERA_READER_ADAPTER_TYPE`: Type of era reader adapter to use (default: `bootstrap`, use `cardano-chain` for production networks as specified in [Network configurations](../getting-started/network-configurations.md))
- `ERA_READER_ADAPTER_PARAMS`: JSON encoded parameters for the era reader adapter. For `cardano-chain` type, compute using: `jq -nc --arg address $(wget -q -O - **YOUR_ERA_READER_ADDRESS**) --arg verification_key $(wget -q -O - **YOUR_ERA_READER_VERIFICATION_KEY**) '{"address": $address, "verification_key": $verification_key}'` (URLs can be found in the [Network configurations](../getting-started/network-configurations.md))
- `GENESIS_VERIFICATION_KEY`: Genesis verification key for the Mithril network. Fetch using: `wget -q -O - **YOUR_GENESIS_VERIFICATION_KEY**` (URL can be found in the [Network configurations](../getting-started/network-configurations.md))
- `DMQ_NODE_SOCKET_PATH`: Path to the IPC file of the DMQ node
- `CUSTOM_ORIGIN_TAG_WHITE_LIST`: Comma-separated list of custom origin tags to whitelist for client requests (default: `EXPLORER,BENCHMARK,CI,NA`).

- **Base configuration** **optional** values are:

  - `BLOCKFROST_PARAMETERS`: Parameters to connect to the Blockfrost API. Used to fetch the ticker and name of the registered stake pools. Example: `{"project_id":"preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ"}`
  - `SIGNER_IMPORTER_RUN_INTERVAL`: Time interval at which the pools names and ticker in blockfrost will be imported (in minutes, default: `720`).

- The **Cardano database** configuration values are (only needed if supporting Cardano database certification):

  - `DB_DIRECTORY`: Directory of the Cardano node database stores (same as the `--database-path` setting of the Cardano node)
  - `DATA_STORES_DIRECTORY`: Directory where the aggregator will store its databases (eg, `/opt/mithril/stores`)
  - `GOOGLE_APPLICATION_CREDENTIALS_JSON`: JSON content of the GCP service account credentials (required if using GCP for snapshot storage)
  - `GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON`: JSON content of the GCP KMS credentials for signing (optional, for using GCP KMS to sign ancillary files)
  - `SNAPSHOT_UPLOADER_TYPE`: Type of snapshot uploader (`gcp` for Google Cloud Storage or `local` for local storage)
  - `SNAPSHOT_BUCKET_NAME`: Name of the GCP bucket where snapshots are stored (required if `SNAPSHOT_UPLOADER_TYPE` is `gcp`)
  - `SNAPSHOT_USE_CDN_DOMAIN`: Set to `true` to use CDN domain for constructing snapshot URLs (default: `false`, only relevant for GCP)
  - `SNAPSHOT_COMPRESSION_ALGORITHM`: Compression algorithm for snapshot archives (default: `zstandard`, can also be `gzip`)
  - `ZSTANDARD_PARAMETERS__LEVEL`: Zstandard compression level (eg, `9` for maximum compression, range 1-22)
  - `ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS`: Number of worker threads for Zstandard compression (eg, `4`)
  - `ANCILLARY_FILES_SIGNER_CONFIG`: JSON configuration for signing ancillary files. Can be either a secret key or a GCP KMS key. Example with secret key: `{"type": "secret-key", "secret_key": "your_hex_encoded_secret_key"}`.

- The **Cardano transactions** configuration values are (only needed if supporting Cardano transactions certification):
  - `CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE`: Size of the prover cache pool (default: `10`). This configuration can have a significant impact on the aggregator's memory usage. In particular, on `mainnet`, we recommend avoiding values higher than `10`.
  - `CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE`: Size of the database connection pool (default: `10`).

:::

:::tip

Here is an **example** set of values for **release-preprod** that will be used in this guide in the **tip** boxes to illustrate some commands:

- **Base configuration**:

  - **SIGNED_ENTITY_TYPES**: `MithrilStakeDistribution,CardanoStakeDistribution,CardanoTransactions` (only supporting stake distributions and transactions, excluding database snapshots)
  - **SERVER_PORT**: `8080`
  - **PUBLIC_SERVER_URL**: `https://aggregator.example.com/aggregator`
  - **LEADER_AGGREGATOR_ENDPOINT**: `https://aggregator.release-preprod.api.mithril.network/aggregator`
  - **RUN_INTERVAL**: `60000`
  - **AGGREGATE_SIGNATURE_TYPE**: `Concatenation`
  - **STORE_RETENTION_LIMIT**: `5`
  - **NETWORK**: `preprod`
  - **NETWORK_MAGIC**: `1`
  - **CARDANO_NODE_SOCKET_PATH**: `/cardano/ipc/node.socket`
  - **CARDANO_NODE_VERSION**: `10.5.0`
  - **CHAIN_OBSERVER_TYPE**: `pallas`
  - **ERA_READER_ADAPTER_TYPE**: `cardano-chain`
  - **ERA_READER_ADAPTER_PARAMS**: `$(jq -nc --arg address $(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.addr) --arg verification_key $(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.vkey) '{"address": $address, "verification_key": $verification_key}')`
  - **GENESIS_VERIFICATION_KEY**: `$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)`
  - **DMQ_NODE_SOCKET_PATH**: `/dmq/ipc/node.socket`
  - **CUSTOM_ORIGIN_TAG_WHITE_LIST**: `EXPLORER,BENCHMARK,CI,NA`

- **Optional configuration**:

  - **BLOCKFROST_PARAMETERS**: `{"project_id":"preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ"}`
  - **SIGNER_IMPORTER_RUN_INTERVAL**: 720

- **Cardano database configuration**:

  - **DB_DIRECTORY**: `/cardano/db`
  - **DATA_STORES_DIRECTORY**: `/opt/mithril/stores`
  - **GOOGLE_APPLICATION_CREDENTIALS_JSON**: `**YOUR_SECRET**`
  - **GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON**: `**YOUR_SECRET**`
  - **SNAPSHOT_UPLOADER_TYPE**: `local`
  - **SNAPSHOT_BUCKET_NAME**: `mithril-snapshots`
  - **SNAPSHOT_USE_CDN_DOMAIN**: `false`
  - **SNAPSHOT_COMPRESSION_ALGORITHM**: `zstandard`
  - **ZSTANDARD_PARAMETERS\_\_LEVEL**: `9`
  - **ZSTANDARD_PARAMETERS\_\_NUMBER_OF_WORKERS**: `4`
  - **ANCILLARY_FILES_SIGNER_CONFIG**: `**YOUR_SECRET**`

- **Cardano transaction configuration**:
  - **CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE**: `10`
  - **CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE**: `10`

:::

First, create an environment file that the service will use:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-aggregator.env << EOF
# Base configuration
SIGNED_ENTITY_TYPES=**YOUR_SIGNED_ENTITY_TYPES**
SERVER_PORT=**YOUR_SERVER_PORT**
PUBLIC_SERVER_URL=**YOUR_PUBLIC_SERVER_URL**
LEADER_AGGREGATOR_ENDPOINT=**YOUR_LEADER_AGGREGATOR_ENDPOINT**
RUN_INTERVAL=**YOUR_RUN_INTERVAL**
AGGREGATE_SIGNATURE_TYPE=**YOUR_AGGREGATE_SIGNATURE_TYPE**
STORE_RETENTION_LIMIT=**YOUR_STORE_RETENTION_LIMIT**
NETWORK=**YOUR_NETWORK**
NETWORK_MAGIC=**YOUR_NETWORK_MAGIC**
CARDANO_NODE_SOCKET_PATH=**YOUR_CARDANO_NODE_SOCKET_PATH**
CARDANO_NODE_VERSION=**YOUR_CARDANO_IMAGE_ID**
CHAIN_OBSERVER_TYPE=**YOUR_CHAIN_OBSERVER_TYPE**
ERA_READER_ADAPTER_TYPE=**YOUR_ERA_READER_ADAPTER_TYPE**
ERA_READER_ADAPTER_PARAMS=**YOUR_ERA_READER_ADAPTER_PARAMS**
GENESIS_VERIFICATION_KEY=**YOUR_GENESIS_VERIFICATION_KEY**
DMQ_NODE_SOCKET_PATH=**YOUR_DMQ_NODE_SOCKET_PATH**
CUSTOM_ORIGIN_TAG_WHITE_LIST=**YOUR_CUSTOM_ORIGIN_TAG_WHITE_LIST**
EOF'
```

If you want to configure **Optional** parameters, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Optional configuration
BLOCKFROST_PARAMETERS=**YOUR_BLOCKFROST_PARAMETERS**
SIGNER_IMPORTER_RUN_INTERVAL=**YOUR_SIGNER_IMPORTER_RUN_INTERVAL**
EOF`
```

If you want to support **Cardano database v2** certification, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Cardano database configuration
DB_DIRECTORY=**YOUR_DB_DIRECTORY**
DATA_STORES_DIRECTORY=**YOUR_DATA_STORES_DIRECTORY**
GOOGLE_APPLICATION_CREDENTIALS_JSON=**YOUR_GOOGLE_APPLICATION_CREDENTIALS_JSON**
GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON=**YOUR_GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON**
SNAPSHOT_UPLOADER_TYPE=**YOUR_SNAPSHOT_UPLOADER_TYPE**
SNAPSHOT_BUCKET_NAME=**YOUR_SNAPSHOT_BUCKET_NAME**
SNAPSHOT_USE_CDN_DOMAIN=**YOUR_SNAPSHOT_USE_CDN_DOMAIN**
SNAPSHOT_COMPRESSION_ALGORITHM=**YOUR_SNAPSHOT_COMPRESSION_ALGORITHM**
ZSTANDARD_PARAMETERS__LEVEL=**YOUR_ZSTANDARD_PARAMETERS__LEVEL**
ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS=**YOUR_ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS**
ANCILLARY_FILES_SIGNER_CONFIG=**YOUR_ANCILLARY_FILES_SIGNER_CONFIG**
EOF`
```

If you want to support **Cardano transaction** certification, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Cardano transactions configuration
CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE=**YOUR_CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE**
CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE=**YOUR_CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE**
EOF`
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-aggregator.env << EOF
# Base configuration
SIGNED_ENTITY_TYPES=MithrilStakeDistribution,CardanoStakeDistribution,CardanoTransactions
SERVER_PORT=8080
PUBLIC_SERVER_URL=https://aggregator.example.com/aggregator
LEADER_AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator
RUN_INTERVAL=60000
AGGREGATE_SIGNATURE_TYPE=Concatenation
STORE_RETENTION_LIMIT=5
NETWORK=preprod
NETWORK_MAGIC=1
CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket
CARDANO_NODE_VERSION=10.5.0
CHAIN_OBSERVER_TYPE=pallas
ERA_READER_ADAPTER_TYPE=cardano-chain
ERA_READER_ADAPTER_PARAMS={"address": "addr_test1qpkyv2ws0deszm67t840sdnruqgr492n80g3y96xw3p2ksk6suj5musy6w8lsg3yjd09cnpgctc2qh386rtxphxt248qr0npnx", "verification_key": "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d"}
DMQ_NODE_SOCKET_PATH=/dmq/ipc/node.socket
CUSTOM_ORIGIN_TAG_WHITE_LIST=EXPLORER,BENCHMARK,CI,NA
EOF'
```

If you want to configure **Optional** parameters, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Optional configuration
BLOCKFROST_PARAMETERS={"project_id":"preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ"}
SIGNER_IMPORTER_RUN_INTERVAL=720
EOF'
```

If you want to support the **Cardano database** certification, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Cardano database configuration
DB_DIRECTORY=/cardano/db
DATA_STORES_DIRECTORY=/opt/mithril/stores
GOOGLE_APPLICATION_CREDENTIALS_JSON=**YOUR_SECRET**
GOOGLE_APPLICATION_CREDENTIALS_GCP_KMS_JSON=**YOUR_SECRET**
SNAPSHOT_UPLOADER_TYPE=local
SNAPSHOT_BUCKET_NAME=mithril-snapshots
SNAPSHOT_USE_CDN_DOMAIN=false
SNAPSHOT_COMPRESSION_ALGORITHM=zstandard
ZSTANDARD_PARAMETERS__LEVEL=9
ZSTANDARD_PARAMETERS__NUMBER_OF_WORKERS=4
ANCILLARY_FILES_SIGNER_CONFIG={"type": "secret-key", "secret_key": "**YOUR_SECRET**"}
EOF'
```

If you want to support **Cardano transaction** certification, append the following variables to the `/opt/mithril/mithril-aggregator.env` file:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
# Cardano transactions configuration
CARDANO_TRANSACTIONS_PROVER_CACHE_POOL_SIZE=10
CARDANO_TRANSACTIONS_DATABASE_CONNECTION_POOL_SIZE=10
EOF'
```

:::

Then, create a `/etc/systemd/system/mithril-aggregator.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-aggregator.service << EOF
[Unit]
Description=Mithril aggregator service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
EnvironmentFile=/opt/mithril/mithril-aggregator.env
ExecStart=/opt/mithril/mithril-aggregator -vvv

[Install]
WantedBy=multi-user.target
EOF'
```

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start mithril-aggregator
```

Register the service to start on boot:

```bash
sudo systemctl enable mithril-aggregator
```

Monitor the status of the service:

```bash
systemctl status mithril-aggregator.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep mithril-aggregator
```

### Activate a Prometheus endpoint

The Mithril aggregator node can expose basic metrics on a Prometheus endpoint, which is not activated by default.

| Metrics                                                                                      | Description                                                                                               |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **mithril_aggregator_certificate_detail_total_served_since_startup**                         | Certificate details served since startup on a Mithril aggregator node                                     |
| **mithril_aggregator_artifact_detail_cardano_db_total_served_since_startup**                 | Number of Cardano immutable files full artifact details served since startup on a Mithril aggregator node |
| **mithril_aggregator_cardano_db_total_restoration_since_startup**                            | Number of Cardano immutable files full restorations since startup on a Mithril aggregator node            |
| **mithril_aggregator_cardano_db_immutable_files_restored_since_startup**                     | Number of Cardano immutable files restored since startup on a Mithril aggregator node                     |
| **mithril_aggregator_cardano_db_ancillary_files_restored_since_startup**                     | Number of Cardano ancillary files restored since startup on a Mithril aggregator node                     |
| **mithril_aggregator_cardano_db_complete_restoration_since_startup**                         | Number of complete Cardano database restorations since startup on a Mithril aggregator node               |
| **mithril_aggregator_cardano_db_partial_restoration_since_startup**                          | Number of partial Cardano database restorations since startup on a Mithril aggregator node                |
| **mithril_aggregator_artifact_detail_cardano_database_total_served_since_startup**           | Number of Cardano database artifact details served since startup on a Mithril aggregator node             |
| **mithril_aggregator_artifact_detail_mithril_stake_distribution_total_served_since_startup** | Number of Mithril stake distribution artifact details served since startup on a Mithril aggregator node   |
| **mithril_aggregator_artifact_detail_cardano_stake_distribution_total_served_since_startup** | Number of Cardano stake distribution artifact details served since startup on a Mithril aggregator node   |
| **mithril_aggregator_artifact_detail_cardano_transaction_total_served_since_startup**        | Number of Cardano transaction artifact details served since startup on a Mithril aggregator node          |
| **mithril_aggregator_proof_cardano_transaction_total_proofs_served_since_startup**           | Number of Cardano transaction proofs served since startup on a Mithril aggregator node                    |
| **mithril_aggregator_proof_cardano_transaction_total_transactions_served_since_startup**     | Number of Cardano transaction hashes requested for proof since startup on a Mithril aggregator node       |
| **mithril_aggregator_signer_registration_total_received_since_startup**                      | Number of signer registrations received since startup on a Mithril aggregator node                        |
| **mithril_aggregator_signer_registration_total_successful_since_startup**                    | Number of successful signer registrations received since startup on a Mithril aggregator node             |
| **mithril_aggregator_signature_registration_total_received_since_startup**                   | Number of signature registrations received since startup on a Mithril aggregator node                     |
| **mithril_aggregator_signature_registration_total_successful_since_startup**                 | Number of successful signature registrations received since startup on a Mithril aggregator node          |
| **mithril_aggregator_certificate_total_produced_since_startup**                              | Number of certificates produced since startup on a Mithril aggregator node                                |
| **mithril_aggregator_artifact_cardano_db_total_produced_since_startup**                      | Number of Cardano immutable files full artifacts produced since startup on a Mithril aggregator node      |
| **mithril_aggregator_artifact_cardano_database_total_produced_since_startup**                | Number of Cardano database artifacts produced since startup on a Mithril aggregator node                  |
| **mithril_aggregator_artifact_mithril_stake_distribution_total_produced_since_startup**      | Number of Mithril stake distribution artifacts produced since startup on a Mithril aggregator node        |
| **mithril_aggregator_artifact_cardano_stake_distribution_total_produced_since_startup**      | Number of Cardano stake distribution artifacts produced since startup on a Mithril aggregator node        |
| **mithril_aggregator_artifact_cardano_transaction_total_produced_since_startup**             | Number of Cardano transaction artifacts produced since startup on a Mithril aggregator node               |
| **mithril_aggregator_runtime_cycle_success_since_startup**                                   | Number of successful runtime cycles since startup on a Mithril aggregator                                 |
| **mithril_aggregator_runtime_cycle_total_since_startup**                                     | Number of runtime cycles since startup on a Mithril aggregator                                            |

To expose metrics on the endpoint, append the following environment variable to your environment file. In that case, the metrics server will listen on the `9090` port:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
ENABLE_METRICS_SERVER=true
EOF`
```

You can also specify a custom listen IP address and port for the metrics server:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
ENABLE_METRICS_SERVER=true
METRICS_SERVER_IP=**YOUR_METRICS_SERVER_IP**
METRICS_SERVER_PORT=**YOUR_METRICS_SERVER_PORT**
EOF`
```

:::tip

Here is an example that reproduces the default configuration for the Prometheus server:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
ENABLE_METRICS_SERVER=true
METRICS_SERVER_IP=0.0.0.0
METRICS_SERVER_PORT=9090
EOF`
```

:::

:::info

When activated, the metrics endpoint will be accessible to the `http://**YOUR_METRICS_SERVER_IP**:**YOUR_METRICS_SERVER_PORT**/metrics` location, which translates to [`http://0.0.0.0:9090/metrics`](http://0.0.0.0:9090/metrics) with the default configuration.

:::

:::info

This [Grafana template](https://grafana.com/grafana/dashboards/22165-mithril-aggregator/) makes it easy to set up a dashboard for this Prometheus endpoint (ID 22165).

:::

## Set up the SSL certificate (Traefik)

An aggregator must expose a TLS/SSL endpoint to securely communicate with Mithril signers. You can use a self-signed certificate or a certificate issued by a trusted Certificate Authority (CA).

We recommend using a reverse proxy such as [Traefik](https://doc.traefik.io/traefik/), which can automatically generate and renew SSL certificates using [Let's Encrypt](https://letsencrypt.org/) at no charge.

:::caution

Here is the needed information to set up Traefik:

- `**YOUR_TRAEFIK_HTTP_PORT**`: replace with the HTTP port for Traefik (typically `80`)
- `**YOUR_TRAEFIK_HTTPS_PORT**`: replace with the HTTPS port for Traefik (typically `443`)
- `**YOUR_DOMAIN_NAME**`: replace with your aggregator's domain name (eg, `aggregator.example.com`)
- `**YOUR_EMAIL**`: replace with your email address for Let's Encrypt notifications
- `**YOUR_AGGREGATOR_PORT**`: replace with the port your Mithril aggregator listens on (from `SERVER_PORT` in the aggregator environment file).

:::

:::tip

Here is an **example** set of values that will be used in this guide in the **tip** boxes to illustrate some commands:

- **YOUR_TRAEFIK_HTTP_PORT**: `80`
- **YOUR_TRAEFIK_HTTPS_PORT**: `443`
- **YOUR_DOMAIN_NAME**: `aggregator.example.com`
- **YOUR_EMAIL**: `admin@example.com`
- **YOUR_AGGREGATOR_PORT**: `8080`.

:::

### Download the pre-built binary

To download the latest released version of Traefik, first determine the latest version:

```bash
TRAEFIK_VERSION=$(curl -s https://api.github.com/repos/traefik/traefik/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
```

Then, download the binary:

```bash
curl -L -o traefik.tar.gz https://github.com/traefik/traefik/releases/download/v${TRAEFIK_VERSION}/traefik_v${TRAEFIK_VERSION}_linux_amd64.tar.gz
```

Extract the archive:

```bash
tar -xzf traefik.tar.gz
```

### Installing the service

#### Make the binary executable

To make the binary executable, run:

```bash
chmod +x traefik
```

#### Move the executable

To move the executable to /opt/traefik, run:

```bash
sudo mkdir -p /opt/traefik
sudo mv traefik /opt/traefik
```

#### Prepare the configuration directories

Create the necessary directories for Traefik configuration and certificates:

```bash
sudo mkdir -p /opt/traefik/config
sudo mkdir -p /opt/traefik/letsencrypt
```

#### Prepare the static configuration file

Create a `/opt/traefik/traefik.yml` static configuration file:

```bash
sudo bash -c 'cat > /opt/traefik/traefik.yml << EOF
entryPoints:
  web:
    address: ":**YOUR_TRAEFIK_HTTP_PORT**"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":**YOUR_TRAEFIK_HTTPS_PORT**"
    http:
      tls:
        certResolver: letsencrypt

certificatesResolvers:
  letsencrypt:
    acme:
      email: **YOUR_EMAIL**
      storage: /opt/traefik/letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

providers:
  file:
    directory: /opt/traefik/config
    watch: true

log:
  level: INFO

accessLog: {}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set:

```bash
sudo bash -c 'cat > /opt/traefik/traefik.yml << EOF
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /opt/traefik/letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

providers:
  file:
    directory: /opt/traefik/config
    watch: true

log:
  level: INFO

accessLog: {}
EOF'
```

:::

#### Prepare the dynamic configuration file

Create a `/opt/traefik/config/dynamic.yml` dynamic configuration file to route traffic to the Mithril aggregator:

```bash
sudo bash -c 'cat > /opt/traefik/config/dynamic.yml << EOF
http:
  routers:
    mithril-aggregator:
      rule: "Host(\`**YOUR_DOMAIN_NAME**\`)"
      service: mithril-aggregator
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    mithril-aggregator:
      loadBalancer:
        servers:
          - url: "http://localhost:**YOUR_AGGREGATOR_PORT**"
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set:

```bash
sudo bash -c 'cat > /opt/traefik/config/dynamic.yml << EOF
http:
  routers:
    mithril-aggregator:
      rule: "Host(\`aggregator.example.com\`)"
      service: mithril-aggregator
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    mithril-aggregator:
      loadBalancer:
        servers:
          - url: "http://localhost:8080"
EOF'
```

:::

#### Prepare the acme.json file

Create and secure the ACME certificates file:

```bash
sudo touch /opt/traefik/letsencrypt/acme.json
sudo chmod 600 /opt/traefik/letsencrypt/acme.json
```

#### Create the service user

Create a dedicated system user for Traefik:

```bash
sudo useradd -r -s /usr/sbin/nologin traefik
```

Set appropriate ownership for the Traefik directories:

```bash
sudo chown -R traefik:traefik /opt/traefik
```

#### Set up the service

:::caution

- `User=traefik`:
  Replace this value with the correct user if you use a different username. The service uses Linux capabilities (`CAP_NET_BIND_SERVICE`) to allow the non-root user to bind to privileged ports (80 and 443) without requiring full root privileges.

:::

Create a `/etc/systemd/system/traefik.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/traefik.service << EOF
[Unit]
Description=Traefik reverse proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=traefik
Group=traefik
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectHome=true
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
ExecStart=/opt/traefik/traefik --configFile=/opt/traefik/traefik.yml

[Install]
WantedBy=multi-user.target
EOF'
```

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start traefik
```

Register the service to start on boot:

```bash
sudo systemctl enable traefik
```

Monitor the status of the service:

```bash
systemctl status traefik.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep traefik
```

:::info

Make sure your domain name points to your server's public IP address and that ports 80 and 443 are accessible from the internet for Let's Encrypt certificate validation and HTTPS access.

:::

## Set up the DMQ node (beta)

:::info

The DMQ node setup is currently **beta**. During the stabilization and ramp-up phase of the DMQ network, signatures received through it may not be enough to reach the quorum and thus produce valid certificates.

:::

The DMQ node supports the implementation of a **Decentralized Message Queue** (DMQ) for Mithril. The DMQ protocol allows Mithril signers to exchange signatures in a decentralized manner, enhancing the robustness and scalability of the Mithril networks. Once stabilized and deployed on a majority of SPOs on a Mithril network, the DMQ protocol will allow multiple aggregators to operate simultaneously, improving the overall availability of the Mithril protocol. The DMQ protocol is fully described in the [CIP-0137](https://cips.cardano.org/cip/CIP-0137).

:::caution

- Here is the needed information to set up a DMQ node:
  - `**YOUR_DMQ_NODE_SOCKET_PATH**`: replace with the path to the IPC file of the DMQ node
  - `**YOUR_CARDANO_NODE_SOCKET_PATH**`: replace with the path to the IPC file of the Cardano node
  - `**YOUR_CARDANO_SHELLEY_GENESIS_FILE_PATH**`: replace with the path to the Shelley genesis file of the Cardano node
  - `**YOUR_CARDANO_NETWORK_MAGIC**`: replace with the network magic number of your Cardano network
  - `**YOUR_DMQ_NETWORK_MAGIC**`: replace with the network magic number of your DMQ network (the value can be found in the [Mithril networks](../getting-started/network-configurations.md) table)
  - `**YOUR_DMQ_NODE_PUBLIC_ADDRESS**`: replace with the **public** IP address of your DMQ node
  - `**YOUR_DMQ_NODE_PORT**`: replace with the listening port of your DMQ node
  - `**YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**`: replace with the IP address of your DMQ bootstrap peer (the address can be found in the [Mithril networks](../getting-started/network-configurations.md) table)
  - `**YOUR_DMQ_BOOTSTRAP_PEER_PORT**`: replace with the listening port of your DMQ bootstrap peer (the value can be found in the [Mithril networks](../getting-started/network-configurations.md) table).

:::

:::tip

Here is an **example** set of values for **pre-release-preview** that will be used in this guide in the **tip** boxes to illustrate some commands:

- **YOUR_DMQ_NODE_SOCKET_PATH**: `/dmq/ipc/node.socket`
- **YOUR_CARDANO_NODE_SOCKET_PATH**: `/cardano/ipc/node.socket`
- **YOUR_CARDANO_SHELLEY_GENESIS_FILE_PATH**: `/cardano/config/shelley-genesis.json`
- **YOUR_CARDANO_NETWORK_MAGIC**: `2`
- **YOUR_DMQ_NETWORK_MAGIC**: `2147483650`
- **YOUR_DMQ_NODE_PUBLIC_ADDRESS**: `34.14.65.160`
- **YOUR_DMQ_NODE_PORT**: `6161`
- **YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**: `34.76.22.193`
- **YOUR_DMQ_BOOTSTRAP_PEER_PORT**: `11001`.

:::

### Download the pre-built binary

:::tip

As we are still in a testing stage, we only support the `pre-release-preview` network.

You can use these parameters for the **pre-release-preview** network:

- **DMQ_RELEASE_URL**: `https://github.com/IntersectMBO/dmq-node/releases/download/0.6.0.0/dmq-node-linux.tar.gz`

_These URLs may change in the future; please refer to this page for the latest released version of the DMQ node binary._

:::

To download the latest released version of the DMQ node binary, run the following command:

```bash
curl --fail -sL -o dmq-node.tar.gz **DMQ_RELEASE_URL**
```

Then, extract the archive:

```bash
tar -xzf dmq-node.tar.gz --strip-components=2 result/bin
```

And test that the binary works:

```bash
./dmq-node --version
```

You should see something like:

```bash
dmq-node version: 0.2.0.0
```

### Installing the service

#### Move the executable

To move the executable to /opt/dmq, run:

```bash
sudo mkdir -p /opt/dmq
sudo mv dmq-node /opt/dmq
```

#### Create the DMQ node socket directory

Create the directory that will hold the DMQ node IPC socket file:

```bash
sudo mkdir -p $(dirname **YOUR_DMQ_NODE_SOCKET_PATH**)
sudo chown cardano:cardano $(dirname **YOUR_DMQ_NODE_SOCKET_PATH**)
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo mkdir -p $(dirname /dmq/ipc/node.socket)
sudo chown cardano:cardano $(dirname /dmq/ipc/node.socket)
```

:::

#### Prepare the configuration file of the DMQ node

Create a `/opt/dmq/config.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/config.json << EOF
{
  "NetworkMagic": **YOUR_DMQ_NETWORK_MAGIC**,
  "CardanoNetworkMagic": **YOUR_CARDANO_NETWORK_MAGIC**,
  "CardanoNodeSocket": "**YOUR_CARDANO_NODE_SOCKET_PATH**",
  "ShelleyGenesisFile": "**YOUR_CARDANO_SHELLEY_GENESIS_FILE_PATH**",
  "PeerSharing": true,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/config.json << EOF
{
  "NetworkMagic": 2147483650,
  "CardanoNetworkMagic": 2,
  "CardanoNodeSocket": "/cardano/ipc/node.socket",
  "ShelleyGenesisFile": "/cardano/config/shelley-genesis.json",
  "PeerSharing": true,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::

#### Prepare the topology file for the DMQ node

:::tip

The topology file of the DMQ node follows a similar format to the Cardano node topology file. More information is available at [Cardano node topology](https://developers.cardano.org/docs/get-started/infrastructure/node/topology/).

:::

- Create a `/opt/dmq/topology.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/topology.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "**YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**",
          "port": **YOUR_DMQ_BOOTSTRAP_PEER_PORT**,
          "valency": 1
        }
      ],
      "advertise": true,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/topology.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "34.76.22.193",
          "port": 11001,
          "valency": 1
        }
      ],
      "advertise": true,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::

#### Set up the service

:::caution

- `User=cardano`:
  Replace this value with the correct user. We assume that the user running the **Cardano node** is `cardano`. The **DMQ node** must imperatively run with the same user.

:::

- Create a `/etc/systemd/system/dmq-aggregator.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-aggregator.service << EOF
[Unit]
Description=DMQ aggregator service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config.json --topology-file /opt/dmq/topology.json --local-socket **YOUR_DMQ_NODE_SOCKET_PATH** --host-addr **YOUR_DMQ_NODE_PUBLIC_ADDRESS** --port **YOUR_DMQ_NODE_PORT**

[Install]
WantedBy=multi-user.target
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-aggregator.service << EOF
[Unit]
Description=DMQ aggregator service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config.json --topology-file /opt/dmq/topology.json --local-socket /dmq/ipc/node.socket --host-addr 34.14.65.160 --port 11001
[Install]
WantedBy=multi-user.target
EOF'
```

:::

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start dmq-aggregator
```

Register the service to start on boot:

```bash
sudo systemctl enable dmq-aggregator
```

Monitor the status of the service:

```bash
systemctl status dmq-aggregator.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep dmq-aggregator
```

### Update the configuration of the Mithril aggregator

If you have set up the DMQ node, the Mithril aggregator must be configured to use it. Add the DMQ node socket path to the aggregator configuration:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
DMQ_NODE_SOCKET_PATH=**YOUR_DMQ_NODE_SOCKET_PATH**
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-aggregator.env << EOF
DMQ_NODE_SOCKET_PATH=/dmq/ipc/node.socket
EOF'
```

:::

## Verify the Mithril aggregator deployment

After installing and starting your Mithril aggregator node, you should verify that it is operating correctly. The verification process includes checking that your aggregator is:

1. Synchronizing signer registrations with the leader aggregator
2. Synchronizing the certificate chain with the leader aggregator
3. Producing new certificates.

:::info

As a follower aggregator, your node will:

- Fetch and store signer registrations from the leader aggregator
- Synchronize the certificate chain from the leader aggregator
- Produce its own certificates using signatures collected via the DMQ protocol (once DMQ is stable and widely deployed).

:::

### Monitor your aggregator with the Mithril explorer

You can monitor your aggregator's activity using the [Mithril explorer](https://mithril.network/explorer). To connect the explorer to your aggregator, use the following URL format:

```
https://mithril.network/explorer/?aggregator=**URL_ENCODED_AGGREGATOR_ENDPOINT**
```

For example, to monitor the `release-preprod` leader aggregator:

```
https://mithril.network/explorer/?aggregator=https%3A%2F%2Faggregator.release-preprod.api.mithril.network%2Faggregator
```

To monitor your own aggregator, replace the endpoint with your aggregator's public URL (URL-encoded).

:::info

**Aggregator lifecycle during epochs:**

- **At installation epoch**: the aggregator will fetch the signer registrations for the next epoch from the leader aggregator
- **At epoch + 1**: the aggregator will synchronize the certificate chain from the leader aggregator
- **At epoch + 2 and onwards**: once the DMQ protocol is stable and widely deployed, the aggregator will start producing its own certificates using signatures collected via DMQ.

:::

### Register your aggregator for automatic discovery (unstable)

If you want to make your follower aggregator publicly discoverable, you should:

1. **Ensure your aggregator is accessible via HTTPS** by setting up Traefik or another reverse proxy with a valid SSL certificate (as described in the [Set up the SSL certificate](#setup-the-ssl-certificate-traefik) section).

2. **Register your aggregator in the networks configuration**. You can do this by:

   - Opening an issue in the [Mithril GitHub repository](https://github.com/IntersectMBO/mithril/issues)
   - Or by creating a pull request that modifies the [`networks.json`](https://github.com/IntersectMBO/mithril/blob/main/networks.json) file and updates the `aggregators` field in the Cardano network you are targeting.

   Here is an example command to add an aggregator to the `release-preprod` network configuration:

   ```bash
   jq '.preprod.mithril-networks.release-preprodaggregators += [{"name": "My Aggregator", "endpoint": "https://aggregator.example.com/aggregator"}]' networks.json > networks.json.tmp && mv networks.json.tmp networks.json
   ```

:::info

Registering your aggregator for automatic discovery is optional. Your aggregator will still work and synchronize with the leader aggregator even if it's not publicly registered.

:::
