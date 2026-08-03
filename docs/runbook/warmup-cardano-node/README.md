# Cardano node warmup for ledger replay

## Introduction

When a new version of the Cardano node requires a **ledger state re-computation from genesis** (a.k.a. ledger replay), starting the new node against the existing database will trigger a full replay that can take many hours. During this time the Mithril aggregator is unable to observe the chain and is effectively down.

To avoid this long downtime, a warmup process bootstraps a temporary Cardano node from a recent Mithril snapshot. Once the temporary node has replayed the ledger and caught up with the chain tip, its database is swapped in place of the production node's database. The production aggregator then restarts against an already-replayed database and is back online within minutes.

> [!IMPORTANT]
> :fire: This process must be performed **before** upgrading the Cardano node version in the infrastructure. Perform it on each production aggregator that requires a ledger replay.

## Pre-requisites

- The new Cardano node Docker image version to warm up with
- Minimum memory available, at least the amount of memory used by the current aggregator Cardano node plus a margin of `1GB` (run `docker stats --no-stream --format "{{.MemUsage}}" cardano-node-aggregator` to check)
- Minimum data disk space available, at least the amount required for the Mithril snapshot download and the existing database of the aggregator Cardano node plus a margin of `5GB` (run `du -sh /home/curry/data/$NETWORK/mithril-aggregator/cardano/db` to check the existing database size)

Minimum requirement based on information gathered on 2026-03-31:

| **network** | **available memory** | **available data disk** |
| ----------- | -------------------- | ----------------------- |
| preview     | `7GB`                | `22GB`                  |
| preprod     | `8GB`                | `26GB`                  |
| mainnet     | `21GB`               | `267GB`                 |

## Configure environment variables

### Select the Mithril network

Export the environment variables for the target Mithril network.

For `pre-release-preview`:

```bash
export NETWORK=preview
export AGGREGATOR_ENDPOINT=https://aggregator.pre-release-preview.api.mithril.network/aggregator
export GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/genesis.vkey)
```

For `release-preprod`:

```bash
export NETWORK=preprod
export AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator
export GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)
```

For `release-mainnet`:

```bash
export NETWORK=mainnet
export AGGREGATOR_ENDPOINT=https://aggregator.release-mainnet.api.mithril.network/aggregator
export GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/genesis.vkey)
```

### Set the new Cardano node version

```bash
export CARDANO_NODE_VERSION=**CARDANO_NODE_VERSION**
```

Here is an example for version `11.0.1`:

```bash
export CARDANO_NODE_VERSION=11.0.1
```

## Phase 0: Verify sufficient disk space

Check the available disk space on the data disk (at least 50% must be free):

```bash
df -h
```

Example output:

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/sdb        500G  200G  300G  40% /home/curry/data
```

> [!WARNING]
> Do not proceed if less than 50% of disk space is available. The warmup process requires space for the Mithril snapshot download and a backup of the existing Cardano database.

## Phase 1: Warmup a temporary Cardano node from a Mithril snapshot

### Create a temporary working directory

```bash
rm -rf /home/curry/data/temp
mkdir -p /home/curry/data/temp
cd /home/curry/data/temp
```

### Download the Mithril client

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d latest -p "$(pwd)"
```

### Download the latest Cardano database snapshot

```bash
./mithril-client cardano-db download latest
```

This downloads and restores the latest Cardano database snapshot into `/home/curry/data/temp/db`. The process can take several minutes depending on network speed and snapshot size.

### Start the temporary Cardano node with the new version

Run a temporary Cardano node using the new version to warm up the restored database (i.e. trigger the ledger replay):

```bash
docker run -d --name cardano-node-warmup \
    -v cardano-node-ipc:/ipc \
    -v cardano-node-data:/data \
    --mount type=bind,source="/home/curry/data/temp/db",target=/data/db/ \
    -e NETWORK=${NETWORK} \
    ghcr.io/intersectmbo/cardano-node:${CARDANO_NODE_VERSION}
```

Follow the node logs to monitor the ledger replay progress:

```bash
docker logs -f --tail 100 cardano-node-warmup
```

Wait until the node has fully replayed the ledger and is syncing new blocks from the chain tip. This can take several hours. The node is ready when the logs show it processing recent blocks.

## Phase 2: Switch the production Cardano database with the warmed-up one

Once the temporary node has caught up with the chain tip, perform the database switchover.

### Stop both nodes

```bash
docker stop cardano-node-warmup
docker stop cardano-node-aggregator
```

### Back up and replace the production database

```bash
mv /home/curry/data/$NETWORK/mithril-aggregator/cardano/db /home/curry/data/$NETWORK/mithril-aggregator/cardano/db.bak
mv /home/curry/data/temp/db /home/curry/data/$NETWORK/mithril-aggregator/cardano/db
sudo chown -R curry /home/curry/data/$NETWORK/mithril-aggregator/cardano/db
sudo chgrp -R curry /home/curry/data/$NETWORK/mithril-aggregator/cardano/db
```

### Restart the production aggregator

```bash
docker start cardano-node-aggregator
docker logs -f --tail 100 cardano-node-aggregator
```

Verify that the aggregator Cardano node starts correctly and begins syncing from near the chain tip without triggering a ledger replay. The aggregator should be back online within minutes.

## Phase 3: Cleanup

Once the production node is confirmed to be running correctly, remove the temporary resources:

```bash
docker rm cardano-node-warmup
rm -rf /home/curry/data/$NETWORK/mithril-aggregator/cardano/db.bak
cd /home/curry/
rm -rf /home/curry/data/temp
```
