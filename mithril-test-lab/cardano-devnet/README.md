# Cardano Private Devnet

**This is a work in progress** :hammer_and_wrench:

It scaffolds a private compound devnet with Cardano nodes:

- `N` Cardano Full nodes
- `P` Cardano SPO nodes

## Credits

This cli is inspired by this [script](https://github.com/IntersectMBO/cardano-node/blob/master/scripts/byron-to-alonzo/mkfiles.sh) from the Cardano node team.

## Pre-requisites

- You need to run a Linux computer
- You need to have a recent version of `jq` running (1.6+)

## Download source code

```bash
# Download sources from github
git clone https://github.com/IntersectMBO/mithril

# Go to sources directory
cd mithril/mithril-test-lab/cardano-devnet

# Chmod scripts
chmod u+x *.sh
```

## One step run with default configuration

```bash
# Run devnet with 1 Full node and 2 SPO nodes (with local docker images) and DMQ network
./devnet-run.sh

# Run devnet with Cardano nodes only
NODES=cardano ./devnet-run.sh

# Logs devnet
./devnet-log.sh

# Logs Cardano nodes only on devnet
NODES=cardano ./devnet-log.sh

# Query devnet
./devnet-query.sh

# Stop devnet
./devnet-stop.sh

```

## One step run with custom configuration

```bash
# Run devnet with 2 Full nodes and 5 SPO nodes
ARTIFACTS_DIR=artifacts NUM_FULL_NODES=2 NUM_POOL_NODES=5 ./devnet-run.sh

# Run devnet custom slot length (0.5s) and custom epoch length (120s)
# Slot length: the duration of a Cardano Eslot (can help modulate the immutables creation rate)
# Epoch Length: the duration of a Cardano Epoch
ARTIFACTS_DIR=artifacts SLOT_LENGTH=0.5 EPOCH_LENGTH=120 ./devnet-run.sh

# Run devnet with cardano-node 11.2.0 and a hard fork from Conway to Dijkstra at epoch 2
# Cardano node version: the latest era is Dijkstra from cardano-node 11.2.0 and Conway before
# Cardano hard fork latest era at epoch: the epoch of the hard fork to Dijkstra (0 by default, cardano-node 11.2.0 or later only), the devnet forks to every era up to Conway at epoch 0
ARTIFACTS_DIR=artifacts CARDANO_NODE_VERSION=11.2.0 CARDANO_HARD_FORK_LATEST_ERA_AT_EPOCH=2 ./devnet-run.sh

# Logs devnet
ARTIFACTS_DIR=artifacts LINES=10 ./devnet-log.sh

# Query devnet
ARTIFACTS_DIR=artifacts ./devnet-query.sh

# Stop devnet
ARTIFACTS_DIR=artifacts ./devnet-stop.sh
```

## One step run of the Leios devnet

The Leios mode runs a Cardano node supporting Leios (here a release of `input-output-hk/ouroboros-leios` given by `CARDANO_BINARY_URL`) in the Dijkstra era from epoch 0, gives the pools BLS keys, makes the local roots trustable and shrinks the block body so that a transaction load overflows the blocks and gets endorser blocks announced and certified.

```bash
# Run the Leios devnet (cardano-node 11.2.0 or later, hard fork at epoch 0)
# Use Leios: enables the Leios mode
# Cardano binary URL: the archive of a Cardano node supporting Leios (the official release of the node version by default)
# Active slots coefficient: a low value spaces the blocks so that a certifying block can follow its announcing block (1.0 by default)
ARTIFACTS_DIR=artifacts CARDANO_NODE_VERSION=11.2.0 USE_LEIOS=true CARDANO_BINARY_URL=https://github.com/input-output-hk/ouroboros-leios/releases/download/rc-2026w46/cardano-node-leios-x86_64-linux.tar.gz SLOT_LENGTH=0.2 EPOCH_LENGTH=100 ACTIVE_SLOTS_COEFF=0.1 ./devnet-run.sh

# Submit a transaction load on node-pool1 for a bounded duration (80 transactions per second for 120 seconds by default)
# Load TPS: the target rate of the transaction load
# Load duration: the duration of the transaction load in seconds
cd artifacts && LOAD_TPS=80 LOAD_DURATION=120 ./load-mithril.sh
```

The Leios periods and the block body size of the generated genesis are tuned for the devnet and can be overridden with `LEIOS_ANNOUNCEMENT_PERIOD_MS`, `LEIOS_VOTE_PERIOD_MS`, `LEIOS_DIFFUSION_PERIOD_MS` and `LEIOS_MAX_BLOCK_BODY_SIZE`.

## Step by step run with custom configuration

```bash
# Parameters
ARTIFACTS_DIR=artifacts # Directory where artifacts are produced
NUM_FULL_NODES=1 # Number of Cardano Full nodes
NUM_POOL_NODES=3 # Number of Cardano SPO nodes

# Bootstrap devnet with 1 Full node and 3 SPO nodes
rm -rf ${ARTIFACTS_DIR} && ./devnet-mkfiles.sh ${ARTIFACTS_DIR} ${NUM_FULL_NODES} ${NUM_POOL_NODES}

# Change directory
cd ${ARTIFACTS_DIR}

# Start devnet Cardano nodes
./start-cardano.sh

# Query devnet
./query.sh

# Logs devnet
./log.sh 10

# Stop devnet
./stop.sh
```

## Artifacts generated for the network

```bash
# Example of artifacts
artifacts
├── activate.sh
├── addresses
│   ├── pool-owner1.addr
│   ├── pool-owner1.skey
│   ├── pool-owner1-stake.addr
│   ├── pool-owner1-stake.reg.cert
│   ├── pool-owner1-stake.skey
│   ├── pool-owner1-stake.vkey
│   ├── pool-owner1.vkey
│   ├── user1.addr
│   ├── user1.skey
│   ├── user1-stake.addr
│   ├── user1-stake.deleg.cert
│   ├── user1-stake.reg.cert
│   ├── user1-stake.skey
│   ├── user1-stake.vkey
│   ├── user1.vkey
│   ├── utxo1.addr
│   ├── utxo1.skey
│   └── utxo1.vkey
├── cardano-cli
├── cardano-node
├── docker-compose.yaml
├── log.sh
├── node-full1
│   ├── byron
│   │   ├── delegate.cert
│   │   ├── delegate.key
│   │   ├── genesis.json
│   │   └── genesis.spec.json
│   ├── configuration.yaml
│   ├── ipc
│   ├── shelley
│   │   ├── genesis.alonzo.json
│   │   ├── genesis.alonzo.spec.json
│   │   ├── genesis.json
│   │   ├── genesis.spec.json
│   │   ├── kes.skey
│   │   ├── kes.vkey
│   │   ├── node.cert
│   │   ├── operator.counter
│   │   ├── operator.skey
│   │   ├── operator.vkey
│   │   ├── vrf.skey
│   │   └── vrf.vkey
│   ├── start-node.sh
│   ├── topology.docker.json
│   ├── topology.json
│   └── tx
├── node-pool1
│   ├── byron
│   │   ├── genesis.json
│   │   └── genesis.spec.json
│   ├── configuration.yaml
│   ├── ipc
│   ├── owner.skey
│   ├── owner.vkey
│   ├── registration.cert
│   ├── shelley
│   │   ├── genesis.alonzo.json
│   │   ├── genesis.alonzo.spec.json
│   │   ├── genesis.json
│   │   ├── genesis.spec.json
│   │   ├── kes.skey
│   │   ├── kes.vkey
│   │   ├── node.cert
│   │   ├── operator.counter
│   │   ├── operator.skey
│   │   ├── operator.vkey
│   │   ├── vrf.skey
│   │   └── vrf.vkey
│   ├── start-node.sh
│   ├── topology.docker.json
│   ├── topology.json
│   └── tx
├── query.sh
├── start-cardano.sh
└── stop.sh
```

## Example utxo & stakes informations retrieved from the network

```bash
=====================================================================
 Query Cardano devnet
=====================================================================

=====================================================================
=== Cardano Network
=====================================================================

>> Query chain tip
{
    "era": "Alonzo",
    "syncProgress": "100.00",
    "hash": "3be9b4493fea53f5da1f765ec49fe0268f6dd4097bc2437a5ed6e8600bfbb61e",
    "epoch": 2,
    "slot": 200,
    "block": 8
}

>> Query whole utxo
                           TxHash                                 TxIx        Amount
--------------------------------------------------------------------------------------
6c12b0d33e83fdaa830f00d16bcc91a6ed897e770600473b579fa746ba633194     0        448999157 lovelace + TxOutDatumNone
6c12b0d33e83fdaa830f00d16bcc91a6ed897e770600473b579fa746ba633194     1        1000000 lovelace + TxOutDatumNone
9134193f0cd9d838752c8215313a22213c08dbb6d58218ae4ef2fbabe5bf6c30     0        447999157 lovelace + TxOutDatumNone
9134193f0cd9d838752c8215313a22213c08dbb6d58218ae4ef2fbabe5bf6c30     1        2000000 lovelace + TxOutDatumNone
f90d90f58d0decba651c7fe476cf9b866254363347b8bd38e14c03e0a57e8aa1     0        1002000000 lovelace + TxOutDatumNone

>> Query stake pools
pool1vu2kd36hm9wp5hrzczp5ahdh0j2ls59srq5s8ju542zyqr5qd6j
pool1n6sxl7cfe9j9mf6jv228nluvy3k3xdu62chqk2wfaazrsenz4jz

>> Query stake distribution
                           PoolId                                 Stake frac
------------------------------------------------------------------------------
pool1vu2kd36hm9wp5hrzczp5ahdh0j2ls59srq5s8ju542zyqr5qd6j   1.052e-3
pool1n6sxl7cfe9j9mf6jv228nluvy3k3xdu62chqk2wfaazrsenz4jz   5.258e-4
```

# Running Mihtril

Mithril can be run from the E2E test with the `run-only` command

`cargo run -p mithril-end-to-end -- -vvv --bin-directory binaries_location/ --devnet-scripts-directory=mithril-test-lab/cardano-devnet/ run-only`

See more about Mithril E2E testing in mithril-end-to-end [README.md](../mithril-end-to-end/README.md)
