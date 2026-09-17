# Runbook: download a Cardano database through IPFS with the Mithril client

This runbook downloads the latest certified Cardano database of the `dev-preview` Mithril network,
with the immutable files fetched from the public IPFS network through a local Kubo node.

Every block runs **on the local machine** (Linux, tested on Ubuntu), in **one terminal**, in order.

## 0. Prerequisites

Docker Engine must be installed and usable without `sudo` (<https://docs.docker.com/engine/install/>).

```sh
sudo apt update && sudo apt install -y build-essential m4 libssl-dev pkg-config git curl jq
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## 1. Build the Mithril client

The `future_snark` feature is required to decode the certificates of the `dev-preview` network.

```sh
mkdir -p ~/mithril-ipfs-demo && cd ~/mithril-ipfs-demo
git clone https://github.com/IntersectMBO/mithril.git
cd mithril
git checkout 649d474625d8432f1273e3e3e6c9ea5de037fdf8
cargo build --release -p mithril-client-cli --features future_snark
cp target/release/mithril-client ~/mithril-ipfs-demo/
cd ~/mithril-ipfs-demo
./mithril-client --version
```

Expected: `mithril-client 0.13.24`. The build takes several minutes.

## 2. Start the local Kubo node

The client requires Kubo `0.43.0` or newer.

```sh
docker run -d --name kubo-mithril-client \
  -v kubo-mithril-client:/data/ipfs \
  -p 127.0.0.1:5001:5001 \
  ipfs/kubo:v0.43.1 daemon --migrate=true --enable-gc
```

```sh
until curl -s -m 2 -X POST http://127.0.0.1:5001/api/v0/version > /dev/null; do sleep 2; done
curl -s -X POST http://127.0.0.1:5001/api/v0/version | jq -r .Version
```

Expected: `0.43.1`.

## 3. Download the Cardano database through IPFS

```sh
cd ~/mithril-ipfs-demo
export AGGREGATOR_ENDPOINT=https://aggregator.dev-preview.api.mithril.network/aggregator
export GENESIS_VERIFICATION_KEY=$(curl -s https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/dev-preview/genesis.vkey)
export IPFS_RPC_URL=http://127.0.0.1:5001/
```

```sh
./mithril-client -vvv --unstable cardano-db download latest --download-dir ./db-ipfs
```

The database holds about 28,000 immutable files (4.5 GB of compressed archives), the download takes several minutes.

Expected: the `-vvv` logs show each immutable file fetched from the IPFS network through the Kubo node,
with one `files/stat` call and one `cat` call per file:

```text
DEBG POST Kubo RPC, ipfs_path: ipfs://QmXDNa3GfUyGoEvo5sA79oD3aJNHiVcUHrhbAVcD2bzpXN/28428.tar.zst, route: api/v0/files/stat
DEBG POST Kubo RPC, ipfs_path: ipfs://QmXDNa3GfUyGoEvo5sA79oD3aJNHiVcUHrhbAVcD2bzpXN/28410.tar.zst, route: api/v0/cat
DEBG POST Kubo RPC, ipfs_path: ipfs://QmXDNa3GfUyGoEvo5sA79oD3aJNHiVcUHrhbAVcD2bzpXN/28429.tar.zst, route: api/v0/files/stat
DEBG POST Kubo RPC, ipfs_path: ipfs://QmXDNa3GfUyGoEvo5sA79oD3aJNHiVcUHrhbAVcD2bzpXN/28409.tar.zst, route: api/v0/cat
```

Expected, at the end of the output:

```text
Cardano database snapshot '<HASH>' archives have been successfully unpacked. Immutable files have been successfully verified with Mithril.
```

## 4. Clean up

```sh
docker rm -f kubo-mithril-client && docker volume rm kubo-mithril-client
rm -rf ~/mithril-ipfs-demo
```
