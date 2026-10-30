#!/bin/sh
set -e

for variable in IPFS_SWARM_PORT IPFS_PUBLIC_ADDRESS IPFS_STORAGE_MAX; do
  eval "value=\${$variable:-}"
  if [ -z "$value" ]; then
    echo "configure-node: $variable is not set" >&2
    exit 1
  fi
done

# The server profile is applied by 'ipfs init' only when the repository is created, so it must be
# re-asserted here for a repository restored from a disk snapshot
if [ "$(ipfs config --json Swarm.AddrFilters)" = "null" ] || [ "$(ipfs config --json Swarm.AddrFilters)" = "[]" ]; then
  ipfs config profile apply server > /dev/null
fi

ipfs config Addresses.API "/ip4/0.0.0.0/tcp/5001"
ipfs config --json Addresses.Swarm "[\"/ip4/0.0.0.0/tcp/${IPFS_SWARM_PORT}\", \"/ip4/0.0.0.0/udp/${IPFS_SWARM_PORT}/quic-v1\"]"

# The VM only sees its private address, so the public address must be announced explicitly for
# remote peers to be able to dial this node
ipfs config --json Addresses.AppendAnnounce "[\"/ip4/${IPFS_PUBLIC_ADDRESS}/tcp/${IPFS_SWARM_PORT}\", \"/ip4/${IPFS_PUBLIC_ADDRESS}/udp/${IPFS_SWARM_PORT}/quic-v1\"]"

# The node still publishes provider records as a DHT client, without serving routing queries for
# the whole public network from a VM shared with the other Mithril services
ipfs config Routing.Type dhtclient

ipfs config --json Swarm.ConnMgr.LowWater 50
ipfs config --json Swarm.ConnMgr.HighWater 200
ipfs config --json Swarm.ResourceMgr.MaxMemory '"1GB"'
ipfs config --json Swarm.ResourceMgr.MaxFileDescriptors 1024

# The default Bitswap server keeps at most 1 MB in flight per peer, which throttles the download of
# large archives by a client
ipfs config --json Internal.Bitswap.TaskWorkerCount 32
ipfs config --json Internal.Bitswap.EngineTaskWorkerCount 32
ipfs config --json Internal.Bitswap.EngineBlockstoreWorkerCount 256
ipfs config --json Internal.Bitswap.MaxOutstandingBytesPerPeer 8388608

ipfs config Datastore.StorageMax "${IPFS_STORAGE_MAX}"
ipfs config --json Experimental.FilestoreEnabled true
ipfs config Plugins.Plugins.telemetry.Config.Mode off

# The IPNS signing key is replaced at each start so that a rotated key from the deployment is applied
if [ -n "${IPFS_IPNS_SIGNING_KEY:-}" ]; then
  if [ -z "${IPFS_IPNS_SIGNING_KEY_NAME:-}" ]; then
    echo "configure-node: IPFS_IPNS_SIGNING_KEY_NAME is not set" >&2
    exit 1
  fi
  if ipfs key list | grep -qx "${IPFS_IPNS_SIGNING_KEY_NAME}"; then
    ipfs key rm "${IPFS_IPNS_SIGNING_KEY_NAME}" > /dev/null
  fi
  ipns_key_file=$(mktemp)
  trap 'rm -f "$ipns_key_file"' EXIT
  printf '%s\n' "${IPFS_IPNS_SIGNING_KEY}" > "$ipns_key_file"
  ipfs key import --format=pem-pkcs8-cleartext "${IPFS_IPNS_SIGNING_KEY_NAME}" "$ipns_key_file" > /dev/null
fi
