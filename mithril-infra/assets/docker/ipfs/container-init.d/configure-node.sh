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
ipfs config --json Swarm.ResourceMgr.MaxMemory '"2GB"'
ipfs config --json Swarm.ResourceMgr.MaxFileDescriptors 1024

ipfs config Datastore.StorageMax "${IPFS_STORAGE_MAX}"
ipfs config Plugins.Plugins.telemetry.Config.Mode off
