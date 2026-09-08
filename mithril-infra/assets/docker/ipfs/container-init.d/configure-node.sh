#!/bin/sh
set -e

ipfs config Addresses.API "/ip4/0.0.0.0/tcp/5001"
ipfs config --json Addresses.Swarm "[\"/ip4/0.0.0.0/tcp/${IPFS_SWARM_PORT}\", \"/ip4/0.0.0.0/udp/${IPFS_SWARM_PORT}/quic-v1\"]"

# The VM only sees its private address, so the public address must be announced explicitly for
# remote peers to be able to dial this node
ipfs config --json Addresses.AppendAnnounce "[\"/ip4/${IPFS_PUBLIC_ADDRESS}/tcp/${IPFS_SWARM_PORT}\", \"/ip4/${IPFS_PUBLIC_ADDRESS}/udp/${IPFS_SWARM_PORT}/quic-v1\"]"

ipfs config Routing.Type dht
ipfs config Datastore.StorageMax "${IPFS_STORAGE_MAX}"
ipfs config Plugins.Plugins.telemetry.Config.Mode off
