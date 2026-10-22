#!/bin/bash

# Verifies an IPFS replica of the Mithril immutable archives set up with setup_ipfs_replica.sh.
#
# The script checks that the Kubo node is connected to the IPFS network, that the latest version of the
# directory published under the IPNS name is fully stored locally and pinned, and prints a link to check
# with the IPFS Check tool that the node is reachable.

set -euo pipefail

DEPLOYMENT=${DEPLOYMENT:-binary}
IPNS_NAME=${IPNS_NAME:-}
CONTAINER_NAME=mithril-ipfs
IPFS_BINARY=/opt/mithril-ipfs/ipfs

print_help() {
    cat << EOF
Verifies an IPFS replica of the Mithril immutable archives set up with setup_ipfs_replica.sh.

Usage:
  IPNS_NAME=<name> [DEPLOYMENT=docker] bash verify_ipfs_replica.sh

Required variables:
  IPNS_NAME   IPNS name of the immutable archives (eg, /ipns/k51...)

Optional variables:
  DEPLOYMENT  'binary' (default) or 'docker'

Options:
  -h, --help  Print this help
EOF
}

fail() {
    echo ">> ERROR: $1" >&2
    exit 1
}

oops() {
    echo ">> Oops, $1"
    exit 1
}

check_dependencies() {
    if [ "$DEPLOYMENT" = "binary" ]; then
        command -v sudo > /dev/null || fail "The 'sudo' command is required but not installed."
        [ -x "$IPFS_BINARY" ] || fail "The Kubo binary $IPFS_BINARY is not installed."
    else
        command -v docker > /dev/null || fail "The 'docker' command is required but not installed."
        docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1 || fail "The $CONTAINER_NAME container is not reachable (missing container or no access to the Docker daemon)."
    fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    print_help
    exit 0
fi

[ -n "$IPNS_NAME" ] || fail "Required environment variable IPNS_NAME is not set (see --help)."
case "$DEPLOYMENT" in
    binary) ipfs_node=(sudo -u mithril-ipfs env IPFS_PATH=/var/lib/mithril-ipfs "$IPFS_BINARY") ;;
    docker) ipfs_node=(docker exec "$CONTAINER_NAME" ipfs) ;;
    *) fail "DEPLOYMENT must be 'binary' or 'docker', got '$DEPLOYMENT'." ;;
esac
check_dependencies

if ! PEERS=$("${ipfs_node[@]}" swarm peers 2> /dev/null); then
    oops "the Kubo node is not running. Check its service or container logs."
fi
PEERS_COUNT=$(echo -n "$PEERS" | grep -c . || true)
if [ "$PEERS_COUNT" -eq 0 ]; then
    oops "your node is not connected to any peer. Check that port 4001 (TCP and UDP) is open and try again later."
fi
echo ">> Your node is connected to $PEERS_COUNT peers."

if ! DIRECTORY_PATH=$("${ipfs_node[@]}" name resolve --nocache "$IPNS_NAME" 2> /dev/null); then
    oops "the IPNS name $IPNS_NAME cannot be resolved on the IPFS network. Try again later."
fi
DIRECTORY_CID=${DIRECTORY_PATH#/ipfs/}
echo ">> The latest version of the directory is $DIRECTORY_PATH"

if ! DIRECTORY_STAT=$("${ipfs_node[@]}" files stat --with-local "$DIRECTORY_PATH" 2> /dev/null); then
    oops "the directory $DIRECTORY_PATH cannot be read yet. Try again later."
fi
LOCAL_SHARE=$(echo "$DIRECTORY_STAT" | grep '^Local:' || true)
if [ -z "$LOCAL_SHARE" ]; then
    oops "the local share of the directory cannot be computed from the Kubo output."
fi
if ! echo "$LOCAL_SHARE" | grep -q '(100.00%)'; then
    oops "the replica is not complete yet: $LOCAL_SHARE"
fi

if ! "${ipfs_node[@]}" pin ls --type=recursive "$DIRECTORY_PATH" > /dev/null 2>&1; then
    oops "the latest version of the directory is not pinned yet. Check the replication with 'journalctl -u mithril-ipfs-replication' and try again later."
fi
echo ">> Congrats, your replica is complete and up to date: $LOCAL_SHARE"

PEER_ID=$("${ipfs_node[@]}" config Identity.PeerID)
echo ">> Check that your node is reachable and announces the directory at:"
echo "https://check.ipfs.network/?cid=$DIRECTORY_CID&multiaddr=/p2p/$PEER_ID"
