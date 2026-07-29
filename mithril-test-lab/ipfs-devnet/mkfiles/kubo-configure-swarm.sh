#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Configure a swarm of kubo ipfs node"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -b, --ipfs-bin-path <path> Path to the kubo ipfs binary (required)"
    echo "  -d, --nodes-dir <dir>      Directory that will contains the nodes configuration (required)"
    echo "  -n, --number <int>         Number of nodes to configure (min: 2)"
    echo "  -h, --help                 Print this help"
    echo "  -o, --overwrite            Allow overwriting existing configuration"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

# Generate a 64 chars long random hex string
generate_swarm_key() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

configure_node() {
  local -r node_id="$1"
  local -r swarm_key="$2"
  local -r ipfs_bin_path="$3"
  local -r nodes_dir="${4%/}"
  local -r overwrite="$5"

  local node_dir
  node_dir="$nodes_dir/kubo-node-$node_id"

  if [[ -e "$node_dir" ]]; then
    if [[ "$overwrite" != true ]]; then
      error_exit "Node configuration already exists: '$node_dir'. Use -o, --overwrite to replace it."
    fi

    echo "Removing existing configuration: '$node_dir'"
    rm -rf -- "$node_dir"
  fi

  #---------- Node init
  IPFS_PATH=$node_dir "$ipfs_bin_path" init --profile test

  #---------- Write swarm key
  {
    printf '%s\n' "/key/swarm/psk/1.0.0/"
    printf '%s\n' "/base16/"
    printf '%s\n' "$swarm_key"
  } > "$node_dir/swarm.key"

  #---------- Additional config
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Addresses.API "/ip4/127.0.0.1/tcp/500${node_id}"
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Addresses.Gateway "/ip4/127.0.0.1/tcp/808${node_id}"
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Addresses.Swarm "[\"/ip4/127.0.0.1/tcp/400${node_id}\"]"
  # Disable automatic discovery when starting up
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Bootstrap '[]'
  # Disable unsupported private network features
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Swarm.Transports.Network.Websocket false
  # Disable Multicast DNS-SD discovery mechanisms
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Discovery.MDNS.Enabled false
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Routing.Type dht
  # Allows files to be added without duplicating the space they take up on disk
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Experimental.FilestoreEnabled true
  # Avoid NAT port mapping
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Swarm.DisableNatPortMap true
  # Disable telemetry
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Plugins.Plugins.telemetry.Config.Mode off
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare IPFS_BIN="" NODES_DIR="" NUMBER_OF_NODES="" OVERWRITE=false

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -b | --ipfs-bin-path) shift; IPFS_BIN=${1:-} ;;
      -d | --nodes-dir) shift; NODES_DIR=${1:-} ;;
      -n | --number) shift; NUMBER_OF_NODES=${1:-} ;;
      -h | --help ) display_help ;;
      -o | --overwrite ) OVERWRITE=true ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly NODES_DIR NUMBER_OF_NODES=${NUMBER_OF_NODES:-2} OVERWRITE

if [[ -z "$IPFS_BIN" ]]; then
  error_exit "Missing required option: -b, --ipfs-bin-path"
fi

if [[ ! -x "$IPFS_BIN" ]]; then
  error_exit "IPFS binary is not executable or does not exist: '$IPFS_BIN'"
fi

if [[ -z "$NODES_DIR" ]]; then
  error_exit "Missing required option: -d, --nodes-dir"
fi

if ! [[ "$NUMBER_OF_NODES" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for -n, --number: '$NUMBER_OF_NODES'. Expected an integer."
fi

if (( NUMBER_OF_NODES < 2 )); then
  error_exit "Invalid value for -n, --number: '$NUMBER_OF_NODES'. Expected at least 2."
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ">> Configuring ${NUMBER_OF_NODES} Kubo nodes in '${NODES_DIR}'"

SWARM_KEY="$(generate_swarm_key)"
readonly SWARM_KEY
echo ">> Swarm key generated (not displayed)."

for ((node_id = 1; node_id <= NUMBER_OF_NODES; node_id++)); do
  configure_node "$node_id" "$SWARM_KEY" "$IPFS_BIN" "$NODES_DIR" "$OVERWRITE"
done
