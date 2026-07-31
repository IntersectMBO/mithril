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
    echo "  -n, --number <int>         Number of nodes to configure (min: 2)"
    echo "  -h, --help                 Print this help"
    echo "  -o, --overwrite            Allow overwriting existing configuration"
    echo "  -s, --swarm-dir <dir>      Directory that will contains the swarm nodes (required)"
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

# Init a node, removing existing content if overwrite is set, returning the node Peer Id
init_node() {
  local -r node_id="$1"
  local -r ipfs_bin_path="$2"
  local -r swarm_dir="${3%/}"
  local -r overwrite="$4"

  local node_dir
  node_dir="$swarm_dir/kubo-node-$node_id"

  if [[ -e "$node_dir" ]]; then
    if [[ "$overwrite" != true ]]; then
      error_exit "Node configuration already exists: '$node_dir'. Use -o, --overwrite to replace it."
    fi

    echo ">> Removing existing configuration: '$node_dir'" >&2
    rm -rf -- "$node_dir"
  fi

  mkdir -p -- "$swarm_dir"
  IPFS_PATH="$node_dir" "$ipfs_bin_path" init --profile test >&2

  # Important: only line that print to stdout so function output can be correctly retrieved
  IPFS_PATH="$node_dir" "$ipfs_bin_path" id -f "<id>"
}

configure_node() {
  local -r node_id="$1"
  local -r swarm_key="$2"
  local -r ipfs_bin_path="$3"
  local -r swarm_dir="${4%/}"

  local node_dir
  node_dir="$swarm_dir/kubo-node-$node_id"

  local api_port gateway_port swarm_port
  api_port=$((5000 + node_id))
  gateway_port=$((8080 + node_id))
  swarm_port=$((4000 + node_id))

  #---------- Write swarm key
  {
    printf '%s\n' "/key/swarm/psk/1.0.0/"
    printf '%s\n' "/base16/"
    printf '%s\n' "$swarm_key"
  } > "$node_dir/swarm.key"

  #---------- Additional config
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Addresses.API "/ip4/127.0.0.1/tcp/${api_port}"
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config Addresses.Gateway "/ip4/127.0.0.1/tcp/${gateway_port}"
  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Addresses.Swarm "[\"/ip4/127.0.0.1/tcp/${swarm_port}\"]"
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

configure_node_peers() {
  local -r node_id="$1"
  local -r number_of_nodes="$2"
  local -r ipfs_bin_path="$3"
  local -r swarm_dir="${4%/}"
  shift 4
  local -a peer_ids=("$@")

  local node_dir
  node_dir="$swarm_dir/kubo-node-$node_id"

  local peer_node_id peer_id swarm_port peers_json separator
  peers_json="["
  separator=""

  for ((peer_node_id = 1; peer_node_id <= number_of_nodes; peer_node_id++)); do
    if [[ "$peer_node_id" == "$node_id" ]]; then
      continue
    fi

    peer_id="${peer_ids[$((peer_node_id - 1))]}"
    swarm_port=$((4000 + peer_node_id))

    peers_json="${peers_json}${separator}{\"ID\":\"${peer_id}\",\"Addrs\":[\"/ip4/127.0.0.1/tcp/${swarm_port}\"]}"
    separator=","
  done

  peers_json="${peers_json}]"

  IPFS_PATH="$node_dir" "$ipfs_bin_path" config --json Peering.Peers "$peers_json"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare IPFS_BIN="" SWARM_DIR="" NUMBER_OF_NODES="" OVERWRITE=false

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -b | --ipfs-bin-path) shift; IPFS_BIN=${1:-} ;;
      -n | --number) shift; NUMBER_OF_NODES=${1:-} ;;
      -h | --help ) display_help ;;
      -o | --overwrite ) OVERWRITE=true ;;
      -s | --swarm-dir) shift; SWARM_DIR=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly SWARM_DIR NUMBER_OF_NODES=${NUMBER_OF_NODES:-2} OVERWRITE

if [[ -z "$IPFS_BIN" ]]; then
  error_exit "Missing required option: -b, --ipfs-bin-path"
fi

if [[ ! -x "$IPFS_BIN" ]]; then
  error_exit "IPFS binary is not executable or does not exist: '$IPFS_BIN'"
fi

if [[ -z "$SWARM_DIR" ]]; then
  error_exit "Missing required option: -s, --swarm-dir"
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

echo ">> Configuring ${NUMBER_OF_NODES} Kubo nodes in '${SWARM_DIR}'"

SWARM_KEY="$(generate_swarm_key)"
readonly SWARM_KEY
echo ">> Swarm key generated (not displayed)."

declare -a PEER_IDS
# Init node first - generating their peer Id which will be needed afterward
for ((node_id = 1; node_id <= NUMBER_OF_NODES; node_id++)); do
  PEER_IDS[node_id - 1]=$(init_node "$node_id" "$IPFS_BIN" "$SWARM_DIR" "$OVERWRITE")
done
echo ">> nodes ids:"
printf '%s\n' "${PEER_IDS[@]}"

for ((node_id = 1; node_id <= NUMBER_OF_NODES; node_id++)); do
  configure_node "$node_id" "$SWARM_KEY" "$IPFS_BIN" "$SWARM_DIR"
  configure_node_peers "$node_id" "$NUMBER_OF_NODES" "$IPFS_BIN" "$SWARM_DIR" "${PEER_IDS[@]}"
done
echo ">> Kubo nodes configuration finished"
