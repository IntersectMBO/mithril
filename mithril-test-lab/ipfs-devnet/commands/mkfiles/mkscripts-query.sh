#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Create the scripts that query information from the Kubo swarm nodes"
    echo
    echo "Usage: $0 [OPTIONS] <node_dir>..."
    echo
    echo "Options:"
    echo "  -b, --ipfs-bin-path <path> Path to the kubo ipfs binary (required)"
    echo "  -h, --help                 Print this help"
    echo "  -o, --output <dir>         Output directory [default='.']"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

shell_quote() {
  printf '%q' "$1"
}

write_nodes_paths_declaration() {
  printf 'readonly NODES_PATHS=('

  local node_path
  for node_path in "$@"; do
    printf ' %s' "$(shell_quote "$node_path")"
  done

  printf ' )\n'
}

write_log_script() {
  local -r output_dir="${1%/}"
  shift
  local -a nodes_paths=("$@")

  local -r script_path="${output_dir}/log.sh"

  {
    cat <<'EOF'
#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Tail the logs from all Kubo nodes"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help                Print this help"
    echo "  -l, --lines <int>         Number of lines to tail from each nodes log file [default: '10']"
    echo "  -s, --separator <string>  Separator to print between each log file [default: 70 '-']"
    echo
    echo "Environment variables:"
    echo "  TAIL_LINES                Number of lines to tail from each nodes log file"
    echo "  SEPARATOR                 Separator to print between each log file"
    echo
    echo "Options and environment variables can be mixed; when both are provided for the same setting,"
    echo "the command-line option takes priority."
    echo
    exit 0
}

error_exit() {
  echo "$1" 1>&2
  exit 1
}

EOF

    write_nodes_paths_declaration "${nodes_paths[@]}"

    cat <<'EOF'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare TAIL_LINES="${TAIL_LINES:-}" SEPARATOR="${SEPARATOR:-}"

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -h | --help ) display_help ;;
      -l | --lines) shift; TAIL_LINES=${1:-} ;;
      -s | --separator) shift; SEPARATOR=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly TAIL_LINES=${TAIL_LINES:-10}
readonly SEPARATOR=${SEPARATOR:-"----------------------------------------------------------------------"}

if ! [[ "$TAIL_LINES" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for --lines: '$TAIL_LINES'. Expected a positive integer."
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

for node_path in "${NODES_PATHS[@]}"; do
  log_file="${node_path%/}/ipfs.log"

  echo "${SEPARATOR}"
  echo "tail -n ${TAIL_LINES} ${log_file}"
  echo "${SEPARATOR}"

  if [[ -f "$log_file" ]]; then
    tail -n "${TAIL_LINES}" "${log_file}"
  else
    echo "Skipping Kubo node '$node_path': log file '$log_file' was not found. Is the swarm running?"
  fi
  echo "${SEPARATOR}"
  echo
done
EOF
  } > "$script_path"

  chmod +x "$script_path"
}


write_query_script() {
  local -r output_dir="${1%/}"
  local -r ipfs_bin="$2"
  shift 2
  local -a nodes_paths=("$@")

  local -r script_path="${output_dir}/query.sh"

  {
    cat <<'EOF'
#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Run an ipfs command against one Kubo node from the swarm"
    echo
    echo "Usage: $0 [OPTIONS] -- <ipfs-command> [ipfs-command-options...]"
    echo "       $0 [OPTIONS] <ipfs-command> [ipfs-command-options...]"
    echo
    echo "Options:"
    echo "  -h, --help          Print this help"
    echo "  -n, --node <int>    Node number to query, starting at 1 [default: 1]"
    echo
    echo "Examples:"
    echo "  $0 -- id"
    echo "  $0 --node 1 -- swarm peers"
    echo "  $0 --node 2 id"
    echo
    echo "Show the Kubo ipfs CLI help:"
    echo "  $0 -- --help"
    echo "  $0 help"
    echo
    echo "The script sets IPFS_PATH automatically and uses the Kubo binary downloaded during init."
    echo
    exit 0
}

error_exit() {
  echo "$1" 1>&2
  exit 1
}

require_value() {
  local -r option="$1"
  local -r value="${2:-}"

  if [[ -z "$value" ]]; then
    error_exit "Missing value for option: $option"
  fi
}

EOF

    printf 'readonly IPFS_BIN=%s\n' "$(shell_quote "$ipfs_bin")"
    write_nodes_paths_declaration "${nodes_paths[@]}"

    cat <<'EOF'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare NODE=1

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -h | --help ) display_help ;;
      -n | --node)
        shift
        require_value "--node" "${1:-}"
        NODE=$1
        ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -eq 0 ]]; then
  error_exit "Missing ipfs command. Use '$0 --help' for usage."
fi

if ! [[ "$NODE" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for --node: '$NODE'. Expected a positive integer."
fi

if (( NODE < 1 || NODE > ${#NODES_PATHS[@]} )); then
  error_exit "Invalid value for --node: '$NODE'. Expected a value between 1 and ${#NODES_PATHS[@]}."
fi

readonly NODE NODE_PATH="${NODES_PATHS[$((NODE - 1))]}"

if [[ ! -x "$IPFS_BIN" ]]; then
  error_exit "IPFS binary is not executable or does not exist: '$IPFS_BIN'"
fi

if [[ ! -d "$NODE_PATH" ]]; then
  error_exit "Node directory does not exist: '$NODE_PATH'"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

IPFS_PATH="$NODE_PATH" "$IPFS_BIN" "$@"
EOF
  } > "$script_path"

  chmod +x "$script_path"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare IPFS_BIN="" OUTPUT_DIR=""
declare -a NODES_PATHS=()

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -b | --ipfs-bin-path) shift; IPFS_BIN=${1:-} ;;
      -h | --help ) display_help ;;
      -o | --output) shift; OUTPUT_DIR=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
fi

while [[ "$#" -gt 0 ]]; do
  NODES_PATHS+=("$1")
  shift
done

readonly IPFS_BIN OUTPUT_DIR=${OUTPUT_DIR:-"."}

if [[ -z "$IPFS_BIN" ]]; then
  error_exit "Missing required option: -b, --ipfs-bin-path"
fi

if [[ ! -x "$IPFS_BIN" ]]; then
  error_exit "IPFS binary is not executable or does not exist: '$IPFS_BIN'"
fi

if [[ ! -d "$OUTPUT_DIR" ]]; then
  error_exit "Output is not a directory or does not exist: '$OUTPUT_DIR'"
fi

if [[ "${#NODES_PATHS[@]}" -eq 0 ]]; then
  error_exit "Missing node directories"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

write_log_script "$OUTPUT_DIR" "${NODES_PATHS[@]}"
write_query_script "$OUTPUT_DIR" "$IPFS_BIN" "${NODES_PATHS[@]}"

echo ">> Created: ${OUTPUT_DIR%/}/log.sh"
echo ">> Created: ${OUTPUT_DIR%/}/query.sh"
