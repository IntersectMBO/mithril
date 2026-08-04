#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# shellcheck source=./commands/lib/common.sh
source "${SCRIPT_DIRECTORY}/commands/lib/common.sh"

display_help() {
    echo "Manage a swarm of IPFS Kubo nodes"
    echo
    echo "Usage: $0 <COMMAND> [OPTIONS]"
    echo
    echo "Commands:"
    echo "  init                     Download, configure, and create scripts to manage the Kubo swarm"
    echo "  load-webui               Download and load the Kubo Web UI on the private IPFS network"
    echo "  log                      Tail the logs from all Kubo nodes"
    echo "  query                    Run an ipfs command against one configured node"
    echo "  start                    Start the Kubo swarm using the generated start script"
    echo "  stop                     Stop the Kubo swarm using the generated stop script"
    echo "  help                     Print this help"
    echo
    echo "Run '$0 <COMMAND> --help' for command-specific options."
    echo
    echo "Environment variables:"
    echo "  SWARM_DIR                Directory that contains the swarm nodes"
    echo
    exit 0
}

# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------

declare -r command="${1:-}"

case "$command" in
  init)
    shift
    exec bash "${SCRIPT_DIRECTORY}/commands/ipfs-devnet-init.sh" "$@"
    ;;
  log | query | start | stop)
    shift
    exec bash "${SCRIPT_DIRECTORY}/commands/ipfs-devnet-exec.sh" --command "$command" "$@"
    ;;
  load-webui)
    shift
    exec bash "${SCRIPT_DIRECTORY}/commands/ipfs-devnet-load-webui.sh" "$@"
    ;;
  help | -h | --help)
    display_help
    ;;
  "")
    display_help
    ;;
  *)
    error_exit "Unknown command: $command"
    ;;
esac
