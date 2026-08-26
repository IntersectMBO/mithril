#!/bin/bash

set -e

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 --docker-cmd [docker run command string] [--include-ancillary] [--ledger-backend <in-memory|lmdb|lsm|legacy>]"
  echo ""
  echo "Parameters:"
  echo "  --docker-cmd <command>                         (Required) The 'docker run' command output in the result of a mithril-client CLI download or snapshot converter command."
  echo "  --include-ancillary                            (Optional) Whether the ancillary files were included in the restoration."
  echo "  --ledger-backend <in-memory|lmdb|lsm|legacy>   (Optional) Specify the ledger backend. Default is 'in-memory'. Note: lmdb and lsm backends require --include-ancillary to be set."
  exit 1
fi

DOCKER_CMD=""
INCLUDE_ANCILLARY="false"
LEDGER_BACKEND="in-memory"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --docker-cmd) DOCKER_CMD="$2"; shift;;
        --include-ancillary) INCLUDE_ANCILLARY="true" ;;
        --ledger-backend) LEDGER_BACKEND="$2"; shift ;;
    esac
    shift
done

if [[ -z "$DOCKER_CMD" ]]; then
  echo "Error: argument '--docker-cmd \"docker run ...\"' is mandatory."
  exit 1
fi

echo "Docker command:"
echo "$DOCKER_CMD"

# Note: ledger conversion to an on disk backend can only be executed if ancillary files are included
if [[ "$INCLUDE_ANCILLARY" == "true" ]]; then
  case ${LEDGER_BACKEND,,} in
    lmdb)
      DOCKER_CMD="${DOCKER_CMD/ ghcr/" -e CARDANO_CONFIG_JSON_MERGE='{\"LedgerDB\":{\"Backend\":\"V1LMDB\"}}' ghcr"}"
      ;;
    lsm)
      # The LSM backend relies on io_uring syscalls which are blocked by the default Docker seccomp profile
      DOCKER_CMD="${DOCKER_CMD/ ghcr/" -e CARDANO_CONFIG_JSON_MERGE='{\"LedgerDB\":{\"Backend\":\"V2LSM\"}}' --security-opt seccomp=unconfined ghcr"}"
      ;;
  esac
fi

DOCKER_CMD_DETACHED="${DOCKER_CMD/docker run/docker run -d}"
echo "Running Docker command in detached mode:"
echo "$DOCKER_CMD_DETACHED"

CONTAINER_ID=$(eval "$DOCKER_CMD_DETACHED")

wait_for_log() {
  local CONTAINER_ID="$1"
  local TIMEOUT="$2"
  local LOG_MESSAGE="$3"

  echo "Waiting up to $TIMEOUT seconds for '$LOG_MESSAGE'..."
  for ((i=1; i<=TIMEOUT; i++)); do
    if docker logs "$CONTAINER_ID" 2>&1 | grep -q "$LOG_MESSAGE"; then
      echo "Found '$LOG_MESSAGE' in logs."
      return 0
    fi
    sleep 1
  done

  echo "'$LOG_MESSAGE' not found within $TIMEOUT seconds."
  docker logs "$CONTAINER_ID"
  return 1
}

if wait_for_log "$CONTAINER_ID" 15 "Started opening Immutable DB"; then
  echo "✅ The Cardano node started successfully from the Mithril snapshot."
else
  echo "❌ Failed to start the Cardano node from the Mithril snapshot."
  exit 1
fi

if [[ "$INCLUDE_ANCILLARY" == "true" ]]; then
  echo "Parameter '--include-ancillary' is set."
  if wait_for_log "$CONTAINER_ID" 30 "Chain extended, new tip"; then
    echo "✅ The Cardano node started successfully from the Mithril snapshot with the ancillary files."
    exit 0
  else
    echo "❌ Failed to start the Cardano node from the Mithril snapshot with the ancillary files."
    exit 1
  fi
else
  echo "Parameter '--include-ancillary' is not set."
  echo "Skipping additional check for 'Chain extended, new tip' in logs."
  exit 0
fi
