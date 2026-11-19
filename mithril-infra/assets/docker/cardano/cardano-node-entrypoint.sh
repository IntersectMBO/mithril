#!/bin/sh
# Entrypoint of the Cardano node images built from 'Dockerfile.cardano'.
#
# Delegates to the entrypoint of the base image when it exists ('bundle-entrypoint' for the
# Cardano/Mithril bundle image, 'entrypoint' for the official Cardano node image).
# Otherwise (e.g. the Leios node image, whose entrypoint is the bare 'cardano-node' binary),
# runs 'cardano-node' with the given arguments and the socket path that the official
# entrypoint would add ('CARDANO_SOCKET_PATH', '/ipc/node.socket' by default).
set -e

for BASE_IMAGE_ENTRYPOINT in bundle-entrypoint entrypoint; do
  if command -v "$BASE_IMAGE_ENTRYPOINT" > /dev/null 2>&1; then
    exec "$BASE_IMAGE_ENTRYPOINT" "$@"
  fi
done

if ! command -v cardano-node > /dev/null 2>&1; then
  echo "cardano-node-entrypoint: 'cardano-node' is not in the PATH" >&2
  exit 1
fi

if [ "$1" = "run" ]; then
  set -- "$@" --socket-path "${CARDANO_SOCKET_PATH:-/ipc/node.socket}"
fi

exec cardano-node "$@"
