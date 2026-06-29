# Get the operating system
UNAME=$(uname -s) OPERATING_SYSTEM=
case $UNAME in
  Darwin )      OPERATING_SYSTEM="macos";;
  Linux )       OPERATING_SYSTEM="linux";;
  * )           echo "Error: Unsupported operating system. This script can only be run on Linux or MacOS."
                exit 1;;
esac

# Get the architecture
UNAME_ARCH=$(uname -m)
case $UNAME_ARCH in
  x86_64 )      ARCHITECTURE="amd64";;
  arm64 )       ARCHITECTURE="arm64";;
  aarch64 )     ARCHITECTURE="arm64";;
  * )           echo "Error: Unsupported architecture. Only amd64 and arm64 are supported."
                exit 1;;
esac

# Is semver on the first argument strictly lower than equal to the second argument?
version_lt() {
  VERSION_LHS=$1
  VERSION_RHS=$2
  if [ "${VERSION_LHS}" != "${VERSION_RHS}" ] && [ "${VERSION_LHS}" = "`echo -e "${VERSION_LHS}\n${VERSION_RHS}" | sort -V | head -n1`" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Cardano node version
if [ -z "${CARDANO_NODE_VERSION}" ]; then 
  CARDANO_NODE_VERSION="11.0.1"
fi
if [ -z "${CARDANO_NODE_VERSION_RELEASE}" ]; then 
  CARDANO_NODE_VERSION_RELEASE=$(echo "${CARDANO_NODE_VERSION}" | cut -d'-' -f1)
fi
if [ -z "${CARDANO_BINARY_URL}" ]; then 
  if [ "$(version_lt ${CARDANO_NODE_VERSION_RELEASE} 10.6.0)" = "true" ]; then
    CARDANO_BINARY_URL="https://github.com/IntersectMBO/cardano-node/releases/download/${CARDANO_NODE_VERSION}/cardano-node-${CARDANO_NODE_VERSION_RELEASE}-${OPERATING_SYSTEM}.tar.gz"
  else
    CARDANO_BINARY_URL="https://github.com/IntersectMBO/cardano-node/releases/download/${CARDANO_NODE_VERSION}/cardano-node-${CARDANO_NODE_VERSION_RELEASE}-${OPERATING_SYSTEM}-${ARCHITECTURE}.tar.gz"
  fi
fi
if [ -z "${CARDANO_CLI_ERA}" ]; then
    CARDANO_CLI_ERA=latest
fi
if [ -z "${NETWORK_MAGIC}" ]; then 
  NETWORK_MAGIC=42
fi
if [ -z "${DMQ_NODE_VERSION}" ]; then 
  DMQ_NODE_VERSION="0.7.0.0"
fi
if [ -z "${DMQ_NODE_BINARY_URL}" ]; then 
  DMQ_NODE_BINARY_URL="https://github.com/IntersectMBO/dmq-node/releases/download/${DMQ_NODE_VERSION}/dmq-node-linux.tar.gz"
fi
if [ -z "${DMQ_NETWORK_MAGIC}" ]; then 
  DMQ_NETWORK_MAGIC=2147483690
fi
if [ -z "${HARD_FORK_BABBAGE_AT_EPOCH}" ]; then 
  HARD_FORK_BABBAGE_AT_EPOCH=0
fi
if [ -n "${CARDANO_HARD_FORK_LATEST_ERA_AT_EPOCH}" ]; then 
  HARD_FORK_CONWAY_AT_EPOCH=$(( HARD_FORK_BABBAGE_AT_EPOCH + CARDANO_HARD_FORK_LATEST_ERA_AT_EPOCH ))
fi
if [ -z "${HARD_FORK_CONWAY_AT_EPOCH}" ]; then 
  HARD_FORK_CONWAY_AT_EPOCH=0
fi
if [ -z "${NUM_FULL_NODES}" ]; then 
  NUM_FULL_NODES="1"
fi
if [ -z "${NUM_POOL_NODES}" ]; then 
  NUM_POOL_NODES="2"
fi
if [ -z "${SLOT_LENGTH}" ]; then 
  SLOT_LENGTH="0.75"
fi
if [ -z "${EPOCH_LENGTH}" ]; then 
  EPOCH_LENGTH="100"
fi
if [ -z "${LISTENING_ADDR}" ]; then
  LISTENING_ADDR="127.0.0.1"
fi
DEVNET_VERSION=$(cat VERSION)

# Display configuration summary
echo ">> Devnet Version: ${DEVNET_VERSION}"
echo ">> Artifacts Directory[env::ARTIFACTS_DIR]: ${ARTIFACTS_DIR}"
echo ">> Cardano Full nodes [env::NUM_FULL_NODES]: ${NUM_FULL_NODES}"
echo ">> Cardano SPO nodes [env::NUM_POOL_NODES]: ${NUM_POOL_NODES}"
echo ">> Cardano Node Version [env::CARDANO_NODE_VERSION]: ${CARDANO_NODE_VERSION}"
echo ">> Cardano Network Magic [env::NETWORK_MAGIC]: ${NETWORK_MAGIC}"
echo ">> Cardano Hard Fork Babbage At Epoch [env::HARD_FORK_BABBAGE_AT_EPOCH]: ${HARD_FORK_BABBAGE_AT_EPOCH}"
echo ">> Cardano Hard Fork Conway At Epoch [env::HARD_FORK_CONWAY_AT_EPOCH]: ${HARD_FORK_CONWAY_AT_EPOCH}"
echo ">> Cardano Slot Length [env::SLOT_LENGTH]: ${SLOT_LENGTH}s"
echo ">> Cardano Epoch Length [env::EPOCH_LENGTH]: ${EPOCH_LENGTH}s"
echo ">> Cardano Listening Address [env::LISTENING_ADDR]: ${LISTENING_ADDR}"

# Check if root directory already exists
if ! mkdir -p "${ARTIFACTS_DIR}"; then
  echo "The ${ARTIFACTS_DIR} directory already exists, please move or remove it"
  exit
fi

echo ">> Creating artifacts directory..."
# Download cardano-cli & cardano-node if enabled (default: yes)
if [[ "$SKIP_CARDANO_BIN_DOWNLOAD" != "true" ]]; then
  echo ">> Downloading cardano-cli & cardano-node..."
  curl -sL "${CARDANO_BINARY_URL}" --output cardano-bin.tar.gz
  echo ">> Extracting cardano-cli & cardano-node..."
  # First tar when archive has a 'bin' directory, and second tar is to handle legacy archive without 'bin' directory
  tar xzf cardano-bin.tar.gz -C "${ARTIFACTS_DIR}/" ./bin || (mkdir -p "${ARTIFACTS_DIR}/bin" && tar --strip-components=1 -C "${ARTIFACTS_DIR}/bin" -xzf cardano-bin.tar.gz)
  rm -f cardano-bin.tar.gz
else
  echo ">> Skipping cardano-cli & cardano-node download, copying from local bin directory..."
  mkdir -p "${ARTIFACTS_DIR}/bin"
  cp "${SCRIPT_DIRECTORY}/bin/cardano-node" "${ARTIFACTS_DIR}/bin/cardano-node"
  cp "${SCRIPT_DIRECTORY}/bin/cardano-cli" "${ARTIFACTS_DIR}/bin/cardano-cli"
fi

# Download DMQ node binary if enabled (default: yes)
if [[ "$SKIP_DMQ_BIN_DOWNLOAD" != "true" ]]; then
  echo ">> Downloading dmq node binary..."
  curl -sL "${DMQ_NODE_BINARY_URL}" --output dmq-bin.tar.gz
  echo ">> Extracting dmq-node..."
  tar xzf dmq-bin.tar.gz --strip-components=2 -C "${ARTIFACTS_DIR}/bin" result/bin
  rm -f dmq-bin.tar.gz
fi
set +x

# Switch to artifacts directory
pushd "${ARTIFACTS_DIR}" > /dev/null || exit

# Create addresses sub-directory
mkdir addresses
