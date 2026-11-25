#!/usr/bin/env bash

# Script for registering a cardano stake pool (SPO) / Tests only
## Inspired from https://docs.cardano.org/development-guidelines/operating-a-stake-pool/creating-a-stake-pool

# Import prelude
. $(dirname -- "$0")/_prelude.sh

if [ -z "${GENESIS_FILE}" ]; then
    echo Missing environment variable: GENESIS_FILE
    exit 1
fi

# Check if all env vars are set
if [ -z "${TX_IN}" ]; then
    echo Missing environment variable: TX_IN
    exit 1
fi

if [ -z "${POOL_TICKER}" ]; then
    echo Missing environment variable: POOL_TICKER
    exit 1
fi

if [ -z "${SIGNER_DOMAIN}" ]; then
    echo Missing environment variable: SIGNER_DOMAIN
    exit 1
fi

# Create pool metadata
cat > ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_WWW_DIR}/pool-metadata.json << EOF
{
"name": "Mithril Signer ${POOL_TICKER}",
"description": "Mithril Signer Node ${SIGNER_DOMAIN}",
"ticker": "${POOL_TICKER}",
"homepage": "https://mithril.network"
}
EOF
POOL_METADATA_HASH=$(CARDANO_CLI_CMD ${CARDANO_ERA} stake-pool metadata-hash --pool-metadata-file ${POOL_WWW_DIR}/pool-metadata.json)

# Generate stake pool registration certificate
POOL_PLEDGE=$AMOUNT_STAKED
POOL_COST=$(cat $GENESIS_FILE | jq .protocolParams.minPoolCost)
POOL_MARGIN=0.1
POOL_METADATA_URL=$(curl -s https://tinyurl.com/api-create.php?url=https://${SIGNER_NODE}.${SIGNER_DOMAIN}/pool-metadata.json)
POOL_RELAY_URL="${SIGNER_NODE}.${SIGNER_DOMAIN}"
POOL_RELAY_PORT=$(cat ${POOL_ARTIFACTS_DIR_PREFIX}/pool/port)
SLOT=$(CARDANO_CLI_CMD ${CARDANO_ERA} query tip --testnet-magic $NETWORK_MAGIC | jq .slot)

# Build registration certificate
BLS_KEY_ARGS=""
if [ "${CARDANO_ERA}" = "dijkstra" ]; then
    BLS_KEY_ARGS="--bls-signing-key-file ${POOL_ARTIFACTS_DIR}/bls.skey"
fi
CARDANO_CLI_CMD ${CARDANO_ERA} stake-pool registration-certificate \
--cold-verification-key-file ${POOL_ARTIFACTS_DIR}/cold.vkey \
--vrf-verification-key-file ${POOL_ARTIFACTS_DIR}/vrf.vkey \
${BLS_KEY_ARGS} \
--pool-pledge $POOL_PLEDGE \
--pool-cost $POOL_COST \
--pool-margin $POOL_MARGIN \
--pool-reward-account-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--pool-owner-stake-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--testnet-magic $NETWORK_MAGIC \
--single-host-pool-relay $POOL_RELAY_URL \
--pool-relay-port $POOL_RELAY_PORT \
--metadata-url $POOL_METADATA_URL \
--metadata-hash $POOL_METADATA_HASH \
--out-file ${POOL_ARTIFACTS_DIR}/pool-registration.cert

# Generate delegation certificate pledge
CARDANO_CLI_CMD ${CARDANO_ERA} stake-address stake-delegation-certificate \
--stake-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--cold-verification-key-file ${POOL_ARTIFACTS_DIR}/cold.vkey \
--out-file ${POOL_ARTIFACTS_DIR}/delegation.cert

# Submit the pool certificate and delegation certificate to the blockchain
## Build transaction
STAKE_ADDRESS_DEPOSIT=$(cat $GENESIS_FILE | jq .protocolParams.poolDeposit)
CARDANO_CLI_CMD ${CARDANO_ERA} transaction build \
--tx-in $TX_IN \
--tx-out $(cat ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/payment.addr)+$STAKE_ADDRESS_DEPOSIT \
--change-address $(cat ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/payment.addr) \
--invalid-hereafter $(( $SLOT + 100000 )) \
--out-file ${POOL_ARTIFACTS_DIR}/pool-registration.txbody \
--certificate-file ${POOL_ARTIFACTS_DIR}/pool-registration.cert \
--certificate-file ${POOL_ARTIFACTS_DIR}/delegation.cert \
--witness-override 4 \
--testnet-magic $NETWORK_MAGIC

# Sign transaction
CARDANO_CLI_CMD ${CARDANO_ERA} transaction sign \
--signing-key-file ${POOL_ARTIFACTS_DIR}/payment.skey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/stake.skey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/cold.skey \
--testnet-magic $NETWORK_MAGIC \
--tx-body-file  ${POOL_ARTIFACTS_DIR}/pool-registration.txbody \
--out-file      ${POOL_ARTIFACTS_DIR}/pool-registration.tx

# Submit transaction
CARDANO_NODE_SOCKET_PATH=$CARDANO_NODE_SOCKET_PATH CARDANO_CLI_CMD ${CARDANO_ERA} transaction submit \
--tx-file ${POOL_ARTIFACTS_DIR}/pool-registration.tx \
--testnet-magic $NETWORK_MAGIC

### Compute Pool Id
POOL_ID=$(CARDANO_CLI_CMD ${CARDANO_ERA} stake-pool id --cold-verification-key-file ${POOL_ARTIFACTS_DIR}/cold.vkey)
echo $POOL_ID > ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/pool-id.txt
echo POOL_ID=$POOL_ID

### Delegate stakes to the pool
echo Delegate stakes to pool id "$POOL_ID" at https://docs.cardano.org/cardano-testnet/tools/faucet

