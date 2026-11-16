#!/usr/bin/env bash

# Script for creating keys for a cardano pool (SPO) / Tests only
## Inspired from https://docs.cardano.org/development-guidelines/operating-a-stake-pool/creating-a-stake-pool

# Import prelude
. $(dirname -- "$0")/_prelude.sh

if [ -z "${GENESIS_FILE}" ]; then
    echo Missing environment variable: GENESIS_FILE
    exit 1
fi

# Create keys and addresses
## Create payment keypair
CARDANO_CLI_CMD ${CARDANO_ERA} address key-gen \
--verification-key-file ${POOL_ARTIFACTS_DIR}/payment.vkey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/payment.skey

## Create stake keypair
CARDANO_CLI_CMD ${CARDANO_ERA} stake-address key-gen \
--verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/stake.skey

## Create payment address
CARDANO_CLI_CMD ${CARDANO_ERA} address build \
--payment-verification-key-file ${POOL_ARTIFACTS_DIR}/payment.vkey \
--stake-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--out-file ${POOL_ARTIFACTS_DIR}/payment.addr \
--testnet-magic $NETWORK_MAGIC

## Create stake address
CARDANO_CLI_CMD ${CARDANO_ERA} stake-address build \
--stake-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--out-file ${POOL_ARTIFACTS_DIR}/stake.addr \
--testnet-magic $NETWORK_MAGIC

# Generate your stake pool keys
## Generate Cold Keys and a Cold_counter
CARDANO_CLI_CMD ${CARDANO_ERA} node key-gen \
--cold-verification-key-file ${POOL_ARTIFACTS_DIR}/cold.vkey \
--cold-signing-key-file ${POOL_ARTIFACTS_DIR}/cold.skey \
--operational-certificate-issue-counter-file ${POOL_ARTIFACTS_DIR}/opcert.counter

## Generate VRF Key pair
CARDANO_CLI_CMD ${CARDANO_ERA} node key-gen-VRF \
--verification-key-file ${POOL_ARTIFACTS_DIR}/vrf.vkey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/vrf.skey

## Generate BLS Key pair (required to register a pool from the Dijkstra era)
if [ "${CARDANO_ERA}" = "dijkstra" ]; then
    CARDANO_CLI_CMD ${CARDANO_ERA} node key-gen-BLS \
    --verification-key-file ${POOL_ARTIFACTS_DIR}/bls.vkey \
    --signing-key-file ${POOL_ARTIFACTS_DIR}/bls.skey
fi

## Generate the KES Key pair
CARDANO_CLI_CMD ${CARDANO_ERA} node key-gen-KES \
--verification-key-file ${POOL_ARTIFACTS_DIR}/kes.vkey \
--signing-key-file ${POOL_ARTIFACTS_DIR}/kes.skey

## Generate the Operational Certificate
### Compute KES period
SLOT=$(CARDANO_CLI_CMD ${CARDANO_ERA} query tip --testnet-magic $NETWORK_MAGIC | jq .slot)
SLOTS_KES_PERIOD=$(cat $GENESIS_FILE | jq .slotsPerKESPeriod)
KES_PERIOD=$(( $SLOT / $SLOTS_KES_PERIOD ))

### Generate Operational Certificate
CARDANO_CLI_CMD ${CARDANO_ERA} node issue-op-cert \
--kes-verification-key-file ${POOL_ARTIFACTS_DIR}/kes.vkey \
--cold-signing-key-file ${POOL_ARTIFACTS_DIR}/cold.skey \
--operational-certificate-issue-counter ${POOL_ARTIFACTS_DIR}/opcert.counter \
--kes-period $KES_PERIOD \
--out-file ${POOL_ARTIFACTS_DIR}/opcert.cert

### Create a registration certificate
KEY_REGISTRATION_DEPOSIT_AMOUNT=$(CARDANO_CLI_CMD ${CARDANO_ERA} query gov-state --testnet-magic ${NETWORK_MAGIC} | jq -r .currentPParams.stakeAddressDeposit)
CARDANO_CLI_CMD ${CARDANO_ERA} stake-address registration-certificate \
--stake-verification-key-file ${POOL_ARTIFACTS_DIR}/stake.vkey \
--out-file ${POOL_ARTIFACTS_DIR}/stake.cert \
--key-reg-deposit-amt $KEY_REGISTRATION_DEPOSIT_AMOUNT


### Compute Pool Id
POOL_ID=$(CARDANO_CLI_CMD ${CARDANO_ERA} stake-pool id --cold-verification-key-file ${POOL_ARTIFACTS_DIR}/cold.vkey)
echo $POOL_ID > ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/pool-id.txt
echo POOL_ID=$POOL_ID

### Send funds to / Check utxo payment address
echo Send funds to "$(cat ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/payment.addr)" at https://docs.cardano.org/cardano-testnet/tools/faucet
while true
do  
    UTXO_ROWS_NUMBER=$(( $(CARDANO_CLI_CMD ${CARDANO_ERA} query utxo --address $(cat ${POOL_ARTIFACTS_DIR_PREFIX}${POOL_ARTIFACTS_DIR}/payment.addr) --testnet-magic $NETWORK_MAGIC 2> /dev/null | wc -l) - 2 ))
    if [ $UTXO_ROWS_NUMBER -gt 0 ] ; then
        echo ">>>> Funds Received!"
        break
    else
        echo ">>>> Waiting for Funds..."
        sleep 10
    fi
done
