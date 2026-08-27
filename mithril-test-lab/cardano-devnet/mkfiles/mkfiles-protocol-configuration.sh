# Create Mithril protocol configuration keypair and address
ADDR=protocol-config

## Payment address keys
$CARDANO_CLI "$CARDANO_CLI_ERA" address key-gen \
    --verification-key-file addresses/${ADDR}.vkey \
    --signing-key-file      addresses/${ADDR}.skey

## Payment addresses
$CARDANO_CLI "$CARDANO_CLI_ERA" address build \
    --payment-verification-key-file addresses/${ADDR}.vkey \
    --testnet-magic "${NETWORK_MAGIC}" \
    --out-file addresses/${ADDR}.addr

## Write datums for protocol configuration address
N=1
SCRIPT_TX_VALUE=7200000
AMOUNT_TRANSFERRED=$(( SCRIPT_TX_VALUE * 10 ))

cat >> protocol-configuration.sh <<EOF
#!/usr/bin/env bash
set -e

. "cardano-chain.sh"

# Try to send funds to protocol configuration address
try_send_funds_to_address "${ADDR}" "${AMOUNT_TRANSFERRED}" "protocol-configuration" "${N}"

# Try to write datums for protocol configuration address
try_write_datums_for_address "${ADDR}" "${SCRIPT_TX_VALUE}" "protocol-configuration" "${N}" "\${PROTOCOL_CONFIG_DATUM_FILE}"
    
EOF

chmod u+x protocol-configuration.sh
