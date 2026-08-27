# Create Mithril era keypair and address
ADDR=mithril-era

## Payment address keys
$CARDANO_CLI "$CARDANO_CLI_ERA" address key-gen \
    --verification-key-file addresses/${ADDR}.vkey \
    --signing-key-file      addresses/${ADDR}.skey

## Payment addresses
$CARDANO_CLI "$CARDANO_CLI_ERA" address build \
    --payment-verification-key-file addresses/${ADDR}.vkey \
    --testnet-magic "${NETWORK_MAGIC}" \
    --out-file addresses/${ADDR}.addr

## Write datums for Mithril era address
N=1
SCRIPT_TX_VALUE=2000000
AMOUNT_TRANSFERRED=$(( SCRIPT_TX_VALUE * 10 ))

cat >> era-mithril.sh <<EOF
#!/usr/bin/env bash
set -e

. "cardano-chain.sh"

# Try to send funds to protocol configuration address
try_send_funds_to_address "${ADDR}" "${AMOUNT_TRANSFERRED}" "era" "${N}"

# Try to write datums for protocol configuration address
try_write_datums_for_address "${ADDR}" "${SCRIPT_TX_VALUE}" "era" "${N}" "\${DATUM_FILE}"
    
EOF

chmod u+x era-mithril.sh
