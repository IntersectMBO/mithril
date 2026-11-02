# Create Mithril receiver keypair and address (if not already exist)
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
  do
    ADDR_RX=mithril-rx${i}
    if [ ! -f addresses/${ADDR_RX}.addr ]; then
        ## Payment address keys
        $CARDANO_CLI $CARDANO_CLI_ERA address key-gen \
            --verification-key-file addresses/${ADDR_RX}.vkey \
            --signing-key-file      addresses/${ADDR_RX}.skey

        ## Payment addresses
        $CARDANO_CLI $CARDANO_CLI_ERA address build \
            --payment-verification-key-file addresses/${ADDR_RX}.vkey \
            --testnet-magic ${NETWORK_MAGIC} \
            --out-file addresses/${ADDR_RX}.addr
    fi
done

## Send funds to Mithril receiver addresses
N=1
TX_ID_OUTPUT_FILE=transaction-hashes.txt
SUB_TX_ID_OUTPUT_FILE=sub-transaction-hashes.txt
BLOCK_HASH_OUTPUT_FILE=block-hashes.txt
NESTED_FEE=500000
cat >> payment-mithril.sh <<EOF
#!/usr/bin/env bash
set -e

# Set default payment iterations value
if [ -z "\${PAYMENT_ITERATIONS}" ]; then 
  PAYMENT_ITERATIONS=3
fi
NESTED_PAYMENT_ATTEMPTED=false

# Wait for a number of blocks has elapsed
function wait_for_elapsed_blocks {
    CARDANO_BLOCK_OFFSET=\$1
    CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX=30
    CARDANO_NEXT_BLOCK_WAIT_ROUNDS=1
    CARDANO_NEXT_BLOCK_WAIT_ROUND_DELAY=2
    CURRENT_CARDANO_BLOCK=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.block')
    while true
    do
        CARDANO_BLOCK_TARGET=\$(( \${CURRENT_CARDANO_BLOCK} + \${CARDANO_BLOCK_OFFSET} ))
        CARDANO_BLOCK=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.block')
        if [ \$CARDANO_BLOCK -lt \$CARDANO_BLOCK_TARGET ] ; then
            echo ">>>> Cardano target block not reached yet... [current: \$CARDANO_BLOCK, target: \$CARDANO_BLOCK_TARGET] [attempt \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS]"
            sleep \$CARDANO_NEXT_BLOCK_WAIT_ROUND_DELAY
        else
            echo ">>>> Cardano target block is reached [current: \$CARDANO_BLOCK, target: \$CARDANO_BLOCK_TARGET] [attempt \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS]"
            sleep \$CARDANO_NEXT_BLOCK_WAIT_ROUND_DELAY
            break
        fi
        CARDANO_NEXT_BLOCK_WAIT_ROUNDS=\$(( \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS + 1 ))
        if [ "\$CARDANO_NEXT_BLOCK_WAIT_ROUNDS" -gt "\$CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX" ] ; then
            echo ">>>> Timeout: Cardano target block was not reached within \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX attempts"
            exit 1
        fi
    done
}

EOF

cat >> payment-mithril.sh <<EOF
function process_payment_iteration {
    j=\$1
    echo ">>>> Payment iteration #\${j}/\${PAYMENT_ITERATIONS} in progress..."

EOF
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
do
    ADDR_RX=mithril-rx${i}
cat >> payment-mithril.sh <<EOF
    # Get current Cardano era
    CURRENT_CARDANO_ERA=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.era |= ascii_downcase | .era')
    echo ">>>>>> Current Cardano Era: \${CURRENT_CARDANO_ERA}"

    ## Get the tip block hash
    BLOCK_HASH=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query tip --testnet-magic ${NETWORK_MAGIC} | jq -r '.hash')

    # Set the amount to be transferred
    AMOUNT_TRANSFERRED=\$(( 2000000 + 10 * ${i} + j))
    echo ">>>>>> Send funds: \${AMOUNT_TRANSFERRED} Lovelace from 'utxo${i}.addr' to '${ADDR_RX}.addr'"

    # Send funds to Mithril receiver address
    ## Get the UTxO of utxo${i}
    TX_IN=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/utxo${i}.addr) --out-file /dev/stdout \\
        | jq  -r 'to_entries | [last] | .[0].key')

    ## Build the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
        --tx-in \${TX_IN} \\
        --tx-out \$(cat addresses/${ADDR_RX}.addr)+\${AMOUNT_TRANSFERRED} \\
        --change-address \$(cat addresses/utxo${i}.addr) \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --invalid-hereafter 100000 \\
        --out-file node-pool${i}/tx/tx${i}-payment-funds.txbody

    ## Sign the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction sign \\
        --signing-key-file addresses/utxo${i}.skey \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --tx-body-file  node-pool${i}/tx/tx${i}-payment-funds.txbody \\
        --out-file      node-pool${i}/tx/tx${i}-payment-funds.tx

    ## Submit the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction submit \\
        --tx-file node-pool${i}/tx/tx${i}-payment-funds.tx \\
        --testnet-magic ${NETWORK_MAGIC}
EOF
done
cat >> payment-mithril.sh <<EOF
    ## Wait at least for 10 blocks so that the transaction is confirmed
    wait_for_elapsed_blocks 10

EOF
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
do
    ADDR_RX=mithril-rx${i}
cat >> payment-mithril.sh <<EOF

    ## Compute the submitted transaction id
    TX_ID_SUBMITTED=\$($CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction txid --tx-file node-pool${i}/tx/tx${i}-payment-funds.tx)
    if [[ "\${TX_ID_SUBMITTED}" =~ txhash ]]; then
        TX_ID_SUBMITTED=\$(echo \$TX_ID_SUBMITTED | jq -r '.txhash')
    fi

    ## Retrieve the on-chain transaction id
    TX_IN_ON_CHAIN=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/utxo${i}.addr) --out-file /dev/stdout \\
        | jq  -r 'to_entries | [last] | .[0].key' | cut -d '#' -f 1)
    
    ## Save the transaction id to file
    if [ "\$TX_ID_SUBMITTED" == "\$TX_IN_ON_CHAIN" ]; then
        ## Save the transaction id to file
        echo ">>>>>> Save transaction id #\${TX_ID_SUBMITTED} to ${TX_ID_OUTPUT_FILE} file"
        echo \$TX_ID_SUBMITTED >> ${TX_ID_OUTPUT_FILE}
        ## Save the block hash to file
        echo ">>>>>> Save block hash #\${BLOCK_HASH} to ${BLOCK_HASH_OUTPUT_FILE} file"
        echo \$BLOCK_HASH >> ${BLOCK_HASH_OUTPUT_FILE}
    else
        ## Save the transaction id to file
        echo ">>>>>> Transaction #\${TX_ID_SUBMITTED} has likely been rolled-back and will not be recorded to ${TX_ID_OUTPUT_FILE} file"
    fi
EOF
done
cat >> payment-mithril.sh <<EOF
    
}
EOF

## Send funds to Mithril receiver addresses with nested transactions (Dijkstra era only)
cat >> payment-mithril.sh <<EOF
function process_nested_payment_iteration {
    j=\$1

    # Get current Cardano era
    CURRENT_CARDANO_ERA=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.era |= ascii_downcase | .era')
    if [ "\${CURRENT_CARDANO_ERA}" != "dijkstra" ]; then
        return
    fi
    NESTED_PAYMENT_ATTEMPTED=true
    echo ">>>> Nested payment iteration #\${j}/\${PAYMENT_ITERATIONS} in progress..."

EOF
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
do
    ADDR_RX=mithril-rx${i}
cat >> payment-mithril.sh <<EOF
    # Set the amount to be transferred by the sub-transaction
    AMOUNT_NESTED=\$(( 3000000 + 10 * ${i} + j))
    echo ">>>>>> Send funds: \${AMOUNT_NESTED} Lovelace from 'utxo${i}.addr' to '${ADDR_RX}.addr' with a sub-transaction nested in a transaction of '${ADDR_RX}.addr'"
    rm -f node-pool${i}/tx/tx${i}-nested-sub.unsigned node-pool${i}/tx/tx${i}-nested-sub.signed node-pool${i}/tx/tx${i}-nested-top.txbody node-pool${i}/tx/tx${i}-nested-top.tx

    ## Get the largest UTxO of utxo${i}, which funds the sub-transaction, and of ${ADDR_RX}, which pays the top-level transaction
    SUB_TX_UTXO=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/utxo${i}.addr) --out-file /dev/stdout \\
        | jq  -c 'to_entries | max_by(.value.value.lovelace)')
    SUB_TX_IN=\$(echo \${SUB_TX_UTXO} | jq -r '.key')
    SUB_TX_IN_AMOUNT=\$(echo \${SUB_TX_UTXO} | jq -r '.value.value.lovelace')
    TOP_TX_UTXO=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/${ADDR_RX}.addr) --out-file /dev/stdout \\
        | jq  -c 'to_entries | max_by(.value.value.lovelace)')
    TOP_TX_IN=\$(echo \${TOP_TX_UTXO} | jq -r '.key')
    TOP_TX_IN_AMOUNT=\$(echo \${TOP_TX_UTXO} | jq -r '.value.value.lovelace')
    if [ -z "\${SUB_TX_IN}" ] || [ "\${SUB_TX_IN}" == "null" ] || [ -z "\${TOP_TX_IN}" ] || [ "\${TOP_TX_IN}" == "null" ]; then
        echo ">>>>>> Skip the nested payment of 'utxo${i}.addr' to '${ADDR_RX}.addr': one of the addresses holds no confirmed UTxO yet"
    else

    ## Build the sub-transaction, guarded and signed by the key of utxo${i}
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} sub-transaction build-raw \\
        --tx-in \${SUB_TX_IN} \\
        --tx-out \$(cat addresses/${ADDR_RX}.addr)+\${AMOUNT_NESTED} \\
        --tx-out \$(cat addresses/utxo${i}.addr)+\$(( \${SUB_TX_IN_AMOUNT} - \${AMOUNT_NESTED} )) \\
        --guard-key-hash \$($CARDANO_CLI \${CURRENT_CARDANO_ERA} address key-hash --payment-verification-key-file addresses/utxo${i}.vkey) \\
        --out-file node-pool${i}/tx/tx${i}-nested-sub.unsigned

    ## Sign the sub-transaction
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} sub-transaction sign \\
        --sub-tx-file node-pool${i}/tx/tx${i}-nested-sub.unsigned \\
        --signing-key-file addresses/utxo${i}.skey \\
        --out-file node-pool${i}/tx/tx${i}-nested-sub.signed

    # Build the top-level transaction embedding the sub-transaction, paid and signed by ${ADDR_RX}
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build-raw \\
        --tx-in \${TOP_TX_IN} \\
        --tx-out \$(cat addresses/${ADDR_RX}.addr)+\$(( \${TOP_TX_IN_AMOUNT} - ${NESTED_FEE} )) \\
        --fee ${NESTED_FEE} \\
        --signed-sub-tx-file node-pool${i}/tx/tx${i}-nested-sub.signed \\
        --out-file node-pool${i}/tx/tx${i}-nested-top.txbody

    ## Sign the top-level transaction
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction sign \\
        --signing-key-file addresses/${ADDR_RX}.skey \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --tx-body-file  node-pool${i}/tx/tx${i}-nested-top.txbody \\
        --out-file      node-pool${i}/tx/tx${i}-nested-top.tx

    ## Submit the nested transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction submit \\
        --tx-file node-pool${i}/tx/tx${i}-nested-top.tx \\
        --testnet-magic ${NETWORK_MAGIC}
    fi
EOF
done
cat >> payment-mithril.sh <<EOF
    ## Wait at least for 10 blocks so that the nested transactions are confirmed
    wait_for_elapsed_blocks 10

EOF
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
do
    ADDR_RX=mithril-rx${i}
cat >> payment-mithril.sh <<EOF

    ## Compute the submitted sub-transaction and top-level transaction ids
    if [ ! -f node-pool${i}/tx/tx${i}-nested-top.tx ]; then
        echo ">>>>>> No nested transaction of '${ADDR_RX}.addr' was submitted in this iteration"
    else
    SUB_TX_ID_SUBMITTED=\$($CARDANO_CLI \${CURRENT_CARDANO_ERA} sub-transaction txid --signed-sub-tx-file node-pool${i}/tx/tx${i}-nested-sub.signed --output-text)
    TOP_TX_ID_SUBMITTED=\$($CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction txid --tx-file node-pool${i}/tx/tx${i}-nested-top.tx --output-text)

    ## Save the transaction ids to file when the sub-transaction output is on chain
    if CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/${ADDR_RX}.addr) --out-file /dev/stdout \\
        | jq -e --arg tx_in "\${SUB_TX_ID_SUBMITTED}#0" 'has(\$tx_in)' > /dev/null; then
        echo ">>>>>> Save sub-transaction id #\${SUB_TX_ID_SUBMITTED} to ${SUB_TX_ID_OUTPUT_FILE} file"
        echo \$SUB_TX_ID_SUBMITTED >> ${SUB_TX_ID_OUTPUT_FILE}
        echo ">>>>>> Save transaction id #\${TOP_TX_ID_SUBMITTED} to ${TX_ID_OUTPUT_FILE} file"
        echo \$TOP_TX_ID_SUBMITTED >> ${TX_ID_OUTPUT_FILE}
    else
        echo ">>>>>> Nested transaction #\${TOP_TX_ID_SUBMITTED} has likely been rolled-back and will not be recorded to ${TX_ID_OUTPUT_FILE} file"
    fi
    fi
EOF
done
cat >> payment-mithril.sh <<EOF
    
}
EOF

cat >> payment-mithril.sh <<EOF
# Run payment iterations
for (( j=1; j<=\${PAYMENT_ITERATIONS}; j++ ))
do
    set +e
    process_payment_iteration \$j
    process_nested_payment_iteration \$j
    set -e
done

# Check that at least one transaction has been successfully submitted
TOTAL_TX_SUBMITTED=\$(cat ${TX_ID_OUTPUT_FILE} | wc -l)
if [ \$TOTAL_TX_SUBMITTED -eq 0 ]; then
    echo ">>>>>> Error: No transaction was successfully submitted!"
    exit 1
fi

# Check that at least one nested transaction has been successfully submitted when the Dijkstra era was reached
TOTAL_SUB_TX_SUBMITTED=\$(cat ${SUB_TX_ID_OUTPUT_FILE} 2> /dev/null | wc -l)
if [ "\${NESTED_PAYMENT_ATTEMPTED}" == "true" ] && [ \$TOTAL_SUB_TX_SUBMITTED -eq 0 ]; then
    echo ">>>>>> Error: No nested transaction was successfully submitted!"
    exit 1
fi

# Deduplicate block hashes file
sort -u ${BLOCK_HASH_OUTPUT_FILE} -o ${BLOCK_HASH_OUTPUT_FILE}

EOF

chmod u+x payment-mithril.sh
