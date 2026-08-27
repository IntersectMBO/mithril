cat >> cardano-chain.sh <<EOF
#!/usr/bin/env bash
set -e

# Wait for a number of blocks has elapsed
function wait_for_elapsed_blocks {
    N=\$1
    CARDANO_BLOCK_OFFSET=\$2

    CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX=30
    CARDANO_NEXT_BLOCK_WAIT_ROUNDS=1
    CARDANO_NEXT_BLOCK_WAIT_ROUND_DELAY=2
    CURRENT_CARDANO_BLOCK=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.block')
    while true
    do
        CARDANO_BLOCK_TARGET=\$(( \${CURRENT_CARDANO_BLOCK} + \${CARDANO_BLOCK_OFFSET} ))
        CARDANO_BLOCK=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.block')
        if [ \$CARDANO_BLOCK -lt \$CARDANO_BLOCK_TARGET ] ; then
            echo ">>>> Cardano target block not reached yet... [current: \$CARDANO_BLOCK, target: \$CARDANO_BLOCK_TARGET] [attempt \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS]"
            sleep \$CARDANO_NEXT_BLOCK_WAIT_ROUND_DELAY
        else
            echo ">>>> Cardano target block is reached [current: \$CARDANO_BLOCK, target: \$CARDANO_BLOCK_TARGET] [attempt \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS]"
            break
        fi
        CARDANO_NEXT_BLOCK_WAIT_ROUNDS=\$(( \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS + 1 ))
        if [ "\$CARDANO_NEXT_BLOCK_WAIT_ROUNDS" -gt "\$CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX" ] ; then
            echo ">>>> Timeout: Cardano target block was not reached within \$CARDANO_NEXT_BLOCK_WAIT_ROUNDS_MAX attempts"
            exit 1
        fi
    done
}

# Send funds to address
function send_funds_to_address {
    ADDR=\$1
    AMOUNT_TRANSFERRED=\$2
    CONTEXT=\$3
    N=\$4

    echo ">>>> Gonna send_funds_to_address \${ADDR} \${AMOUNT_TRANSFERRED} \${CONTEXT} \${N}"

    # Remove if exists previous error file
    ERROR_FILE=\${CONTEXT}-error
    rm -f -- "\${ERROR_FILE}"

    # Get current Cardano era
    CURRENT_CARDANO_ERA=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.era |= ascii_downcase | .era')
    echo ">>>> Current Cardano Era: \${CURRENT_CARDANO_ERA}"

    # Get current Cardano block
    CURRENT_CARDANO_BLOCK=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
        --testnet-magic ${NETWORK_MAGIC} \\
        | jq  -r '.block')
    echo ">>>> Current Cardano Block: \${CURRENT_CARDANO_BLOCK}"

    # Send funds to address
    ## Get the UTxO of utxo\${N}
    TX_IN=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/utxo\${N}.addr) --out-file /dev/stdout \\
        | jq  -r 'to_entries | [last] | .[0].key')

    ## Build the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
        --tx-in \${TX_IN} \\
        --tx-out \$(cat addresses/\${ADDR}.addr)+\${AMOUNT_TRANSFERRED} \\
        --change-address \$(cat addresses/utxo\${N}.addr) \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --invalid-hereafter 100000 \\
        --out-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-funds.txbody

    ## Sign the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction sign \\
        --signing-key-file addresses/utxo\${N}.skey \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --tx-body-file  node-pool\${N}/tx/tx\${N}-\${CONTEXT}-funds.txbody \\
        --out-file      node-pool\${N}/tx/tx\${N}-\${CONTEXT}-funds.tx

    ## Submit the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction submit \\
        --tx-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-funds.tx \\
        --testnet-magic ${NETWORK_MAGIC}

    ## Compute the submitted transaction id
    TX_ID_SUBMITTED=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction txid --tx-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-funds.tx)
    if [[ "\${TX_ID_SUBMITTED}" =~ txhash ]]; then
        TX_ID_SUBMITTED=\$(echo \$TX_ID_SUBMITTED | jq -r '.txhash')
    fi
    
    ## Wait at least for 10 blocks so that the transaction is confirmed
    wait_for_elapsed_blocks "\${N}" 10

    ## Wait for all pool nodes to see the new transaction
    for (( i=1; i<=${NUM_POOL_NODES}; i++ )); do
        TOTAL_UTXOS_FOR_TX_ID=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${i}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/\${ADDR}.addr) --out-file /dev/stdout \\
        | jq '. | with_entries(select(.key | startswith("${TX_ID_SUBMITTED}"))) | length')
        echo ">>>>>> \${CONTEXT} address funds retrieved on node-pool\${i}: \${TOTAL_UTXOS_FOR_TX_ID}"
        if [ "\${TOTAL_UTXOS_FOR_TX_ID}" == "0" ]; then
            touch "\${ERROR_FILE}"
            break
        fi
    done
}

# Try to send funds address
function try_send_funds_to_address {
    ADDR=\$1
    AMOUNT_TRANSFERRED=\$2
    CONTEXT=\$3
    N=\$4

    ERROR_FILE=\${CONTEXT}-error
    SEND_FUNDS_ADDRESS_WAIT_ROUNDS_MAX=10
    SEND_FUNDS_ADDRESS_WAIT_ROUNDS=1
    SEND_FUNDS_ADDRESS_WAIT_ROUND_DELAY=2
    while true
    do
        send_funds_to_address "\${ADDR}" "\${AMOUNT_TRANSFERRED}" "\${CONTEXT}" "\${N}"
        if [ -f \${ERROR_FILE} ]; then
            echo ">>>> Funds not transferred successfully to \${CONTEXT} address, a rollback has happened [attempt \$SEND_FUNDS_ADDRESS_WAIT_ROUNDS]!"
            sleep \$SEND_FUNDS_ADDRESS_WAIT_ROUND_DELAY
        else
            echo ">>>> Funds transferred successfully to \${CONTEXT} address [attempt \$SEND_FUNDS_ADDRESS_WAIT_ROUNDS]!"
            break
        fi
        SEND_FUNDS_ADDRESS_WAIT_ROUNDS=\$(( \$SEND_FUNDS_ADDRESS_WAIT_ROUNDS + 1 ))
        if [ "\$SEND_FUNDS_ADDRESS_WAIT_ROUNDS" -gt "\$SEND_FUNDS_ADDRESS_WAIT_ROUNDS_MAX" ] ; then
            echo ">>>> Timeout: Funds were not transferred successfully to \${CONTEXT} address within \$SEND_FUNDS_ADDRESS_WAIT_ROUNDS_MAX attempts"
            exit 1
        fi
    done
}

# Write datums for address
function write_datums_for_address {
    ADDR=\$1
    SCRIPT_TX_VALUE=\$2
    CONTEXT=\$3
    N=\$4
    DATUM_FILE=\$5
    
    # Remove if exists previous error file
    ERROR_FILE=\${CONTEXT}-error
    rm -f -- "\${ERROR_FILE}"

    # Fetch transactions from UTxOs of the address
    TX_IN_DATUM=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/\${ADDR}.addr) --out-file /dev/stdout \\
        | jq -r 'to_entries | map({utxo: .key} + .value) | . [] | select(.inlineDatum | . != null and . != "") | .utxo')
    TX_IN_NO_DATUM=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/\${ADDR}.addr) --out-file /dev/stdout \\
        | jq  -r 'to_entries | [last] | .[0].key')

    ## Build the transaction
    if [ "\${TX_IN_DATUM}" == "" ]; then
        CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
            --tx-in \${TX_IN_NO_DATUM} \\
            --tx-out \$(cat addresses/\${ADDR}.addr)+\${SCRIPT_TX_VALUE} \\
            --tx-out-inline-datum-file \${DATUM_FILE} \\
            --change-address \$(cat addresses/\${ADDR}.addr) \\
            --testnet-magic ${NETWORK_MAGIC} \\
            --invalid-hereafter 100000 \\
            --out-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-datum.txbody
    else
        CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
            --tx-in \${TX_IN_DATUM} \\
            --tx-in \${TX_IN_NO_DATUM} \\
            --tx-out \$(cat addresses/\${ADDR}.addr)+\${SCRIPT_TX_VALUE} \\
            --tx-out-inline-datum-file \${DATUM_FILE} \\
            --change-address \$(cat addresses/\${ADDR}.addr) \\
            --testnet-magic ${NETWORK_MAGIC} \\
            --invalid-hereafter 100000 \\
            --out-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-datum.txbody
    fi

    ## Sign the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction sign \\
        --signing-key-file addresses/\${ADDR}.skey \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --tx-body-file  node-pool\${N}/tx/tx\${N}-\${CONTEXT}-datum.txbody \\
        --out-file      node-pool\${N}/tx/tx\${N}-\${CONTEXT}-datum.tx

    ## Submit the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool\${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction submit \\
        --tx-file node-pool\${N}/tx/tx\${N}-\${CONTEXT}-datum.tx \\
        --testnet-magic ${NETWORK_MAGIC}

    ## Wait at least for 10 blocks so that the transaction is confirmed
    wait_for_elapsed_blocks "\${N}" 10

    ## Wait for all pool nodes to see the new datum
    for (( i=1; i<=${NUM_POOL_NODES}; i++ )); do
        INLINE_DATUM=\$(CARDANO_NODE_SOCKET_PATH=node-pool\${i}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
        --testnet-magic ${NETWORK_MAGIC} --address \$(cat addresses/\${ADDR}.addr) --out-file /dev/stdout \\
        | jq  -r '. [] | select(.inlineDatum | . != null and . != "") | .inlineDatum.fields[].bytes' | xxd -r -p | jq)
        echo ">>>>>> \${CONTEXT} address inline datum retrieved on node-pool\${i}: \${INLINE_DATUM}"
        if [ "\${INLINE_DATUM}" == "" ]; then
            touch \${ERROR_FILE}
            break
        fi
    done
}

# Try to write datums address
function try_write_datums_for_address {
    ADDR=\$1
    SCRIPT_TX_VALUE=\$2
    CONTEXT=\$3
    N=\$4
    DATUM_FILE=\$5

    ERROR_FILE=\${CONTEXT}-error
    WRITE_DATUMS_ADDRESS_WAIT_ROUNDS_MAX=10
    WRITE_DATUMS_ADDRESS_WAIT_ROUNDS=1
    WRITE_DATUMS_ADDRESS_WAIT_ROUND_DELAY=2
    while true
    do
        write_datums_for_address "\${ADDR}" "\${SCRIPT_TX_VALUE}" \${CONTEXT} "\${N}" "\${DATUM_FILE}"
        if [ -f \${ERROR_FILE} ]; then
            echo ">>>> Datums not written successfully for \${CONTEXT} address, a rollback has happened [attempt \$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS]!"
            sleep \$WRITE_DATUMS_ADDRESS_WAIT_ROUND_DELAY
        else
            echo ">>>> Datums successfully written for \${CONTEXT} address [attempt \$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS]!"
            break
        fi
        WRITE_DATUMS_ADDRESS_WAIT_ROUNDS=\$(( \$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS + 1 ))
        if [ "\$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS" -gt "\$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS_MAX" ] ; then
            echo ">>>> Timeout: Datums were not written successfully for \${CONTEXT} address within \$WRITE_DATUMS_ADDRESS_WAIT_ROUNDS_MAX attempts"
            exit 1
        fi
    done
}

EOF

chmod u+x cardano-chain.sh