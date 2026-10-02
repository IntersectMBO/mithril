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
BLOCK_HASH_OUTPUT_FILE=block-hashes.txt
cat >> payment-mithril.sh <<EOF
#!/usr/bin/env bash
set -e

# Set default payment iterations value
if [ -z "\${PAYMENT_ITERATIONS}" ]; then 
  PAYMENT_ITERATIONS=3
fi

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

cat >> payment-mithril.sh <<EOF
# Run payment iterations
for (( j=1; j<=\${PAYMENT_ITERATIONS}; j++ ))
do
    set +e
    process_payment_iteration \$j
    set -e
done

# Check that at least one transaction has been successfully submitted
TOTAL_TX_SUBMITTED=\$(cat ${TX_ID_OUTPUT_FILE} | wc -l)
if [ \$TOTAL_TX_SUBMITTED -eq 0 ]; then
    echo ">>>>>> Error: No transaction was successfully submitted!"
    exit 1
fi

# Deduplicate block hashes file
sort -u ${BLOCK_HASH_OUTPUT_FILE} -o ${BLOCK_HASH_OUTPUT_FILE}

EOF

chmod u+x payment-mithril.sh
