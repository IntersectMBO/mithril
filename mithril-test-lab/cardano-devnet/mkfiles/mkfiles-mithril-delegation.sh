
# Delegation script
cat >> delegate.sh <<EOF
#!/usr/bin/env bash
set -e

# Get current Cardano era
CURRENT_CARDANO_ERA=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
    --testnet-magic ${NETWORK_MAGIC} \\
    | jq  -r '.era |= ascii_downcase | .era')
echo ">>>> Current Cardano Era: \${CURRENT_CARDANO_ERA}"

# Get the current epoch
CURRENT_EPOCH=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip \\
                    --testnet-magic ${NETWORK_MAGIC} | jq .epoch)
echo ">>>> Current Epoch: \${CURRENT_EPOCH}"

# Is semver on the first argument strictly lower than the second argument?
version_lt() {
  VERSION_LHS=\$1
  VERSION_RHS=\$2
  if [ "\${VERSION_LHS}" != "\${VERSION_RHS}" ] && [ "\${VERSION_LHS}" = "`echo -e "\${VERSION_LHS}\n\${VERSION_RHS}" | sort -V | head -n1`" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Is semver on the first argument lower or equal to the second argument?
version_lte() {
  VERSION_LHS=\$1
  VERSION_RHS=\$2
  if [ "\${VERSION_LHS}" == "\${VERSION_RHS}" ]; then
    echo "true"
  else
    version_lt $VERSION_LHS $VERSION_RHS
  fi
}

# Stake addresses registration certs
for ADDR in ${USER_ADDRS}; do
  if [ "\${CURRENT_CARDANO_ERA}" == "conway" ] || [ "\${CURRENT_CARDANO_ERA}" == "dijkstra" ]; then
    KEY_REGISTRATION_DEPOSIT_AMOUNT=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query gov-state --testnet-magic ${NETWORK_MAGIC} | jq .currentPParams.stakeAddressDeposit)
    # Registration certificate with the key deposit amount, from Conway onwards
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} stake-address registration-certificate \
    --stake-verification-key-file addresses/\${ADDR}-stake.vkey \
    --out-file addresses/\${ADDR}-stake.reg.cert \
    --key-reg-deposit-amt \$KEY_REGISTRATION_DEPOSIT_AMOUNT
  else
    # Legacy creation of registration certificate
    $CARDANO_CLI stake-address registration-certificate \
      --stake-verification-key-file addresses/\${ADDR}-stake.vkey \
      --out-file addresses/\${ADDR}-stake.reg.cert
  fi
done

EOF

# User N will delegate to pool N
for N in ${POOL_NODES_N}; do
  cat >> delegate.sh <<EOF
    # Stake address delegation certs
    $CARDANO_CLI \${CURRENT_CARDANO_ERA} stake-address stake-delegation-certificate \
        --stake-verification-key-file addresses/user${N}-stake.vkey \
        --cold-verification-key-file  node-pool${N}/shelley/cold.vkey \
        --out-file addresses/user${N}-stake.deleg.cert

EOF
done

# Prepare transactions for delegating to stake pools
for N in ${POOL_NODES_N}; do
  cat >> delegate.sh <<EOF
    AMOUNT_STAKED=\$(( $N*1000000 +  \$DELEGATION_ROUND*1 ))

    # Get the UTxO
    TX_IN=\$(CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} query utxo \\
      --testnet-magic ${NETWORK_MAGIC}  --address \$(cat addresses/utxo${N}.addr) --out-file /dev/stdout \\
      | jq  -r 'to_entries | [last] | .[0].key')

    # Build the transaction
    if [ "\$DELEGATION_ROUND" -eq 1 ]; then
      # First delegation round, we need to include registration certificate and delegation certificate
      CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
          --tx-in \${TX_IN} \\
          --tx-out \$(cat addresses/user${N}.addr)+\${AMOUNT_STAKED} \\
          --change-address \$(cat addresses/utxo${N}.addr) \\
          --testnet-magic ${NETWORK_MAGIC} \\
          --certificate-file addresses/user${N}-stake.reg.cert \\
          --certificate-file addresses/user${N}-stake.deleg.cert \\
          --invalid-hereafter 100000 \\
          --out-file node-pool${N}/tx/tx${N}-\${DELEGATION_ROUND}.txbody \\
          --witness-override 2
    else
      # All other delegation rounds, we need to include only delegation certificate
      CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction build \\
          --tx-in \${TX_IN} \\
          --tx-out \$(cat addresses/user${N}.addr)+\${AMOUNT_STAKED} \\
          --change-address \$(cat addresses/utxo${N}.addr) \\
          --testnet-magic ${NETWORK_MAGIC} \\
          --certificate-file addresses/user${N}-stake.deleg.cert \\
          --invalid-hereafter 100000 \\
          --out-file node-pool${N}/tx/tx${N}-\${DELEGATION_ROUND}.txbody \\
          --witness-override 2
    fi

    # Sign the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction sign \\
        --signing-key-file addresses/utxo${N}.skey \\
        --signing-key-file addresses/user${N}-stake.skey \\
        --testnet-magic ${NETWORK_MAGIC} \\
        --tx-body-file  node-pool${N}/tx/tx${N}-\${DELEGATION_ROUND}.txbody \\
        --out-file      node-pool${N}/tx/tx${N}-\${DELEGATION_ROUND}.tx

    # Submit the transaction
    CARDANO_NODE_SOCKET_PATH=node-pool${N}/ipc/node.sock $CARDANO_CLI \${CURRENT_CARDANO_ERA} transaction submit \\
        --tx-file node-pool${N}/tx/tx${N}-\${DELEGATION_ROUND}.tx \\
        --testnet-magic ${NETWORK_MAGIC}

EOF

done

chmod u+x delegate.sh
