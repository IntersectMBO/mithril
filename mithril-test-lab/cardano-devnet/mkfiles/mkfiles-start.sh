cat >> start-cardano.sh <<EOF
#!/usr/bin/env bash

echo ">> Start Cardano network"
killall cardano-node > /dev/null 2>&1

# Stop when there's an error, activate it after the killall since it will report an error if it doesn't kill anything
set -e

$CARDANO_CLI --version
$CARDANO_NODE --version

EOF

for NODE in ${FULL_NODES}; do
  cat >> ${NODE}/start-node.sh <<EOF
#!/usr/bin/env bash

$CARDANO_NODE run \\
  --config                          ${NODE}/configuration.yaml \\
  --topology                        ${NODE}/topology.json \\
  --database-path                   ${NODE}/db \\
  --socket-path                     ${NODE}/ipc/node.sock \\
  --port                            $(cat ${NODE}/port) \\
  > ${NODE}/node.log
EOF
  chmod u+x ${NODE}/start-node.sh
  cat >> start-cardano.sh <<EOF
echo ">> Starting Cardano node '${NODE}'"
./${NODE}/start-node.sh &

EOF
done

for NODE in ${POOL_NODES}; do
  cat >> ${NODE}/start-node.sh <<EOF
#!/usr/bin/env bash

$CARDANO_NODE run \\
  --config                          ${NODE}/configuration.yaml \\
  --topology                        ${NODE}/topology.json \\
  --database-path                   ${NODE}/db \\
  --socket-path                     ${NODE}/ipc/node.sock \\
  --byron-delegation-certificate    ${NODE}/byron/delegate.cert \\
  --byron-signing-key               ${NODE}/byron/delegate.key \\
  --shelley-kes-key                 ${NODE}/shelley/kes.skey \\
  --shelley-vrf-key                 ${NODE}/shelley/vrf.skey \\
  --shelley-operational-certificate ${NODE}/shelley/opcert.cert \\
  --port                            $(cat ${NODE}/port) \\
  > ${NODE}/node.log
EOF
  chmod u+x ${NODE}/start-node.sh
  cat >> start-cardano.sh <<EOF
echo ">> Starting Cardano node '${NODE}'"
./${NODE}/start-node.sh &

EOF
done

cat >> start-cardano.sh <<EOF
echo ">> Wait for Cardano network to be ready"
CARDANO_ACTIVATION_WAIT_ROUNDS_MAX=30
CARDANO_ACTIVATION_WAIT_ROUNDS=1
CARDANO_ACTIVATION_WAIT_ROUND_DELAY=2
while true
do
    EPOCH=\$(CARDANO_NODE_SOCKET_PATH=node-pool1/ipc/node.sock $CARDANO_CLI $CARDANO_CLI_ERA query tip --testnet-magic ${NETWORK_MAGIC} 2> /dev/null | jq -r .epoch)
    if [ "\$EPOCH" != "" ] ; then
        echo ">>>> Cardano network is ready!"
        break
    else
        echo ">>>> Cardano network is not ready yet... [attempt \$CARDANO_ACTIVATION_WAIT_ROUNDS]"
        sleep \$CARDANO_ACTIVATION_WAIT_ROUND_DELAY
    fi
    CARDANO_ACTIVATION_WAIT_ROUNDS=\$(( \$CARDANO_ACTIVATION_WAIT_ROUNDS + 1 ))
    if [ "\$CARDANO_ACTIVATION_WAIT_ROUNDS" -gt "\$CARDANO_ACTIVATION_WAIT_ROUNDS_MAX" ] ; then
        echo ">>>> Timeout: Cardano network could no start within \$CARDANO_ACTIVATION_WAIT_ROUNDS_MAX attempts"
        exit 1
    fi
done

EOF

cat >> start-cardano.sh <<EOF
echo ">> Wait for Cardano nodes to have enough immutable files"
for NODE in ${ALL_NODES}; do
  echo ">> Wait for \${NODE} to have enough immutable files"
  NODE_ACTIVATION_WAIT_ROUNDS_MAX=100
  NODE_ACTIVATION_WAIT_ROUNDS=1
  NODE_ACTIVATION_WAIT_ROUND_DELAY=2
  while true
  do
      TOTAL_IMMUTABLE_FILES=\$(ls -1q \${NODE}/db/immutable | grep ".chunk" | wc -l)
      if [ "\$TOTAL_IMMUTABLE_FILES" -gt "1" ] ; then
          echo ">>>> \${NODE} has enough immutable files!"
          break
      else
          echo ">>>> \${NODE} has not enough immutable files yet... [attempt \$NODE_ACTIVATION_WAIT_ROUNDS]"
          sleep \$NODE_ACTIVATION_WAIT_ROUND_DELAY
      fi
      NODE_ACTIVATION_WAIT_ROUNDS=\$(( \$NODE_ACTIVATION_WAIT_ROUNDS + 1 ))
      if [ "\$NODE_ACTIVATION_WAIT_ROUNDS" -gt "\$NODE_ACTIVATION_WAIT_ROUNDS_MAX" ] ; then
          echo ">>>> Timeout: \${NODE} has not enough immutable files within \$NODE_ACTIVATION_WAIT_ROUNDS_MAX attempts"
          exit 1
      fi
  done
done

EOF

chmod u+x start-cardano.sh

cat >> start-dmq.sh <<EOF
#!/usr/bin/env bash

echo ">> Start DMQ network"
killall dmq-node > /dev/null 2>&1

# Stop when there's an error, activate it after the killall since it will report an error if it doesn't kill anything
set -e

$DMQ_NODE --version

EOF

for NODE in ${ALL_NODES}; do
  cat >> ${NODE}/start-dmq.sh <<EOF
#!/usr/bin/env bash

$DMQ_NODE \\
  --configuration-file              ${NODE}/config.dmq.json \\
  --topology-file                   ${NODE}/topology.dmq.json \\
  --local-socket                    ${NODE}/ipc/dmq.node.sock \\
  --host-addr                       $(cat ${NODE}/host) \\
  --port                            $(cat ${NODE}/port.dmq) \\
  --min-sig-delay 0.01s \\
  > ${NODE}/dmq.node.log
EOF
  chmod u+x ${NODE}/start-dmq.sh
  cat >> start-dmq.sh <<EOF
echo ">> Starting DMQ node '${NODE}'"
./${NODE}/start-dmq.sh &

EOF
done

chmod u+x start-dmq.sh

cat >> stop.sh <<EOF
#!/usr/bin/env bash

echo ">> Stop Cardano network"
killall cardano-node

echo ">> Stop DMQ network"
killall -q dmq-node || true

EOF
chmod u+x stop.sh
