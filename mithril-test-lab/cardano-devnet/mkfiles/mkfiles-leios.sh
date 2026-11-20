# Leios mode: node configuration keys, trustable local roots and a transaction load script
if [ "${USE_LEIOS}" = "true" ]; then

## Node configuration keys of the Leios node
for NODE in ${ALL_NODES}; do
  cat >> ${NODE}/configuration.yaml <<EOF
LeiosMinOfferLead: 30
EgressBudgetMbps: 250
LeiosAdaptiveEndorsements:
  Enabled: true
TxSubmissionLogicVersion: TxSubmissionLogicV2
ConsensusMode: PraosMode
EOF
done

## Trustable local roots, required by the endorsement logic to consider the node caught up
for NODE in ${ALL_NODES}; do
  cat ${NODE}/topology.json | jq '.localRoots |= map(. + {trustable: true, hotValency: (.accessPoints | length), warmValency: (.accessPoints | length)} | del(.valency)) | .useLedgerAfterSlot = -1' > ${NODE}/topology.json.tmp
  mv ${NODE}/topology.json.tmp ${NODE}/topology.json
done

## Transaction load script, fed by the last genesis UTxO key
cat >> load-mithril.sh <<EOF
#!/usr/bin/env bash
# Submit a transaction load with tx-firehose on node-pool1, in the background, for a bounded duration.
# Usage: LOAD_TPS=${LOAD_TPS} LOAD_DURATION=${LOAD_DURATION} ./load-mithril.sh
# Requires: timeout (coreutils), the tx-firehose binary of the Leios node archive in ./bin
set -e
if [ "\$1" = "--help" ]; then
  sed -n 2,4p "\$0"
  exit 0
fi
if ! command -v timeout > /dev/null; then
  echo "Error: the 'timeout' command is required to bound the transaction load"
  exit 1
fi
if [ -z "\${LOAD_TPS}" ]; then
  LOAD_TPS=${LOAD_TPS}
fi
if [ -z "\${LOAD_DURATION}" ]; then
  LOAD_DURATION=${LOAD_DURATION}
fi

# The firehose stops submitting after a rollback spends its inputs, so it is restarted until the duration elapses
function run_load {
    LOAD_END=\$(( SECONDS + LOAD_DURATION ))
    while [ \$SECONDS -lt \$LOAD_END ]; do
        timeout \$(( LOAD_END - SECONDS )) $CARDANO_BIN_PATH/tx-firehose \\
          --socket-path node-pool1/ipc/node.sock \\
          --testnet-magic ${NETWORK_MAGIC} \\
          --signing-key-file addresses/${LOAD_ADDR}.skey \\
          --tps \${LOAD_TPS} \\
          --outputs-per-tx 2 \\
          --max-consecutive-errors 1 \\
          >> load.log 2>&1 || true
        sleep 1
    done
}

echo ">> Start transaction load: \${LOAD_TPS} tps for \${LOAD_DURATION}s"
rm -f load.log
nohup bash -c "\$(declare -f run_load); LOAD_TPS=\${LOAD_TPS} LOAD_DURATION=\${LOAD_DURATION} run_load" > load-supervisor.log 2>&1 &
echo \$! > load-supervisor.pid
echo ">> Transaction load started (log: load.log)"
EOF
chmod u+x load-mithril.sh

fi
