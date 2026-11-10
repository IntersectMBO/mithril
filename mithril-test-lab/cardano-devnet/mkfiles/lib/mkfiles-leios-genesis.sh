# Leios mode genesis: BLS keys of the pools, short Leios periods and a small block body so that the load overflows a block
if [ -z "${LEIOS_ANNOUNCEMENT_PERIOD_MS}" ]; then
  LEIOS_ANNOUNCEMENT_PERIOD_MS=300
fi
if [ -z "${LEIOS_VOTE_PERIOD_MS}" ]; then
  LEIOS_VOTE_PERIOD_MS=600
fi
if [ -z "${LEIOS_DIFFUSION_PERIOD_MS}" ]; then
  LEIOS_DIFFUSION_PERIOD_MS=900
fi
if [ -z "${LEIOS_MAX_BLOCK_BODY_SIZE}" ]; then
  LEIOS_MAX_BLOCK_BODY_SIZE=4096
fi

## Generate a BLS key pair per pool and take its proof of possession from a pool registration certificate
## (the certificate CBOR embeds the key as `82 5860 <96 bytes> 5830 <48 bytes>`, there is no standalone command for the proof)
BLS_KEYS_JSON='{}'
for N in ${POOL_NODES_N}; do
  $CARDANO_CLI dijkstra node key-gen-BLS \
    --verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/bls${N}.vkey \
    --signing-key-file ${ARTIFACTS_DIR_TEMP}/pools/bls${N}.skey
  POOL_ID=$($CARDANO_CLI dijkstra stake-pool id \
    --stake-pool-verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/cold${N}.vkey \
    --output-format hex)
  $CARDANO_CLI dijkstra stake-pool registration-certificate \
    --cold-verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/cold${N}.vkey \
    --vrf-verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/vrf${N}.vkey \
    --bls-signing-key-file ${ARTIFACTS_DIR_TEMP}/pools/bls${N}.skey \
    --pool-pledge 0 \
    --pool-cost 0 \
    --pool-margin 0 \
    --pool-reward-account-verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/staking-reward${N}.vkey \
    --pool-owner-stake-verification-key-file ${ARTIFACTS_DIR_TEMP}/pools/staking-reward${N}.vkey \
    --testnet-magic ${NETWORK_MAGIC} \
    --out-file ${ARTIFACTS_DIR_TEMP}/pools/bls${N}.reg.cert
  CERT_CBOR=$(jq -r .cborHex ${ARTIFACTS_DIR_TEMP}/pools/bls${N}.reg.cert)
  if [[ ! "${CERT_CBOR}" =~ 825860([0-9a-f]{192})5830([0-9a-f]{96}) ]] || [[ "${CERT_CBOR#*825860}" == *825860* ]]; then
    echo "Error: the registration certificate of node-pool${N} does not embed one BLS key as '82 5860 <96 bytes> 5830 <48 bytes>', the cardano-cli format changed"
    exit 1
  fi
  BLS_KEYS_JSON=$(echo "${BLS_KEYS_JSON}" | jq --arg pool_id "${POOL_ID}" --arg bls_pubkey "${BASH_REMATCH[1]}" --arg bls_proof "${BASH_REMATCH[2]}" '. + {($pool_id): {blsPubKey: $bls_pubkey, blsPossessionProof: $bls_proof}}')
  echo ">> BLS key generated for node-pool${N} (pool ${POOL_ID})"
done

## Inject the BLS keys in the genesis pools and shrink the block body
cat ${ARTIFACTS_DIR_TEMP}/genesis.json | jq --argjson bls_keys "${BLS_KEYS_JSON}" --argjson max_block_body_size ${LEIOS_MAX_BLOCK_BODY_SIZE} '
  .staking.pools |= with_entries(.value.blsKey = $bls_keys[.key])
  | .protocolParams.maxBlockBodySize = $max_block_body_size
' > ${ARTIFACTS_DIR_TEMP}/genesis.json.tmp
mv ${ARTIFACTS_DIR_TEMP}/genesis.json.tmp ${ARTIFACTS_DIR_TEMP}/genesis.json
if ! jq -e '[.staking.pools[] | .blsKey != null] | all' ${ARTIFACTS_DIR_TEMP}/genesis.json > /dev/null; then
  echo "Error: a genesis pool has no BLS key, the pool ids of the registration certificates do not match the genesis"
  exit 1
fi

## Shorten the Leios periods so that a certifying block can follow its announcing block within the devnet slots
cat ${ARTIFACTS_DIR_TEMP}/genesis.dijkstra.json | jq --argjson announcement ${LEIOS_ANNOUNCEMENT_PERIOD_MS} --argjson vote ${LEIOS_VOTE_PERIOD_MS} --argjson diffusion ${LEIOS_DIFFUSION_PERIOD_MS} '
  .leiosAnnouncementPeriodLength = $announcement
  | .leiosVotePeriodLength = $vote
  | .leiosDiffusionPeriodLength = $diffusion
' > ${ARTIFACTS_DIR_TEMP}/genesis.dijkstra.json.tmp
mv ${ARTIFACTS_DIR_TEMP}/genesis.dijkstra.json.tmp ${ARTIFACTS_DIR_TEMP}/genesis.dijkstra.json
