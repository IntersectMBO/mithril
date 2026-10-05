
NODE_PORT_START=4000

# Create network topology
FULL_NODES=()
FULL_NODES_N=()
for (( i=1; i<=${NUM_FULL_NODES}; i++ ))
  do
    FULL_NODES=("${FULL_NODES[@]}" "node-full${i}")
    FULL_NODES_N=("${FULL_NODES_N[@]}" "${i}")
done
FULL_NODES=${FULL_NODES[@]}
FULL_NODES_N=${FULL_NODES_N[@]}

POOL_NODES=()
POOL_NODES_N=()
for (( i=1; i<=${NUM_POOL_NODES}; i++ ))
  do
    POOL_NODES=("${POOL_NODES[@]}" "node-pool${i}")
    POOL_NODES_N=("${POOL_NODES_N[@]}" "${i}")
done
POOL_NODES=${POOL_NODES[@]}
POOL_NODES_N=${POOL_NODES_N[@]}

ALL_NODES="${FULL_NODES} ${POOL_NODES}"

# create the topology files
NODE_ADDR=$LISTENING_ADDR
NODE_PORT=$NODE_PORT_START
TOPOLOGY='
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [],
      "advertise": false,
      "trustable": false
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}'
for NODE in ${ALL_NODES}; do
  NODE_PORT=$(( ${NODE_PORT} + 1))
  echo ${NODE_PORT} > ${NODE}/port.dmq
  TOPOLOGY=$(echo ${TOPOLOGY} | jq '.localRoots[0].accessPoints[.localRoots[0].accessPoints | length] |= . + {"address": "'${NODE_ADDR}'","port": '${NODE_PORT}', "valency": 1}')
done
echo $TOPOLOGY | jq . > topology.dmq.json

NODE_IX=0
for NODE in ${ALL_NODES}; do
  cat topology.dmq.json |  jq '.localRoots[0].accessPoints |= del(.['${NODE_IX}']) | .localRoots[0].valency = (.localRoots[0].accessPoints | length)' > ${NODE}/topology.dmq.json
  NODE_IX=$(( ${NODE_IX} + 1))
done