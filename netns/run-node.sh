#!/usr/bin/env bash
# run-node.sh -- launch one Besu node inside the current network namespace.
# Meant to be invoked via `ip netns exec`, e.g.:
#
#   # Node-1 (X-Wing) in ns1:
#   sudo ip netns exec ns1 env JAVA_HOME="$JAVA_HOME" ./run-node.sh node1 xwing ~/node1.log
#   # Node-2 (X-Wing) in ns2:
#   sudo ip netns exec ns2 env JAVA_HOME="$JAVA_HOME" ./run-node.sh node2 xwing ~/node2.log
#
#   proto = xwing | ecies
#
# Note: JAVA_HOME must point to a Linux JDK 25. Pass it through with `env`.
set -e
BASE=/mnt/c/Users/hanati/IdeaProjects/besu
BESU="$BASE/build/install/besu/bin/besu"
QB="$BASE/QBFT-Network"

role="$1"; proto="$2"; log="${3:-/tmp/besu-$1.log}"

if [ "$role" = "node1" ]; then
  DATA="$QB/Node-1/data"; P2P=30303; RPC=8545; HOST=10.0.0.1; KEY="$QB/Node-1/data/xwing-key"
elif [ "$role" = "node2" ]; then
  DATA="$QB/Node-2/data"; P2P=30304; RPC=8546; HOST=10.0.0.2; KEY="$QB/Node-2/data/xwing-key"
else
  echo "role must be node1 or node2"; exit 1
fi

export JAVA_OPTS="-Dbesu.rlpx.measurement=true"
if [ "$proto" = "xwing" ]; then
  export JAVA_OPTS="$JAVA_OPTS -Dbesu.rlpx.xwing=true -Dbesu.rlpx.xwing.keyFile=$KEY -Dbesu.rlpx.xwing.addressBook=$QB/xwing-addressbook"
fi

echo "role=$role proto=$proto host=$HOST p2p=$P2P rpc=$RPC log=$log"
echo "JAVA_HOME=${JAVA_HOME:-(not set!)}"

"$BESU" \
  --data-path="$DATA" \
  --genesis-file="$QB/genesis.json" \
  --data-storage-format=FOREST \
  --p2p-host=$HOST --p2p-port=$P2P --nat-method=NONE \
  --Xp2p-check-maintained-connections-frequency=2 \
  --rpc-http-enabled --rpc-http-host=0.0.0.0 --rpc-http-port=$RPC \
  --rpc-http-api=ETH,NET,ADMIN,QBFT --host-allowlist="*" --rpc-http-cors-origins="all" \
  2>&1 | tee "$log"
