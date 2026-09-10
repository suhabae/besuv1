#!/usr/bin/env bash
# measure-mutual-all.sh -- 두 노드 모두 Hello 완료(mutual) 자동 측정.
#   전제: (1) measure/mutual-hello 브랜치 체크아웃, (2) 빌드 완료(build/install/besu 존재, -XX 제거),
#         (3) export JAVA_HOME=<JDK25>.  실행: bash netns/measure-mutual-all.sh   (sudo는 내부에서 물어봄)
set -u
DIR=/mnt/c/Users/hanati/IdeaProjects/besu/netns
BESU=/mnt/c/Users/hanati/IdeaProjects/besu/build/install/besu/bin/besu
: "${JAVA_HOME:?먼저 export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 하세요}"
[ -x "$BESU" ] || { echo "빌드 먼저 하세요: ./gradlew installDist (지금 $BESU 없음)"; exit 1; }
JAR=$(ls -t build/install/besu/lib/besu-ethereum-p2p-*.jar 2>/dev/null | head -1)
DEF="$DIR/../ethereum/p2p/src/main/java/org/hyperledger/besu/ethereum/p2p/rlpx/connections/netty/DeFramer.java"
if [ -n "$JAR" ] && [ "$DEF" -nt "$JAR" ]; then echo "⚠ 빌드($JAR)가 소스보다 오래됨 → 먼저 ./gradlew installDist 로 재빌드 필요(안 하면 mutual 계측 미반영)"; fi
grep -q wallPeerEstablished "$DIR/../ethereum/p2p/src/main/java/org/hyperledger/besu/ethereum/p2p/rlpx/connections/netty/DeFramer.java" \
  || { echo "경고: DeFramer에 mutual 계측이 없음 → measure/mutual-hello 브랜치인지, 빌드했는지 확인"; }

kill_nodes(){ sudo pkill -f 'build/install/besu' 2>/dev/null || true; sleep 2; }
trap kill_nodes EXIT
wait_rpc(){ # $1=host $2=port
  for i in $(seq 1 90); do
    r=$(sudo ip netns exec ns1 curl -s "http://$1:$2" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' 2>/dev/null)
    [[ "$r" == *result* ]] && { echo "  RPC up: $1:$2"; return 0; }
    sleep 1
  done; echo "  ✗ RPC 안 뜸: $1:$2 (로그 확인: ~/node*.log)"; return 1
}
start_nodes(){ # $1=proto
  kill_nodes; sudo rm -f "$HOME/node1.log" "$HOME/node2.log"
  echo "[$1] 노드 기동..."
  sudo ip netns exec ns1 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node1 "$1" ~/node1.log >/dev/null 2>&1 &
  sudo ip netns exec ns2 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node2 "$1" ~/node2.log >/dev/null 2>&1 &
  wait_rpc 10.0.0.1 8545 || { echo "---- node1.log 마지막 20줄 ----"; sudo tail -20 "$HOME/node1.log" 2>/dev/null; return 1; }
  wait_rpc 10.0.0.2 8546 || { echo "---- node2.log 마지막 20줄 ----"; sudo tail -20 "$HOME/node2.log" 2>/dev/null; return 1; }
  sleep 3
}

echo "== netns 준비 =="; sudo "$DIR/setup-netns.sh" up 2>/dev/null || true

for proto in xwing ecies; do
  start_nodes "$proto" || { echo "$proto 노드 실패 → 중단"; exit 1; }
  echo "[$proto] 스윕 (RTT 0/10/30/50, 각 warmup15+100)..."
  sudo bash "$DIR/sweep.sh" "${proto}3" ~/node1.log 100 15 1.0 "0 10 30 50"
done
kill_nodes

echo; echo "==================== MUTUAL 결과 (이걸 클로드에게 붙여넣기) ===================="
for proto in xwing ecies; do
  echo "########## $proto ##########"
  for r in 0 10 30 50; do
    echo "=== $proto RTT$r ==="
    bash "$DIR/parse-mutual.sh" "$DIR/results/${proto}3-rtt$r.timing" "$DIR/results/${proto}3-rtt$r.resp.timing" 15 100
  done
done
echo "==================== 끝 ===================="
