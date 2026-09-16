#!/usr/bin/env bash
# measure-loss-all.sh (v2) -- RTT 30ms 고정 + 패킷손실 스윕.
#   측정: (1) 핸드셰이크 성공률 (2) 지연(keyReady/mutual) (3) app 메시지 크기(authB/ackB/confB)
#         (4) TCP 재전송 실측(nstat: OutSegs/RetransSegs, ns1·ns2)
#   통제: veth offload(TSO/GSO/GRO) off, 양방향 netem, MTU/MSS 기록, N=500.
#   전제: measure/loss-size 브랜치 빌드(authB 로깅) + export JAVA_HOME.
#   실행: sudo -v && ( while true; do sudo -n true; sleep 50; done ) &
#         export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
#         bash netns/measure-loss-all.sh
set -u
DIR=/mnt/c/Users/hanati/IdeaProjects/besu/netns
RES="$DIR/results"; mkdir -p "$RES"
BESU=/mnt/c/Users/hanati/IdeaProjects/besu/build/install/besu/bin/besu
: "${JAVA_HOME:?export JAVA_HOME 먼저}"
[ -x "$BESU" ] || { echo "빌드 먼저: ./gradlew installDist"; exit 1; }
ENODE="enode://6f73be34d11d94b69c499d2d709366a0b3b637faa71b9e5d17a8707c6d98033c24ba1de52789825a4bcb4fd18815b3dbb75b3a30a7bb9820d7473b3d9940e8d9@10.0.0.2:30304"
MARK='peerTotal(T8-T0)='
RPC="http://10.0.0.1:8545"
DELAY_MS=15                 # 각 방향 15ms → RTT 30ms
LOSSES="0 0.5 1 2 5"        # %
WARMUP=15; MEASURE=500; BUFFER=20; SETTLE=0.8; HSTMO=30
COLLECT=$((MEASURE+BUFFER)); WANT=$((WARMUP+COLLECT))
STAT="$HOME/loss_stat.txt"; : > "$STAT"
NCK="$DIR/../ethereum/p2p/src/main/java/org/hyperledger/besu/ethereum/p2p/rlpx/connections/netty"
grep -q wallPeerEstablished "$NCK/DeFramer.java" || echo "경고: mutual 계측 없음(브랜치/빌드 확인)"
grep -q authBytes "$NCK/HandshakeTimings.java" || echo "⚠ 크기 로깅(authBytes) 소스에 없음 → measure/loss-size 재빌드 필요(그래도 손실/재전송/지연은 측정됨)"

# ns1(개시자)의 TCP 카운터(OutSegs, RetransSegs) 읽기 — /proc/net/snmp 헤더로 컬럼 매핑
tcp_counters(){ # $1=ns
  sudo ip netns exec "$1" cat /proc/net/snmp | awk '
    /^Tcp:/ { if(!h){for(i=1;i<=NF;i++)col[$i]=i; h=1} else {print $col["OutSegs"], $col["RetransSegs"]} }'
}

kill_nodes(){ sudo pkill -f 'build/install/besu' 2>/dev/null || true; sleep 2; }
trap kill_nodes EXIT
wait_rpc(){ for i in $(seq 1 90); do
    r=$(sudo ip netns exec ns1 curl -s "http://$1:$2" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' 2>/dev/null)
    [[ "$r" == *result* ]] && { echo "  RPC up: $1:$2"; return 0; }; sleep 1
  done; echo "  ✗ RPC 안뜸 $1:$2"; return 1; }
start_nodes(){ kill_nodes; sudo rm -f "$HOME/node1.log" "$HOME/node2.log"; echo "[$1] 노드 기동..."
  sudo ip netns exec ns1 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node1 "$1" ~/node1.log >/dev/null 2>&1 &
  sudo ip netns exec ns2 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node2 "$1" ~/node2.log >/dev/null 2>&1 &
  wait_rpc 10.0.0.1 8545 || { sudo tail -20 "$HOME/node1.log"; return 1; }
  wait_rpc 10.0.0.2 8546 || { sudo tail -20 "$HOME/node2.log"; return 1; }
  sleep 3; }

echo "== netns 준비 =="; sudo "$DIR/setup-netns.sh" up 2>/dev/null || true

# --- offload off (세그먼트 단위 손실 해석을 위해) + 환경 기록 ---
echo "== 오프로드 off & 환경 기록 =="
for pair in "ns1 veth1" "ns2 veth2"; do set -- $pair
  sudo ip netns exec "$1" ethtool -K "$2" tso off gso off gro off tx off rx off 2>/dev/null \
    || echo "  ⚠ $2 offload off 실패(veth/WSL 미지원 가능) — 상태만 기록"
  st=$(sudo ip netns exec "$1" ethtool -k "$2" 2>/dev/null | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload' | tr '\n' ' ')
  mtu=$(sudo ip netns exec "$1" ip -o link show "$2" | grep -o 'mtu [0-9]*')
  echo "  $2: $mtu (예상 MSS≈$(( ${mtu#mtu } - 40 ))B) | $st"
done
echo "  ※ 실제 MSS는 SYN에서 확인 권장(선택): sudo ip netns exec ns1 tcpdump -c1 -ni veth1 'tcp[13]&2!=0'"

for proto in xwing ecies; do
  start_nodes "$proto" || { echo "$proto 실패"; exit 1; }
  for L in $LOSSES; do
    tag=$(echo "$L" | tr '.' 'p'); label="${proto}L"
    echo; echo "================ $proto  RTT30  loss=${L}%  (N=$MEASURE) ================"
    sudo ip netns exec ns1 tc qdisc replace dev veth1 root netem delay ${DELAY_MS}ms loss ${L}%
    sudo ip netns exec ns2 tc qdisc replace dev veth2 root netem delay ${DELAY_MS}ms loss ${L}%
    echo "  [검증] $(sudo ip netns exec ns1 tc -s qdisc show dev veth1 | tr '\n' ' ')"
    sudo ip netns exec ns1 ping -c5 -q 10.0.0.2 | awk -F'/' '/rtt|round/{print "  ping avg "$5" ms"} /packet loss/{print "  "$0}'
    LOG=~/node1.log; RLOG=~/node2.log
    base=$(grep -c "$MARK" "$LOG" 2>/dev/null); base=${base:-0}
    rbase=$(grep -c "$MARK" "$RLOG" 2>/dev/null); rbase=${rbase:-0}
    read oI0 rI0 < <(tcp_counters ns1); read oR0 rR0 < <(tcp_counters ns2)
    echo "collecting $WANT (warmup$WARMUP+measure$MEASURE+buffer$BUFFER) — loss라 느릴 수 있음..."
    out=$(sudo ip netns exec ns1 bash "$DIR/measure-collect.sh" "$RPC" "$ENODE" "$LOG" "$WARMUP" "$COLLECT" "$SETTLE" "$HSTMO")
    echo "$out" | grep -E 'samples=(100|300|500)/|Done' | sed 's/^/    /'
    read oI1 rI1 < <(tcp_counters ns1); read oR1 rR1 < <(tcp_counters ns2)
    dl=$(echo "$out" | grep -m1 '^Done.')
    att=$(echo "$dl" | grep -o 'attempts=[0-9]*'|cut -d= -f2); hsf=$(echo "$dl" | grep -o 'hsFail=[0-9]*'|cut -d= -f2)
    echo "LOSSSTAT proto=$proto loss=$L attempts=${att:-0} hsFail=${hsf:-0} outI=$((oI1-oI0)) reI=$((rI1-rI0)) outR=$((oR1-oR0)) reR=$((rR1-rR0))" | tee -a "$STAT"
    after=$(grep -c "$MARK" "$LOG"); new=$((after-base))
    grep "$MARK" "$LOG" | tail -n "$new" > "$RES/${label}-loss${tag}.timing"
    rafter=$(grep -c "$MARK" "$RLOG"); rnew=$((rafter-rbase))
    grep "$MARK" "$RLOG" | tail -n "$rnew" > "$RES/${label}-loss${tag}.resp.timing"
    TARGET_N=$MEASURE bash "$DIR/parse-timing.sh" "$WARMUP" "$RES/${label}-loss${tag}.csv" "$RES/${label}-loss${tag}.timing" | grep -E 'peerTotal|keyReady|respAKE\[init\]|N=' | head -12
  done
  sudo ip netns exec ns1 tc qdisc del dev veth1 root 2>/dev/null || true
  sudo ip netns exec ns2 tc qdisc del dev veth2 root 2>/dev/null || true
done
kill_nodes

echo; echo "==================== LOSS 결과 (이걸 클로드에게 붙여넣기) ===================="
python3 - "$RES" "$STAT" "$WARMUP" "$MEASURE" << 'PY'
import sys,re,os,csv as C,statistics as st
RES,STAT,W,M=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
rec={}
for ln in open(STAT):
    m=re.search(r'proto=(\w+) loss=(\S+) attempts=(\d+) hsFail=(\d+) outI=(\d+) reI=(\d+) outR=(\d+) reR=(\d+)',ln)
    if m: rec[(m.group(1),m.group(2))]=list(map(lambda x:x if not x.isdigit() else int(x), m.groups()[2:]))
def med_col(path,rx,filt):
    v=[]
    if os.path.exists(path):
        for ln in open(path,errors='ignore'):
            if filt in ln:
                mm=re.search(rx,ln);
                if mm: v.append(int(mm.group(1)))
    return int(st.median([x for x in v if x>0])) if any(x>0 for x in v) else 0
def csv_med(cf,key):
    if not os.path.exists(cf): return None
    v=[float(r[key]) for r in C.DictReader(open(cf)) if r.get('phase')=='steady' and r.get(key)]
    return st.median(v) if v else None
for proto in ['xwing','ecies']:
    print(f"\n#### {proto} (RTT30 고정) ####")
    print(f"{'loss%':>6}{'att':>6}{'hsFail':>7}{'succ%':>7}{'reI':>6}{'outI':>7}{'reI%':>6}{'authB':>7}{'ackB':>7}{'confB':>7}{'keyReady_med':>13}{'peerTot_med':>12}")
    for L,tag in [('0','0'),('0.5','0p5'),('1','1'),('2','2'),('5','5')]:
        lab=f"{proto}L-loss{tag}"; tf=f"{RES}/{lab}.timing"; rf=f"{RES}/{lab}.resp.timing"; cf=f"{RES}/{lab}.csv"
        r=rec.get((proto,L))
        att,hsf,outI,reI,outR,reR=(r if r else [0,0,0,0,0,0])
        sr=100*M/att if att else 0; rip=100*reI/outI if outI else 0
        aB=med_col(tf,r'authB=(\d+)','role=INITIATOR'); cB=med_col(tf,r'confB=(\d+)','role=INITIATOR'); kB=med_col(rf,r'ackB=(\d+)','role=RESPONDER')
        kr=csv_med(cf,'keyReady'); pt=csv_med(cf,'peerTotal')
        krs=f"{kr:.2f}" if kr else "n/a"; pts=f"{pt:.2f}" if pt else "n/a"
        print(f"{L:>6}{att:>6}{hsf:>7}{sr:>6.1f}%{reI:>6}{outI:>7}{rip:>5.1f}%{aB:>7}{kB:>7}{cB:>7}{krs:>13}{pts:>12}")
print("\n지표: att=시도수, succ%=목표N/att, reI/outI=개시자 재전송/총 세그먼트, authB/ackB/confB=app 메시지크기(bytes)")
PY
echo; echo "---- mutual(양쪽 Hello) loss별 median ----"
for proto in xwing ecies; do for tag in 0 0p5 1 2 5; do
  echo "== $proto loss=$tag =="
  bash "$DIR/parse-mutual.sh" "$RES/${proto}L-loss${tag}.timing" "$RES/${proto}L-loss${tag}.resp.timing" "$WARMUP" "$MEASURE" 2>/dev/null | grep -E 'mutual|짝지음'
done; done
echo "==================== 끝 ===================="
