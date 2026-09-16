#!/usr/bin/env bash
# measure-loss-all.sh (v3) -- RTT 30ms 고정 + 패킷손실 스윕.
#   측정: (1) 핸드셰이크 성공률  (2) 지연(keyReady/connectKeyReady/initiatorAKE/responderAKE/peerTotal/mutual)
#         (3) app-level 메시지 크기(authB/ackB/confB)  (4) TCP 재전송
#              - nstat(namespace 전체 OutSegs/RetransSegs, RPC 포함 → 상한값)
#              - tcpdump(P2P 30303/30304 포트만, RPC 제외 → 더 좁은 값) : analyze-retrans.sh로 후처리
#   통제: veth offload(TSO/GSO/GRO) off, 양방향 netem, MTU/MSS 기록.
#   전제: measure/loss-size 브랜치 빌드(authB + connectKeyReady/initiatorAKE 로깅) + export JAVA_HOME.
#         Node-1/Node-2 static-nodes.json 은 실험 중 둘 다 [] (자동 static reconnect 제거).
#   실행: sudo -v && ( while true; do sudo -n true; sleep 50; done ) &
#         export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
#         bash netns/measure-loss-all.sh
#   스모크: LOSSES="0" MEASURE=30 WARMUP=5 BUFFER=5 bash netns/measure-loss-all.sh
set -u
DIR=/mnt/c/Users/hanati/IdeaProjects/besu/netns
RES="$DIR/results"; mkdir -p "$RES"
BESU=/mnt/c/Users/hanati/IdeaProjects/besu/build/install/besu/bin/besu
: "${JAVA_HOME:?export JAVA_HOME 먼저}"
[ -x "$BESU" ] || { echo "빌드 먼저: ./gradlew installDist"; exit 1; }
ENODE="enode://6f73be34d11d94b69c499d2d709366a0b3b637faa71b9e5d17a8707c6d98033c24ba1de52789825a4bcb4fd18815b3dbb75b3a30a7bb9820d7473b3d9940e8d9@10.0.0.2:30304"
MARK='peerTotal(T8-T0)='
RPC="http://10.0.0.1:8545"
DELAY_MS="${DELAY_MS:-15}"          # 각 방향 15ms → RTT 30ms
LOSSES="${LOSSES:-0 0.5 1 2 5}"     # % (env로 오버라이드 → 스모크)
WARMUP="${WARMUP:-15}"; MEASURE="${MEASURE:-500}"; BUFFER="${BUFFER:-20}"
SETTLE="${SETTLE:-0.8}"; HSTMO="${HSTMO:-30}"
COLLECT=$((MEASURE+BUFFER)); WANT=$((WARMUP+MEASURE))   # succ% 분자 = warmup+measure (buffer 제외)
STAT="$HOME/loss_stat.txt"; : > "$STAT"
NCK="$DIR/../ethereum/p2p/src/main/java/org/hyperledger/besu/ethereum/p2p/rlpx/connections/netty"
grep -q wallPeerEstablished "$NCK/DeFramer.java" || echo "경고: mutual 계측 없음(브랜치/빌드 확인)"
grep -q authBytes "$NCK/HandshakeTimings.java" || echo "경고: 크기 로깅(authBytes) 소스에 없음 → 재빌드 필요"
grep -q 'connectKeyReady' "$NCK/HandshakeTimings.java" || echo "경고: connectKeyReady/initiatorAKE 로깅 없음 → 재빌드 필요(그래도 나머지는 측정됨)"

# namespace 전체 TCP 카운터(OutSegs, RetransSegs) — /proc/net/snmp. ※RPC/컨센서스 포함, 상한값.
tcp_counters(){ # $1=ns
  sudo ip netns exec "$1" cat /proc/net/snmp | awk '
    /^Tcp:/ { if(!h){for(i=1;i<=NF;i++)col[$i]=i; h=1} else {print $col["OutSegs"], $col["RetransSegs"]} }'
}

TCPDUMP_PID=""
stop_dump(){ [ -n "$TCPDUMP_PID" ] && { sudo kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""; }; }
kill_nodes(){ sudo pkill -f 'build/install/besu' 2>/dev/null || true; sleep 2; }
cleanup(){ stop_dump; kill_nodes; }
trap cleanup EXIT
wait_rpc(){ for i in $(seq 1 90); do
    r=$(sudo ip netns exec ns1 curl -s "http://$1:$2" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' 2>/dev/null)
    [[ "$r" == *result* ]] && { echo "  RPC up: $1:$2"; return 0; }; sleep 1
  done; echo "  RPC 안뜸 $1:$2"; return 1; }
start_nodes(){ kill_nodes; sudo rm -f "$HOME/node1.log" "$HOME/node2.log"; echo "[$1] 노드 기동..."
  sudo ip netns exec ns1 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node1 "$1" ~/node1.log >/dev/null 2>&1 &
  sudo ip netns exec ns2 env JAVA_HOME="$JAVA_HOME" bash "$DIR/run-node.sh" node2 "$1" ~/node2.log >/dev/null 2>&1 &
  wait_rpc 10.0.0.1 8545 || { sudo tail -20 "$HOME/node1.log"; return 1; }
  wait_rpc 10.0.0.2 8546 || { sudo tail -20 "$HOME/node2.log"; return 1; }
  sleep 3; }

echo "== netns 준비 =="; sudo "$DIR/setup-netns.sh" up 2>/dev/null || true

# --- offload off (세그먼트 단위 손실 해석용) : TSO/GSO/GRO 만. (tx/rx 체크섬 offload는 불필요→건드리지 않음) ---
echo "== 오프로드 off & 환경 기록 =="
for pair in "ns1 veth1" "ns2 veth2"; do set -- $pair
  sudo ip netns exec "$1" ethtool -K "$2" tso off gso off gro off 2>/dev/null \
    || echo "  ⚠ $2 offload off 실패(veth/WSL 미지원 가능) — 상태만 기록"
  st=$(sudo ip netns exec "$1" ethtool -k "$2" 2>/dev/null | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload' | tr '\n' ' ')
  mtu=$(sudo ip netns exec "$1" ip -o link show "$2" | grep -o 'mtu [0-9]*')
  echo "  $2: $mtu (예상 MSS≈$(( ${mtu#mtu } - 40 ))B) | $st"
done
echo "  ※ 실제 MSS는 SYN에서 확인 권장(선택): sudo ip netns exec ns1 tcpdump -c1 -ni veth1 'tcp[13]&2!=0'"
command -v tcpdump >/dev/null || echo "  ⚠ tcpdump 없음 → pcap 캡처 건너뜀(nstat 재전송은 그대로). 설치: sudo apt-get install -y tcpdump"

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
    # role별 baseline (초기값)
    base=$(grep "$MARK" "$LOG"  2>/dev/null | grep -c 'role=INITIATOR'); base=${base:-0}
    rbase=$(grep "$MARK" "$RLOG" 2>/dev/null | grep -c 'role=RESPONDER'); rbase=${rbase:-0}
    read oI0 rI0 < <(tcp_counters ns1); read oR0 rR0 < <(tcp_counters ns2)
    # P2P 포트만 pcap 캡처(ns1 관점: 양방향 재전송 모두 보임). RPC(8545/8546)는 제외.
    PCAP="$RES/${label}-loss${tag}.pcap"
    if command -v tcpdump >/dev/null; then
      sudo ip netns exec ns1 tcpdump -i veth1 -n -s 96 -w "$PCAP" 'tcp port 30303 or tcp port 30304' >/dev/null 2>&1 &
      TCPDUMP_PID=$!
    fi
    echo "collecting $COLLECT (warmup$WARMUP+measure$MEASURE+buffer$BUFFER) — loss라 느릴 수 있음..."
    out=$(sudo ip netns exec ns1 bash "$DIR/measure-collect.sh" "$RPC" "$ENODE" "$LOG" "$WARMUP" "$COLLECT" "$SETTLE" "$HSTMO")
    echo "$out" | grep -E 'samples=(100|300|500)/|Done' | sed 's/^/    /'
    stop_dump
    read oI1 rI1 < <(tcp_counters ns1); read oR1 rR1 < <(tcp_counters ns2)
    dl=$(echo "$out" | grep -m1 '^Done.')
    att=$(echo "$dl" | grep -o 'attempts=[0-9]*'|cut -d= -f2)
    hsf=$(echo "$dl" | grep -o 'hsFail=[0-9]*'|cut -d= -f2)
    dcf=$(echo "$dl" | grep -o 'discFail=[0-9]*'|cut -d= -f2)
    echo "LOSSSTAT proto=$proto loss=$L attempts=${att:-0} hsFail=${hsf:-0} discFail=${dcf:-0} outI=$((oI1-oI0)) reI=$((rI1-rI0)) outR=$((oR1-oR0)) reR=$((rR1-rR0))" | tee -a "$STAT"
    # role별 신규 줄만 추출 (initiator=INITIATOR, responder=RESPONDER)
    after=$(grep "$MARK" "$LOG"  | grep -c 'role=INITIATOR'); new=$((after-base))
    grep "$MARK" "$LOG"  | grep 'role=INITIATOR' | tail -n "$new"  > "$RES/${label}-loss${tag}.timing"
    rafter=$(grep "$MARK" "$RLOG" | grep -c 'role=RESPONDER'); rnew=$((rafter-rbase))
    grep "$MARK" "$RLOG" | grep 'role=RESPONDER' | tail -n "$rnew" > "$RES/${label}-loss${tag}.resp.timing"
    TARGET_N=$MEASURE bash "$DIR/parse-timing.sh" "$WARMUP" "$RES/${label}-loss${tag}.csv" "$RES/${label}-loss${tag}.timing" \
      | grep -E 'peerTotal|keyReady|connectKeyReady|initiatorAKE|N=' | head -12
  done
  sudo ip netns exec ns1 tc qdisc del dev veth1 root 2>/dev/null || true
  sudo ip netns exec ns2 tc qdisc del dev veth2 root 2>/dev/null || true
done
kill_nodes

echo; echo "==================== LOSS 결과 (이걸 클로드에게 붙여넣기) ===================="
python3 - "$RES" "$STAT" "$WARMUP" "$MEASURE" "$WANT" << 'PY'
import sys,re,os,csv as C,statistics as st
RES,STAT,W,M,WANT=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5])
rec={}
for ln in open(STAT):
    m=re.search(r'proto=(\w+) loss=(\S+) attempts=(\d+) hsFail=(\d+) discFail=(\d+) outI=(\d+) reI=(\d+) outR=(\d+) reR=(\d+)',ln)
    if m:
        p,L=m.group(1),m.group(2)
        rec[(p,L)]=dict(att=int(m.group(3)),hsf=int(m.group(4)),dcf=int(m.group(5)),
                        outI=int(m.group(6)),reI=int(m.group(7)),outR=int(m.group(8)),reR=int(m.group(9)))
def int_med(path,rx,filt):  # authB/ackB/confB (정수, app-level bytes)
    v=[]
    if os.path.exists(path):
        for ln in open(path,errors='ignore'):
            if filt in ln:
                mm=re.search(rx,ln)
                if mm and int(mm.group(1))>0: v.append(int(mm.group(1)))
    return int(st.median(v)) if v else 0
def us_med(path,rx,filt):   # respAKE 등 microsecond → ms median
    v=[]
    if os.path.exists(path):
        for ln in open(path,errors='ignore'):
            if filt in ln:
                mm=re.search(rx,ln)
                if mm:
                    try: v.append(float(mm.group(1))/1000.0)
                    except ValueError: pass
    return st.median(v) if v else None
def csv_med(cf,key):        # steady 표본만
    if not os.path.exists(cf): return None
    v=[float(r[key]) for r in C.DictReader(open(cf)) if r.get('phase')=='steady' and r.get(key)]
    return st.median(v) if v else None
def s(x,fmt="{:.2f}"): return fmt.format(x) if x is not None else "n/a"
LOSSTAGS=[('0','0'),('0.5','0p5'),('1','1'),('2','2'),('5','5')]
for proto in ['xwing','ecies']:
    print(f"\n#### {proto} (RTT30 고정) — 신뢰성 & 재전송 ####")
    print(f"{'loss%':>6}{'att':>6}{'discF':>6}{'hsF':>5}{'succ%':>7}{'reNS':>6}{'outNS':>7}{'reNS%':>7}")
    for L,tag in LOSSTAGS:
        r=rec.get((proto,L))
        if not r:
            print(f"{L:>6}{'-':>6}"); continue
        succ=100*WANT/(WANT+r['hsf']) if (WANT+r['hsf'])>0 else 0    # [요구] 분자=warmup+measure, 분모=성공+hsFail
        rip=100*r['reI']/r['outI'] if r['outI'] else 0
        print(f"{L:>6}{r['att']:>6}{r['dcf']:>6}{r['hsf']:>5}{succ:>6.1f}%{r['reI']:>6}{r['outI']:>7}{rip:>6.1f}%")
    print(f"\n#### {proto} — 크기(app-level bytes) & 지연(ms, median) ####")
    print(f"{'loss%':>6}{'authB':>7}{'ackB':>7}{'confB':>7}{'keyReady':>9}{'connKR':>8}{'iniAKE':>8}{'respAKE':>8}{'peerTot':>8}")
    for L,tag in LOSSTAGS:
        tf=f"{RES}/{proto}L-loss{tag}.timing"; rf=f"{RES}/{proto}L-loss{tag}.resp.timing"; cf=f"{RES}/{proto}L-loss{tag}.csv"
        aB=int_med(tf,r'authB=(\d+)','role=INITIATOR')
        cB=int_med(tf,r'confB=(\d+)','role=INITIATOR')
        kB=int_med(rf,r'ackB=(\d+)','role=RESPONDER')
        kr=csv_med(cf,'keyReady'); ck=csv_med(cf,'connectKeyReady'); ia=csv_med(cf,'initiatorAKE'); pt=csv_med(cf,'peerTotal')
        ra=us_med(rf,r'respAKE\(T6a-T5\)=([\d.]+)','role=RESPONDER')   # 응답자 AKE
        print(f"{L:>6}{aB:>7}{kB:>7}{cB:>7}{s(kr):>9}{s(ck):>8}{s(ia):>8}{s(ra):>8}{s(pt):>8}")
print("\n지표: succ%=(warmup+measure)/((warmup+measure)+hsFail). discF=teardown 실패(핸드셰이크 성공률과 분리).")
print("reNS/outNS=namespace 전체 재전송/총세그먼트(RPC·컨센서스 포함, 상한). P2P포트 한정 재전송은 analyze-retrans.sh(pcap) 사용.")
print("authB/ackB/confB=application-level handshake frame size(bytes, TCP 세그먼트화 이전). respAKE=응답자 T6a-T5.")
PY
echo; echo "---- mutual(양쪽 Hello) loss별 median ----"
for proto in xwing ecies; do for tag in 0 0p5 1 2 5; do
  f="$RES/${proto}L-loss${tag}.timing"; [ -f "$f" ] || continue
  echo "== $proto loss=$tag =="
  bash "$DIR/parse-mutual.sh" "$f" "$RES/${proto}L-loss${tag}.resp.timing" "$WARMUP" "$MEASURE" 2>/dev/null | grep -E 'mutual|짝지음'
done; done
echo; echo "---- P2P포트 재전송(선택, tshark 필요) ----"
[ -x "$DIR/analyze-retrans.sh" ] && bash "$DIR/analyze-retrans.sh" "$RES" 2>/dev/null || echo "analyze-retrans.sh 로 후처리: bash $DIR/analyze-retrans.sh"
echo "==================== 끝 ===================="