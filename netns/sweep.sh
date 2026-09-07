#!/usr/bin/env bash
# sweep.sh -- RTT sweep for ONE protocol. RUN AS ROOT (sudo); nodes already running.
#   sudo bash sweep.sh <label> <initiatorLog> [MEASURE=100] [WARMUP=10] [SETTLE=1.0] [RTTS="0 10 30 50"]
# Initiator metrics -> results/<label>-rtt<RTT>.{timing,csv}
# Responder respAKE (Node2 own clock) -> results/<label>-rtt<RTT>.resp.{timing} + printed summary
set -u
DIR=/mnt/c/Users/hanati/IdeaProjects/besu/netns
RES="$DIR/results"; mkdir -p "$RES"
RPC="http://10.0.0.1:8545"
ENODE="enode://6f73be34d11d94b69c499d2d709366a0b3b637faa71b9e5d17a8707c6d98033c24ba1de52789825a4bcb4fd18815b3dbb75b3a30a7bb9820d7473b3d9940e8d9@10.0.0.2:30304"
MARK='peerTotal(T8-T0)='

LABEL="${1:?need label}"; LOG="${2:?need initiator log path}"
MEASURE="${3:-100}"; WARMUP="${4:-10}"; SETTLE="${5:-1.0}"; RTTS="${6:-0 10 30 50}"
RLOG="${LOG/node1/node2}"   # responder log
[ -f "$LOG" ] || { echo "initiator log not found: $LOG"; exit 1; }
want=$(( WARMUP + MEASURE ))

for rtt in $RTTS; do
  echo; echo "================ $LABEL  RTT=${rtt}ms ================"
  if [ "$rtt" = "0" ]; then
    ip netns exec ns1 tc qdisc del dev veth1 root 2>/dev/null || true
    ip netns exec ns2 tc qdisc del dev veth2 root 2>/dev/null || true
    echo "netem: cleared (RTT ~0)"
  else
    d=$(( rtt / 2 ))
    ip netns exec ns1 tc qdisc replace dev veth1 root netem delay ${d}ms
    ip netns exec ns2 tc qdisc replace dev veth2 root netem delay ${d}ms
    echo "netem: ${d}ms each way (target RTT ${rtt}ms)"
  fi
  ip netns exec ns1 ping -c2 -q 10.0.0.2 >/dev/null 2>&1
  echo -n "actual ping RTT: "; ip netns exec ns1 ping -c5 -q 10.0.0.2 | awk -F'/' '/=/{print $5" ms (avg)"}'

  base=$(grep -c "$MARK" "$LOG" 2>/dev/null); base=${base:-0}
  rbase=0; [ -f "$RLOG" ] && { rbase=$(grep -c "$MARK" "$RLOG" 2>/dev/null); rbase=${rbase:-0}; }
  echo "collecting $want handshakes (warmup $WARMUP + measure $MEASURE) ..."
  ip netns exec ns1 bash "$DIR/measure-collect.sh" "$RPC" "$ENODE" "$LOG" "$WARMUP" "$MEASURE" "$SETTLE" 20 | sed 's/^/    /'

  # initiator side
  after=$(grep -c "$MARK" "$LOG" 2>/dev/null); after=${after:-0}
  new=$(( after - base ))
  tfile="$RES/${LABEL}-rtt${rtt}.timing"
  grep "$MARK" "$LOG" | tail -n "$new" > "$tfile"
  echo "extracted $new initiator lines -> results/${LABEL}-rtt${rtt}.timing"
  bash "$DIR/parse-timing.sh" "$WARMUP" "$RES/${LABEL}-rtt${rtt}.csv" "$tfile"

  # responder side (Node2 own clock): respAKE = Auth received -> tag_I verified
  if [ -f "$RLOG" ]; then
    rafter=$(grep -c "$MARK" "$RLOG" 2>/dev/null); rafter=${rafter:-0}
    rnew=$(( rafter - rbase ))
    rtfile="$RES/${LABEL}-rtt${rtt}.resp.timing"
    grep "$MARK" "$RLOG" | tail -n "$rnew" > "$rtfile"
    python3 - "$WARMUP" "$rtfile" <<'PY'
import sys,re,math
w=int(sys.argv[1]); f=sys.argv[2]; vals=[]
for ln in open(f,encoding='utf-8',errors='ignore'):
    if 'peerTotal(T8-T0)=' not in ln: continue
    if 'TCP(T1-T0)=n/a' not in ln: continue   # 진짜 responder만 (Node2가 initiator였던 줄 제거)
    m=re.search(r'respAKE\(T6a-T5\)=([\d.]+)', ln)
    if m: vals.append(float(m.group(1))/1000)
vals=vals[w:]; s=sorted(vals); n=len(s)
if n:
    med=s[n//2] if n%2 else (s[n//2-1]+s[n//2])/2
    p90=s[min(n-1,math.ceil(0.9*n)-1)]
    print(f"  [responder respAKE(T6a-T5), Node2 clock] N={n} mean={sum(s)/n:.2f} median={med:.2f} p90={p90:.2f} ms")
else:
    print("  [responder respAKE] no numeric samples (check node2 log)")
PY
  fi
done
ip netns exec ns1 tc qdisc del dev veth1 root 2>/dev/null || true
ip netns exec ns2 tc qdisc del dev veth2 root 2>/dev/null || true
echo; echo "ALL DONE ($LABEL). Files:"; ls -la "$RES" | grep "$LABEL"
