#!/usr/bin/env bash
# sweep.sh -- RTT sweep for ONE protocol. RUN AS ROOT (sudo); nodes must already
# be running for that protocol (node1 in ns1, node2 in ns2).
#
#   sudo bash sweep.sh <label> <initiatorLog> [MEASURE=100] [WARMUP=10] [SETTLE=1.0] [RTTS="0 10 30 50"]
#
# For each target RTT (ms): sets symmetric netem (delay=RTT/2 each way), drives
# WARMUP+MEASURE clean reconnect handshakes, extracts exactly that many NEW timing
# lines from the log, writes results/<label>-rtt<RTT>.{timing,csv}, prints a summary.
set -u
DIR=/mnt/c/Users/hanati/IdeaProjects/besu/netns
RES="$DIR/results"; mkdir -p "$RES"
RPC="http://10.0.0.1:8545"
ENODE="enode://6f73be34d11d94b69c499d2d709366a0b3b637faa71b9e5d17a8707c6d98033c24ba1de52789825a4bcb4fd18815b3dbb75b3a30a7bb9820d7473b3d9940e8d9@10.0.0.2:30304"
MARK='peerTotal(T8-T0)='

LABEL="${1:?need label, e.g. xwing}"; LOG="${2:?need initiator log path}"
MEASURE="${3:-100}"; WARMUP="${4:-10}"; SETTLE="${5:-1.0}"; RTTS="${6:-0 10 30 50}"
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
  ip netns exec ns1 ping -c2 -q 10.0.0.2 >/dev/null 2>&1   # warm (discard cold first packet)
  echo -n "actual ping RTT: "
  ip netns exec ns1 ping -c5 -q 10.0.0.2 | awk -F'/' '/=/{print $5" ms (avg)"}'

  base=$(grep -c "$MARK" "$LOG" 2>/dev/null); base=${base:-0}
  echo "collecting $want handshakes (warmup $WARMUP + measure $MEASURE) ..."
  ip netns exec ns1 bash "$DIR/measure-collect.sh" "$RPC" "$ENODE" "$LOG" "$WARMUP" "$MEASURE" "$SETTLE" 20 | sed 's/^/    /'

  after=$(grep -c "$MARK" "$LOG" 2>/dev/null); after=${after:-0}
  new=$(( after - base ))
  tfile="$RES/${LABEL}-rtt${rtt}.timing"
  grep "$MARK" "$LOG" | tail -n "$new" > "$tfile"
  echo "extracted $new timing lines -> results/${LABEL}-rtt${rtt}.timing"
  bash "$DIR/parse-timing.sh" "$WARMUP" "$RES/${LABEL}-rtt${rtt}.csv" "$tfile"
done

# leave the link clean for next run
ip netns exec ns1 tc qdisc del dev veth1 root 2>/dev/null || true
ip netns exec ns2 tc qdisc del dev veth2 root 2>/dev/null || true
echo; echo "ALL DONE ($LABEL). CSV + timing files in results/:"
ls -la "$RES" | grep "$LABEL"
