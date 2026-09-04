#!/usr/bin/env bash
# measure-collect.sh -- drive clean reconnects and collect EXACTLY N real
# handshake samples. A sample counts only when a NEW "peerTotal(T8-T0)=" timing
# line appears in the initiator's log after admin_addPeer (guarantees N).
#
#   sudo ip netns exec ns1 bash measure-collect.sh \
#        http://10.0.0.1:8545 "<peer enode>" "$HOME/node1.log" 10 100 1.0 15
#
# args: RPC  PEER_ENODE  INITIATOR_LOG  [WARMUP=10] [MEASURE=100] [SETTLE=1.0] [HS_TIMEOUT_SEC=15]
set -u
RPC="$1"; ENODE="$2"; LOG="$3"
WARMUP="${4:-10}"; MEASURE="${5:-100}"; SETTLE="${6:-1.0}"; TMO="${7:-15}"

rpc() { curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}"; }
peers() {
  local h; h="$(rpc net_peerCount '[]' 2>/dev/null | grep -o '0x[0-9a-fA-F]\+' | head -1)"
  [ -z "$h" ] && { echo -1; return; }; echo $(( 16#${h#0x} ))
}
tcount() { grep -c 'peerTotal(T8-T0)=' "$LOG" 2>/dev/null || true; }
# wait_peers <target>: return 0 if reached within 20s, else 1
wait_peers() { local t=0; while [ $t -lt 400 ]; do [ "$(peers)" = "$1" ] && return 0; sleep 0.05; t=$((t+1)); done; return 1; }
# wait_new_timing <baseline_count>: return 0 when count > baseline within TMO sec
wait_new_timing() { local base="$1" t=0 lim=$(( TMO*20 )); while [ $t -lt $lim ]; do [ "$(tcount)" -gt "$base" ] && return 0; sleep 0.05; t=$((t+1)); done; return 1; }

if [ ! -f "$LOG" ]; then echo "LOG not found: $LOG"; exit 1; fi
target=$(( WARMUP + MEASURE ))
samples=0; attempts=0; discFail=0; hsFail=0
echo "Goal: $target real handshakes (warmup $WARMUP + measure $MEASURE)."
echo "RPC=$RPC  LOG=$LOG  SETTLE=$SETTLE  HS_TIMEOUT=${TMO}s"
start=$(date +%s)
while [ $samples -lt $target ]; do
  attempts=$(( attempts + 1 ))
  rpc admin_removePeer "[\"$ENODE\"]" >/dev/null
  if ! wait_peers 0; then discFail=$(( discFail+1 )); sleep "$SETTLE"; continue; fi
  sleep "$SETTLE"
  base="$(tcount)"
  rpc admin_addPeer "[\"$ENODE\"]" >/dev/null
  if ! wait_peers 1; then hsFail=$(( hsFail+1 )); sleep "$SETTLE"; continue; fi
  if ! wait_new_timing "$base"; then hsFail=$(( hsFail+1 )); sleep "$SETTLE"; continue; fi
  samples=$(( samples+1 ))
  sleep "$SETTLE"
  if [ $(( samples % 10 )) -eq 0 ]; then
    echo "  samples=$samples/$target  attempts=$attempts  discFail=$discFail  hsFail=$hsFail"
  fi
done
end=$(date +%s)
echo "Done. samples=$samples  attempts=$attempts  discFail=$discFail  hsFail=$hsFail  elapsed=$((end-start))s"
echo "Note: parse the log for exactly these $samples timing lines. WARMUP=$WARMUP to drop."
echo "Next: bash parse-timing.sh $((WARMUP+1)) result.csv $LOG"
