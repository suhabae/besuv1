#!/usr/bin/env bash
# setup-netns.sh  -- create two network namespaces (ns1, ns2) linked by a veth
#                    pair, and control netem delay/rate on the link.
#
#   ns1 (10.0.0.1) <=== veth ===> ns2 (10.0.0.2)
#
# Usage (all need sudo):
#   sudo ./setup-netns.sh up                       # create ns + veth + IPs
#   sudo ./setup-netns.sh delay 5ms                # +5ms each way  (RTT ~10ms)
#   sudo ./setup-netns.sh delay 15ms rate 100mbit  # +15ms + 100Mbit cap
#   sudo ./setup-netns.sh clear                     # remove netem (delay/rate)
#   sudo ./setup-netns.sh status                    # show qdisc + ping RTT
#   sudo ./setup-netns.sh down                      # tear everything down
set -e
NS1=ns1; NS2=ns2
IP1=10.0.0.1; IP2=10.0.0.2
V1=veth1; V2=veth2

cmd="${1:-up}"
case "$cmd" in
  up)
    ip netns add $NS1
    ip netns add $NS2
    ip link add $V1 type veth peer name $V2
    ip link set $V1 netns $NS1
    ip link set $V2 netns $NS2
    ip netns exec $NS1 ip addr add $IP1/24 dev $V1
    ip netns exec $NS2 ip addr add $IP2/24 dev $V2
    ip netns exec $NS1 ip link set $V1 up
    ip netns exec $NS2 ip link set $V2 up
    ip netns exec $NS1 ip link set lo up
    ip netns exec $NS2 ip link set lo up
    echo "UP: $NS1($IP1) <-> $NS2($IP2)"
    ip netns exec $NS1 ping -c1 -W1 $IP2 >/dev/null && echo "link OK"
    ;;
  delay)
    d="$2"; rate=""
    if [ "$3" = "rate" ]; then rate="rate $4"; fi
    ip netns exec $NS1 tc qdisc replace dev $V1 root netem delay "$d" $rate
    ip netns exec $NS2 tc qdisc replace dev $V2 root netem delay "$d" $rate
    echo "netem set: delay $d each way (RTT ~= 2x $d) $rate"
    echo "measuring actual RTT..."
    ip netns exec $NS1 ping -c 5 $IP2 | tail -2
    ;;
  clear)
    ip netns exec $NS1 tc qdisc del dev $V1 root 2>/dev/null || true
    ip netns exec $NS2 tc qdisc del dev $V2 root 2>/dev/null || true
    echo "netem cleared (delay/rate removed)"
    ;;
  status)
    echo "== ns1 qdisc =="; ip netns exec $NS1 tc qdisc show dev $V1
    echo "== ns2 qdisc =="; ip netns exec $NS2 tc qdisc show dev $V2
    echo "== RTT ns1->ns2 =="; ip netns exec $NS1 ping -c 5 $IP2 | tail -2
    ;;
  down)
    ip netns del $NS1 2>/dev/null || true
    ip netns del $NS2 2>/dev/null || true
    echo "DOWN (namespaces + veth removed)"
    ;;
  *)
    echo "unknown: $cmd  (use: up | delay | clear | status | down)"; exit 1;;
esac
