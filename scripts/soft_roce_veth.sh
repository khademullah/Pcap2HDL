#!/usr/bin/env bash
# Soft-RoCE on a host veth pair (no netns), using ibv_rc_pingpong.
#   sudo ./scripts/soft_roce_veth.sh setup
#   sudo ./scripts/soft_roce_veth.sh demo
#   sudo ./scripts/soft_roce_veth.sh cleanup
set -euo pipefail

VETH0=veth0
VETH1=veth1
IP0=192.168.10.1
IP1=192.168.10.2
RXE0=rxe0
RXE1=rxe1
# 0 = RoCEv1 (EtherType 0x8915). 1 = typical RoCEv2 IPv4 GID (UDP/4791).
GID=${GID:-1}
PCAP=${PCAP:-soft_roce.pcap}

need_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "Run as root: sudo $0 $*"
        exit 1
    fi
}

need_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing $1. sudo apt install -y rdma-core ibverbs-utils iproute2 tcpdump"
        exit 1
    fi
}

cmd_setup() {
    need_root
    cmd_cleanup >/dev/null 2>&1 || true
    modprobe rdma_rxe
    ip link add "$VETH0" type veth peer name "$VETH1"
    ip link set "$VETH0" up
    ip link set "$VETH1" up
    ip addr add "$IP0/24" dev "$VETH0"
    ip addr add "$IP1/24" dev "$VETH1"
    rdma link add "$RXE0" type rxe netdev "$VETH0"
    rdma link add "$RXE1" type rxe netdev "$VETH1"
    echo "=== rdma link ==="
    rdma link
    echo "=== ibv_devinfo ==="
    ibv_devinfo
    echo "=== GIDs (RoCEv2 IPv4 is usually index 1, not 0) ==="
    show_gids 2>/dev/null || true
}

cmd_server() {
    need_root
    need_bin ibv_rc_pingpong
    echo "ibv_rc_pingpong server $RXE1 gid=$GID"
    ibv_rc_pingpong -d "$RXE1" -g "$GID"
}

cmd_client() {
    need_root
    need_bin ibv_rc_pingpong
    echo "ibv_rc_pingpong client $RXE0 gid=$GID -> $IP1"
    ibv_rc_pingpong -d "$RXE0" -g "$GID" "$IP1"
}

cmd_capture() {
    need_root
    echo "Capturing on $VETH0 -> $PCAP  (RoCEv2 UDP/4791 and RoCEv1 0x8915)"
    tcpdump -i "$VETH0" -s 0 -B 16384 -w "$PCAP" 'udp port 4791 or ether proto 0x8915'
}

cmd_demo() {
    need_root
    need_bin ibv_rc_pingpong
    need_bin tcpdump
    local pcap_abs
    pcap_abs="$(pwd)/${PCAP}"
    pkill -f ibv_rc_pingpong 2>/dev/null || true
    pkill -f "tcpdump -i ${VETH0}" 2>/dev/null || true
    rm -f "$pcap_abs"
    echo "Demo GID=$GID  pcap=$pcap_abs"
    tcpdump -i "$VETH0" -s 0 -U -B 16384 -w "$pcap_abs" 'udp port 4791 or ether proto 0x8915' >/tmp/soft_roce_tcpdump.out 2>&1 &
    local tpid=$!
    sleep 1
    ibv_rc_pingpong -d "$RXE1" -g "$GID" >/tmp/soft_roce_server.out 2>&1 &
    local spid=$!
    sleep 1
    set +e
    timeout 20 ibv_rc_pingpong -d "$RXE0" -g "$GID" "$IP1"
    local rc=$?
    set -e
    sleep 1
    kill -INT "$spid" 2>/dev/null || true
    kill -INT "$tpid" 2>/dev/null || true
    wait "$tpid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    echo "--- server ---"
    cat /tmp/soft_roce_server.out || true
    echo "--- tcpdump ---"
    cat /tmp/soft_roce_tcpdump.out || true
    echo "Wrote $(stat -c %s "$pcap_abs" 2>/dev/null || echo 0) bytes"
    tcpdump -r "$pcap_abs" -nn -c 12 2>/dev/null || true
    if [[ $rc -ne 0 ]]; then
        echo "pingpong client exited $rc. Try: sudo GID=0 $0 demo   (RoCEv1)"
        exit "$rc"
    fi
}

cmd_cleanup() {
    need_root
    pkill -f ibv_rc_pingpong 2>/dev/null || true
    rdma link delete "$RXE0" 2>/dev/null || true
    rdma link delete "$RXE1" 2>/dev/null || true
    ip link del "$VETH0" 2>/dev/null || true
    echo "veth/rxe removed."
}

usage() {
    echo "Usage: sudo $0 <setup|server|client|capture|demo|cleanup>"
    echo "  GID=0  RoCEv1 (ethertype 0x8915)   GID=1  RoCEv2 (UDP/4791, default)"
    exit 1
}

case "${1:-}" in
    setup)   cmd_setup ;;
    server)  cmd_server ;;
    client)  cmd_client ;;
    capture) cmd_capture ;;
    demo)    cmd_demo ;;
    cleanup) cmd_cleanup ;;
    *)       usage ;;
esac
