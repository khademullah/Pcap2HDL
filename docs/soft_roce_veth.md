# Soft-RoCE (RXE) capture on a veth pair

Soft-RoCE encapsulates verbs in **Ethernet frames** via the kernel stack, so `tcpdump` on the veth works. This recipe keeps **both veths in the host netns** (no namespaces) and uses `ibv_rc_pingpong` from `ibverbs-utils`.

`-g 0` is usually the **RoCEv1** GID (EtherType `0x8915`), not UDP/4791. Capturing only `udp port 4791` with `-g 0` yields an empty pcap. Default here is **`-g 1`** (IPv4 RoCEv2). Capture both:

`udp port 4791 or ether proto 0x8915`

## 1. Packages

```bash
sudo apt update
sudo apt install -y rdma-core ibverbs-utils iproute2 tcpdump
```

## 2–3. veth + `rdma_rxe`

```bash
sudo ./scripts/soft_roce_veth.sh setup
```

Manual:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 192.168.10.1/24 dev veth0
sudo ip addr add 192.168.10.2/24 dev veth1
sudo modprobe rdma_rxe
sudo rdma link add rxe0 type rxe netdev veth0
sudo rdma link add rxe1 type rxe netdev veth1
ibv_devinfo
show_gids
```

## 4–5. Capture, then pingpong

One shot:

```bash
sudo ./scripts/soft_roce_veth.sh demo
tcpdump -r soft_roce.pcap -nn -c 12
wireshark soft_roce.pcap
```

Or three terminals:

```bash
sudo ./scripts/soft_roce_veth.sh capture    # writes soft_roce.pcap
sudo ./scripts/soft_roce_veth.sh server
sudo ./scripts/soft_roce_veth.sh client
```

Equivalent of the original pingpong lines (use `-g 1` for RoCEv2):

```bash
ibv_rc_pingpong -d rxe1 -g 1
ibv_rc_pingpong -d rxe0 -g 1 192.168.10.2
```

RoCEv1 instead:

```bash
sudo GID=0 ./scripts/soft_roce_veth.sh demo
```

## 6. Wireshark

Verified on this VM with `ibv_rc_pingpong -g 1`: GIDs `::ffff:192.168.10.1` ↔ `::ffff:192.168.10.2`, ~630 Mbit/s, and a multi-MB `soft_roce.pcap`.

Stack: Ethernet → IPv4 → **UDP dest 4791** → InfiniBand BTH.

Wireshark names it **RRoCE**. Typical `ibv_rc_pingpong` opcodes:

- RC Send First / Middle (payload ~1040 B UDP)
- RC Acknowledge (20 B UDP)

Filters: `rocev2`, `udp.port == 4791`, `eth.type == 0x8915` (RoCEv1 only).

If tcpdump reports “dropped by kernel”, the burst is faster than the ring; the script uses `-B 16384`. Replay in Pcap2HDL with the current DUT as **IPv4/UDP:4791** until a BTH parser exists.

```bash
# optional: feed this capture into the HDL bench
cp soft_roce.pcap traffic.pcap
make MAX_PACKETS=32
```

## Cleanup

```bash
sudo ./scripts/soft_roce_veth.sh cleanup
```
