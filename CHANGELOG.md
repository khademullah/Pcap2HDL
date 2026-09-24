# Release notes

## Unreleased (0.4)

C vs HDL IPv4 checksum, ARP and VXLAN classify, random `tready`, synthetic pcap helper, GitHub Actions.

### DUT / replay

- `pkt_ip_csum`: RFC 1071 header checksum. DPI-C folds the same bytes; gate `CSUM mis=0`. `tuser` stays the RSS hash; `tuser_err` is C checksum-fail sideband.
- ARP (`0x0806`) is not `other`. VXLAN (UDP dest 4789) walks the overlay to the inner Ethernet type and reports `vni`.
- `make BP=2`: `$urandom` `tready`. DUT counts must match `BP=0`.
- Coverage bins printed as `[COV]` (size class, TCP flags, RoCE send/ack). Verilator 5.032 does not support `covergroup`.

### Tooling

- `python3 scripts/gen_pcap.py ci.pcap` (stdlib; ARP + TCP SYN + VXLAN + runt).
- `.github/workflows/ci.yml`: generate that file, `make PCAP=ci.pcap BP=2`.

### How to check

```bash
python3 scripts/gen_pcap.py ci.pcap
make PCAP=ci.pcap MAX_PACKETS=8 BP=2   # arp=1 vxlan=1 CSUM mis=0 streamed 4
make MAX_PACKETS=8                    # ipv4=8 tcp=8 hs=1 seq_ok=5 CSUM ok=8 mis=0
make BP=2 MAX_PACKETS=8               # same TCP gate as BP=0
```

## 0.3.0

C and HDL agree on RSS; libpcap reports what it dropped. Sources sit in `hdl/` and `dpi/`.

### Replay (DPI-C)

- BPF skip count: compile the filter, apply `pcap_offline_filter` per frame (no `pcap_setfilter`). Bench prints `BPF matched=` / `skipped=` for frames walked over while filling `MAX_PACKETS`. Unread tail of the file is neither match nor skip.
- Default `MAX_PACKETS` is 100.

### DUT

- NIC RSS: Microsoft Toeplitz on the IPv4 4-tuple (TCP/UDP) or 2-tuple (other IPv4). DPI-C puts the hash on `tuser`; `pkt_rss` recomputes after parse. Gate `mis=0`. Queue = `hash % 4`.

### Layout

- SystemVerilog under `hdl/`, DPI-C under `dpi/`. Makefile rebuilds if those paths change.

### How to check

```bash
make                                    # traffic.pcap, 100 packets; RSS mis=0
make FILTER='tcp port 5201'             # matched=100 skipped=0
make FILTER='udp'                       # streamed 0; skipped=1000
make PCAP=soft_roce.pcap MAX_PACKETS=8   # roce=8 msg=1 ack=1 icrc ok=8
make PCAP=soft_roce.pcap MAX_PACKETS=16  # msg=3 ack=3
make AXIS_W=64 PCAP=soft_roce.pcap MAX_PACKETS=8
```

Traces stay local (gitignored). Compact handshake logs: `make MAX_PACKETS=8` → `examples/`.

### Not in 0.3

IPv6, VLAN, IPv4 header checksum, Ethernet FCS, live capture, host CSR map.

## 0.2.0

Stack-meets-HDL: libpcap decides the slice and can write the bus back; the DUT is a real AXI-Stream slave with TCP next-seq.

### Replay (DPI-C)

- `tready`: DUT samples only on `tvalid && tready`. `make BP=1` stalls every other cycle; classification matches 0.1.
- `DUMP=replay.pcap`: accepted beats written through `pcap_dump` (same DLT and timestamps). `make PCAP=replay.pcap` must match the original DUT summary. Wireshark still: `docs/wireshark_replay.png`.
- `FILTER=`: `pcap_compile` / `pcap_setfilter` on the offline handle. HDL only streams matches. `MAX_PACKETS` counts hits, not file order.

### DUT

- TCP next-seq: payload = `iplen − IHL×4 − data-offset×4`; SYN/FIN consume one. In-order data/ACK after handshake is `SEQ_OK`.

### How to check

```bash
make                                    # ipv4=8 tcp=8 hs=1 seq_ok=5 seq_err=0
make BP=1
make FILTER='tcp port 5201'             # same TCP gate; BPF in C
make FILTER='udp'                       # traffic.pcap: streamed 0
make DUMP=replay.pcap
make PCAP=replay.pcap
make PCAP=soft_roce.pcap                # roce=8 msg=1 ack=1 icrc ok=8
make PCAP=soft_roce.pcap FILTER='udp port 4791'
make PCAP=soft_roce.pcap MAX_PACKETS=16  # msg=3 ack=3
make AXIS_W=64 PCAP=soft_roce.pcap
```

Traces stay local (gitignored).

### Not in 0.2

IPv6, VLAN, IPv4 options, Ethernet FCS, live capture, host CSR map.

## 0.1.0

First public cut: replay a captured Ethernet `.pcap` into Verilator and classify IPv4 TCP and Soft-RoCEv2 in cycle-accurate HDL.

### Replay

- DPI-C `libpcap` reader: bytes, on-wire length, timestamps, DLT
- Plusargs: `+PCAP=`, `+MAX_PACKETS=` (default 8), `+PACE=1` IFG from pcap timestamps (capped), `+PACE_MAX_US=`
- AXI-Stream-like bus: `tdata`, `tkeep`, `tvalid`, `tstart`, `tlast`
- Default 8 bits per cycle; `make AXIS_W=64` packs eight bytes per beat

### DUT

- Size class: runt (&lt;64), standard, jumbo (&gt;1500)
- IPv4 L2–L4: MAC, EtherType, TTL, total length vs captured (`LEN_MISMATCH`), TCP/UDP ports, TCP flags/seq/ack
- Soft-RoCEv2 (UDP/4791): BTH opcode, dest QP, PSN, P_Key, AckReq
- RoCE session CAM: in-order Send, `MSG_DONE`, reverse `ACK_OK`, next-message `PSN_GAP`
- TCP 4-tuple CAM: SYN / SYN-ACK / `HS_DONE`, FIN, RST
- RoCEv2 ICRC on the last 4 bytes of a complete frame; truncated captures are skipped, not failed

### How to check

```bash
make                              # traffic.pcap: ipv4=8 tcp=8 hs=1 mismatch=0
make PCAP=soft_roce.pcap          # roce=8 msg=1 ack=1 psn_gap=0 icrc ok=8
make PCAP=soft_roce.pcap MAX_PACKETS=16
make AXIS_W=64 PCAP=soft_roce.pcap
```

Traces stay local (gitignored). Capture Soft-RoCE with `scripts/soft_roce_veth.sh`. Reference logs: `examples/`.

License: MIT.
