# Release notes

## 0.1.0 — 2026-09-23

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

### Not in 0.1

IPv6, VLAN, IPv4 options, full TCP sequence windows, Ethernet FCS, AXI-Stream `tready`, live capture, host CSR map.

License: MIT.
