# Contributing

This repository is aimed at digital design, verification, and network-hardware engineers. A general software background helps on the DPI-C side; clocked AXI-Stream and L2–L4 still matter for HDL changes. The learning curve is steep if you have not seen a handshake or an Ethernet header before.

## Why this repo exists

Early bring-up of a network pipeline is hard: silicon and a live port are not always available, but captures are. Replaying `.pcap` into SystemVerilog through DPI-C is a normal industry pattern. The stack here is Verilator, SystemVerilog, AXI-Stream (`tvalid` / `tready`), and C (`libpcap`). Soft-RoCEv2 and RSS Toeplitz sit in the same domain as data-center, AI-cluster, and SmartNIC paths.

Sources are split so a change can stay in one module: `hdl/pkt_rss.sv`, `hdl/pkt_size_filter.sv`, `dpi/pcap_reader.c`, and so on. Keep that isolation.

## What you need

- Cycle-accurate thinking: bytes on `tdata` / `tkeep`, packet edges on `tstart` / `tlast`.
- Slave handshake: DUT samples only when `tvalid && tready`. `make BP=1` is 50% stall; `make BP=2` is random.
- Packet layout: Ethernet, IPv4, TCP/UDP, optional RoCE BTH.

## Parked work (good first PRs)

See Status in [Readme.md](Readme.md) and “Not in 0.3” in [CHANGELOG.md](CHANGELOG.md).

1. **IPv6** — `pkt_header_parser.sv` is IPv4-only. Parse IPv6 and keep IPv4 gates (`make`, RoCE) green.
2. **VLAN (802.1Q)** — EtherType `0x8100`, then the inner type; shift the L3 window. Do not break untagged `traffic.pcap` / `soft_roce.pcap`.
3. **More traces in `examples/`** — UDP, failed TCP handshake, truncated or malformed frames. Keep `*.pcap` gitignored; commit the log and a short note in `examples/README.md`. Capture with `tcpdump` or `scripts/soft_roce_veth.sh`.
4. **Docs** — how to hang a custom DUT on the same AXI-Stream (`tdata`, `tkeep`, `tvalid`, `tready`, `tstart`, `tlast`, `tuser`). Typos and missing plusargs belong here too.

IPv4 header checksum is in 0.4 (`CSUM mis=0`). Live sniff, host CSRs, and Ethernet FCS stay out unless a note in CHANGELOG says otherwise.

## Stretch work (landed)

Keep gates green (`mis=0`, TCP `seq_ok`, RoCE `icrc ok`). Do not replace the DPI-C bench with a UVM env.

### Verification

- `[COV]` counters: size class, TCP SYN/ACK/FIN/RST, RoCE send vs ACK. Verilator 5.032 cannot compile `covergroup`.
- C vs HDL: RSS hash on `tuser`, IPv4 checksum in `pkt_ip_csum` (`CSUM mis=0`). `tuser_err` is checksum-fail sideband.

### Parser

- ARP EtherType `0x0806`.
- VXLAN UDP dest 4789, VNI, inner Ethernet type.

### AXI-Stream

- `make BP=2`: random `tready`. Same DUT counts as `BP=0` / `BP=1`.

### Tooling

- GitHub Actions: `python3 scripts/gen_pcap.py ci.pcap` then `make PCAP=ci.pcap BP=2`.
- `scripts/gen_pcap.py` uses the stdlib (no Scapy in CI).

## How to check

```bash
make
make FILTER='tcp port 5201'    # matched=100 skipped=0
make FILTER='udp'              # streamed 0; skipped=1000
make MAX_PACKETS=8             # compact TCP handshake log
make PCAP=soft_roce.pcap MAX_PACKETS=8
make BP=1
make BP=2
python3 scripts/gen_pcap.py ci.pcap
make PCAP=ci.pcap MAX_PACKETS=8 BP=2
```

Do not add a GUI. Match the existing log style (`[SV]`, `[DUT]`, `[C-DPI]`). License is MIT (`LICENSE`).
