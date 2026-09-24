# Contributing

This repository is aimed at digital design, verification, and network-hardware engineers. A general software background helps on the DPI-C side; clocked AXI-Stream and L2–L4 still matter for HDL changes. The learning curve is steep if you have not seen a handshake or an Ethernet header before.

## Why this repo exists

Early bring-up of a network pipeline is hard: silicon and a live port are not always available, but captures are. Replaying `.pcap` into SystemVerilog through DPI-C is a normal industry pattern. The stack here is Verilator, SystemVerilog, AXI-Stream (`tvalid` / `tready`), and C (`libpcap`). Soft-RoCEv2 and RSS Toeplitz sit in the same domain as data-center, AI-cluster, and SmartNIC paths.

Sources are split so a change can stay in one module: `hdl/pkt_rss.sv`, `hdl/pkt_size_filter.sv`, `dpi/pcap_reader.c`, and so on. Keep that isolation.

## What you need

- Cycle-accurate thinking: bytes on `tdata` / `tkeep`, packet edges on `tstart` / `tlast`.
- Slave handshake: DUT samples only when `tvalid && tready`. `make BP=1` is the stall gate.
- Packet layout: Ethernet, IPv4, TCP/UDP, optional RoCE BTH.

## Parked work (good first PRs)

See Status in [Readme.md](Readme.md) and “Not in 0.3” in [CHANGELOG.md](CHANGELOG.md).

1. **IPv6** — `pkt_header_parser.sv` is IPv4-only. Parse IPv6 and keep IPv4 gates (`make`, RoCE) green.
2. **VLAN (802.1Q)** — EtherType `0x8100`, then the inner type; shift the L3 window. Do not break untagged `traffic.pcap` / `soft_roce.pcap`.
3. **More traces in `examples/`** — UDP, failed TCP handshake, truncated or malformed frames. Keep `*.pcap` gitignored; commit the log and a short note in `examples/README.md`. Capture with `tcpdump` or `scripts/soft_roce_veth.sh`.
4. **Docs** — how to hang a custom DUT on the same AXI-Stream (`tdata`, `tkeep`, `tvalid`, `tready`, `tstart`, `tlast`, `tuser`). Typos and missing plusargs belong here too.

IPv4 header checksum (C vs HDL, `mis=0` like RSS) is the next stack-vs-hardware gate after VLAN/IPv6. Live sniff, host CSRs, and Ethernet FCS stay out unless a note in CHANGELOG says otherwise.

## Stretch work

Beyond the Status parked list. Keep gates green (`mis=0`, TCP `seq_ok`, RoCE `icrc ok`). Do not replace the DPI-C bench with a UVM env.

### Verification

- **Functional coverage** — `covergroup` on size class (runt / standard / jumbo), TCP flags (SYN, ACK, FIN, RST), and RoCEv2 opcodes already decoded by `pkt_header_parser`.
- **C vs HDL scoreboard** — RSS already compares DPI-C hash on `tuser` with `pkt_rss`. Same pattern for IPv4 checksum, TCP seq windows, or ICRC: compute in `dpi/pcap_reader.c`, check in HDL, count `mis`. Raise on mismatch; do not only `$display`.

### Parser

- **ARP** — EtherType `0x0806`. Classify instead of folding into `other` / trunc. Untagged IPv4 and RoCE logs must stay the same.
- **VXLAN** — UDP dest 4789, skip the overlay, parse the inner Ethernet/IP. Gate with a dedicated capture; default `traffic.pcap` has no VXLAN.

### AXI-Stream

- `tuser` already carries the RSS hash. Extra sideband (early checksum fail, drop reason) needs a new field or a documented `tuser` layout so RSS `mis=0` still holds. `tkeep` is the byte qualifier; `tstrb` only if a DUT actually needs it.
- **Random backpressure** — `BP=1` is every other cycle. A `$urandom` stall generator must not drop or duplicate bytes (same DUT counts as `BP=0` / `BP=1`).

### Tooling

- **GitHub Actions** — install Verilator and `libpcap-dev`, run `make` (and `FILTER=` / RoCE if traces can live in CI). Do not commit `.pcap` files.
- **Scapy helper** under `scripts/` — build truncated, fragmented, or fuzzed captures for the parser. Output stays gitignored; commit the command and the example log.

## How to check

```bash
make
make FILTER='tcp port 5201'    # matched=100 skipped=0
make FILTER='udp'              # streamed 0; skipped=1000
make MAX_PACKETS=8             # compact TCP handshake log
make PCAP=soft_roce.pcap MAX_PACKETS=8
make BP=1
```

Do not add a GUI. Match the existing log style (`[SV]`, `[DUT]`, `[C-DPI]`). License is MIT (`LICENSE`).
