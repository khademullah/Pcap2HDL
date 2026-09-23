<p align="center">
  <img src="docs/pcap2hdl-logo.png" alt="Pcap2HDL" width="280">
</p>

# Pcap2HDL

Replay captured network traces in a cycle-accurate SystemVerilog simulation.

Pcap2HDL streams `.pcap` files into Verilator through DPI-C (`libpcap`). Each captured byte is driven on an AXI-Stream-like bus (`tdata`, `tvalid`, `tstart`, `tlast`) so hardware under test can see the same frames a NIC would, with simulation time frozen for debug.

Typical uses: early bring-up of FPGA or ASIC packet pipelines (classification, DPI, RoCE-aware paths) before silicon or a live Ethernet port is available.

## Requirements

Linux (Ubuntu is the reference environment), Verilator 5.032 or later, and:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

GTKWave is optional (`make wave`). Soft-RoCE capture additionally needs `rdma-core`, `ibverbs-utils`, and `tcpdump`; see `docs/soft_roce_veth.md`.

## Layout

| Path | Role |
|------|------|
| `Makefile` | Compile, run, waveforms, clean |
| `tb_pcap_dpi.sv` | Testbench: DPI imports, stream driver, plusargs |
| `pkt_size_filter.sv` | Frame length: runt (&lt;64), standard, jumbo (&gt;1500) |
| `pkt_header_parser.sv` | L2–L4 parse; TCP / UDP / Soft-RoCE BTH (opcode, QP, PSN) |
| `pcap_reader.c` | Offline `libpcap` reader (`caplen` bytes) |
| `traffic.pcap` | Local iperf TCP trace (not in git) |
| `soft_roce.pcap` | Local Soft-RoCEv2 trace from `scripts/soft_roce_veth.sh` |
| `docs/` | Capture notes, TCP GTKWave still |
| `examples/` | Soft-RoCE simulation logs and GTKWave still |
| `scripts/soft_roce_veth.sh` | veth + RXE + `ibv_rc_pingpong` capture helper |

## Data path

```
.pcap  ->  libpcap (DPI-C)  ->  testbench byte stream  ->  pkt_size_filter
                                                         ->  pkt_header_parser
```

1. `open_pcap()` opens the file named by `+PCAP=`.
2. Packets are replayed up to `+MAX_PACKETS=` (default 8).
3. Bytes are updated on the clock negedge and sampled by the DUT on posedge.
4. `pkt_size_filter` counts `tvalid` beats and pulses `pkt_done` with length class.
5. `pkt_header_parser` latches MAC, EtherType, IPv4, and L4 ports. UDP port 4791 (or EtherType 0x8915) sets `is_roce` and, for RoCEv2, BTH opcode, dest QP, and PSN.

## Build and run

```bash
make                              # traffic.pcap, 8 packets
make PCAP=soft_roce.pcap          # Soft-RoCEv2
make PCAP=soft_roce.pcap MAX_PACKETS=16
make wave                         # GTKWave on simulation_trace.vcd
make clean
```

Traces are selected at runtime; a rebuild is not required when only `PCAP` or `MAX_PACKETS` changes.

## Example: TCP (`traffic.pcap`)

One `[HDR]` line is printed when headers are valid (after L4 ports for TCP/UDP). One `[DUT]` line follows `tlast`. MAC swap with a stable `192.168.1.1` / `192.168.1.2` pair is a two-host conversation.

```
[HDR] ... IPv4  192.168.1.1:42262 -> 192.168.1.2:5201   TCP
[DUT] Classified packet: 74 bytes -> STANDARD
...
[DUT] Header  ipv4=8  tcp=8  udp=0  roce=0  other=0  trunc=0
```

Waveform: `docs/gtkwave_8pkt.jpg`. Each `tvalid` burst is one frame (`tstart` / `tlast`). At millisecond zoom the 10 ns clock looks solid; zoom into a burst to see edges.

## Example: Soft-RoCE (`soft_roce.pcap`)

```bash
make PCAP=soft_roce.pcap
make PCAP=soft_roce.pcap MAX_PACKETS=16
```

UDP/4791 frames are tagged `ROCE` with BTH opcode, dest QP, and PSN. A pingpong message is Send First/Middle/Last then Ack; the 62-byte Ack is also runt (<64). Full log: `examples/soft_roce_8pkt.log`.

```
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_FIRST qp=0x11 psn=0xe1b96c
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96d
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96e
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_LAST qp=0x11 psn=0xe1b96f
[HDR] ... 192.168.10.2:49441 -> 192.168.10.1:4791  ROCE ACK qp=0x11 psn=0xe1b96f
[DUT] Classified packet: 62 bytes ->     RUNT
...
[DUT] Header  ipv4=8  tcp=0  udp=0  roce=8  other=0  trunc=0
```

Capture a new file with `sudo ./scripts/soft_roce_veth.sh setup` then `demo` (`docs/soft_roce_veth.md`).

## Status

- Environment: DPI-C pcap stream into Verilator
- Control: packet cap and clean exit
- Size filter: runt / standard / jumbo
- L2/L3: MAC, EtherType, IPv4
- L4: TCP/UDP ports; Soft-RoCE on UDP/4791
- RoCEv2 BTH: opcode (SEND_FIRST/MIDDLE/LAST, ACK, …), dest QP, PSN

## License

See `LICENSE`.
