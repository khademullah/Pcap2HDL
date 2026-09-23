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
| `pkt_header_parser.sv` | L2–L4 parse; TCP flags/seq; Soft-RoCE BTH (opcode, QP, PSN, P_Key, AckReq) |
| `pkt_roce_tracker.sv` | RoCE session CAM: PSN sequence, MSG_DONE, ACK_OK |
| `pkt_tcp_tracker.sv` | TCP 4-tuple CAM: SYN / SYN-ACK / HS_DONE |
| `pcap_reader.c` | Offline `libpcap` reader: bytes, wire length, timestamp, DLT |
| `traffic.pcap` | Local iperf TCP trace (not in git) |
| `soft_roce.pcap` | Local Soft-RoCEv2 trace from `scripts/soft_roce_veth.sh` |
| `docs/` | Capture notes, TCP GTKWave still |
| `examples/` | Soft-RoCE simulation logs and GTKWave still |
| `scripts/soft_roce_veth.sh` | veth + RXE + `ibv_rc_pingpong` capture helper |

## Data path

```
.pcap  ->  libpcap (DPI-C)  ->  testbench byte stream  ->  pkt_size_filter
                                                         ->  pkt_header_parser
                                                         ->  pkt_roce_tracker
                                                         ->  pkt_tcp_tracker
```

1. `open_pcap()` opens the file named by `+PCAP=`; `get_datalink()` reports the capture DLT.
2. Packets are replayed up to `+MAX_PACKETS=` (default 8). After each `fetch_next_packet()`, `get_wire_len()` / `get_ts_sec()` / `get_ts_usec()` expose the pcap header (on-wire length vs stored `caplen`, capture timestamp).
3. Bytes are updated on the clock negedge and sampled by the DUT on posedge.
4. `pkt_size_filter` counts `tvalid` beats and pulses `pkt_done` with length class.
5. `pkt_header_parser` latches MAC, EtherType, IPv4, L4 ports, TCP sequence/flags, and RoCE BTH (opcode, P_Key, AckReq, dest QP, PSN).
6. `pkt_roce_tracker` follows Send First/Middle/Last PSN per `{src,dst,qp}` and matches the reverse-direction ACK.
7. `pkt_tcp_tracker` follows SYN / SYN-ACK / ACK and pulses `HS_DONE` when the handshake seq/ack match.

## Build and run

```bash
make                              # traffic.pcap, 8 packets
make PCAP=soft_roce.pcap          # Soft-RoCEv2
make PCAP=soft_roce.pcap MAX_PACKETS=16
make PACE=1                       # IFG from pcap timestamps (capped at 100 us)
make wave                         # GTKWave on simulation_trace.vcd
make clean
```

Traces are selected at runtime; a rebuild is not required when only `PCAP` or `MAX_PACKETS` changes.

## Example: TCP (`traffic.pcap`)

```bash
make
```

One `[HDR]` line is printed when headers are valid (after L4 ports for TCP/UDP). One `[DUT]` line follows `tlast`. DPI reports DLT, stored vs on-wire length, and the pcap timestamp. MAC swap with a stable `192.168.1.1` / `192.168.1.2` pair is a two-host iperf conversation.

```
[SV] Datalink DLT=1 (Ethernet)
[SV] Processing Packet #1 (captured 74 / wire 74 bytes) ts=1788332455.060537
[HDR] ... IPv4  192.168.1.1:42262 -> 192.168.1.2:5201  TCP SYN seq=0x5803f137 ack=0x00000000
[TCP] SYN_OK
[DUT] Classified packet: 74 bytes -> STANDARD
[SV] Processing Packet #2 ...
[HDR] ... IPv4  192.168.1.2:5201 -> 192.168.1.1:42262  TCP SYN ACK seq=0x15c9e53f ack=0x5803f138
[TCP] SYNACK_OK
...
[TCP] HS_DONE
...
[DUT] Header  ipv4=8  tcp=8  udp=0  roce=0  other=0  trunc=0
[DUT] TCP     hs=1  seq_err=0  op_err=0
[SV] Processing Packet #2 (captured 74 / wire 74 bytes) ts=1788332455.060565
[HDR] ... IPv4  192.168.1.2:5201 -> 192.168.1.1:42262  TCP
...
[DUT] Header  ipv4=8  tcp=8  udp=0  roce=0  other=0  trunc=0
```

Waveform: `docs/gtkwave_8pkt.jpg`. Each `tvalid` burst is one frame (`tstart` / `tlast`). At millisecond zoom the 10 ns clock looks solid; zoom into a burst to see edges.

## Example: Soft-RoCE (`soft_roce.pcap`)

```bash
make PCAP=soft_roce.pcap
make PCAP=soft_roce.pcap MAX_PACKETS=16
```

UDP/4791 frames are tagged `ROCE` with BTH opcode, dest QP, and PSN. The tracker emits `OK` on in-order fragments, `MSG_DONE` on Send Last, and `ACK_OK` on the matching reverse ACK. An 8-packet cap finishes mid-message in the reverse direction (`msg=1 ack=1`). `MAX_PACKETS=16` completes three messages (`msg=3 ack=3`, three runt ACKs) and starts the next Send. Logs: `examples/soft_roce_8pkt.log`, `examples/soft_roce_16pkt.log`.

```
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_FIRST qp=0x11 psn=0xe1b96c
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96d
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96e
[HDR] ... 192.168.10.1:49441 -> 192.168.10.2:4791  ROCE SEND_LAST qp=0x11 psn=0xe1b96f pkey=0xffff
[TRK] MSG_DONE
[HDR] ... 192.168.10.2:49441 -> 192.168.10.1:4791  ROCE ACK qp=0x11 psn=0xe1b96f pkey=0xffff
[TRK] ACK_OK
[DUT] Classified packet: 62 bytes ->     RUNT
...
[DUT] Header  ipv4=8  tcp=0  udp=0  roce=8  other=0  trunc=0
[DUT] Tracker msg=1  ack=1  psn_err=0  op_err=0
```

Capture a new file with `sudo ./scripts/soft_roce_veth.sh setup` then `demo` (`docs/soft_roce_veth.md`).

## Status

- Environment: DPI-C pcap stream into Verilator (bytes, wire length, timestamp, DLT)
- Control: packet cap and clean exit
- Size filter: runt / standard / jumbo
- L2/L3: MAC, EtherType, IPv4
- L4: TCP/UDP ports; TCP flags, seq, ack
- RoCEv2 BTH: opcode, dest QP, PSN, P_Key, AckReq
- Tracker: RoCE PSN/ACK; TCP handshake (SYN / SYN-ACK / HS_DONE)
- Replay: optional `+PACE=1` IFG from pcap timestamps (capped)

## License

See `LICENSE`.
