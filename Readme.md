# Pcap2HDL
A high-performance, progressive hardware-software verification environment that bridges **software network traces** with **hardware description languages (HDL)**. This project leverages SystemVerilog Direct Programming Interface (DPI-C) to stream raw binary `.pcap` files directly into a clock-cycle accurate Verilog hardware simulation using **Verilator**.
##  Purpose & Value
When designing network accelerators (FPGAs/ASICs) for High-Frequency Trading (HFT) or Deep Packet Inspection (DPI), hardware cannot directly interact with a live Ethernet wire during early development phases. 

**Pcap2HDL acts as a Digital Twin:**
* **Deterministic Replay:** Feeds real-world Wireshark traces (`.pcap`) into hardware logic step-by-step.
* **No Packet Loss:** Freezes simulation time to allow deep debugging of complex edge-case network bugs.
* **AXI-Stream Emulation:** Converts static data into real-time streaming hardware protocols with explicit control signaling (`tstart`, `tlast`, `tvalid`).

##  Environment Prerequisites
This framework runs inside a Linux Virtual Machine (e.g., Ubuntu) and relies on open-source EDA and packet capture libraries:
```bash
# Install essential C/C++ build tools and the PCAP development library
sudo apt update
sudo apt install build-essential libpcap-dev
```

Ensure you have **Verilator** installed (Verified on version 5.032+).
##  File Structure
* `Makefile` - Orchestrates the compilation, simulation runs, and waveform generation.
* `tb_pcap_dpi.sv` - SystemVerilog testbench importing C-DPI functions and driving hardware buses.
* `pkt_size_filter.sv` - Streaming length classifier (runt / standard / jumbo).
* `pkt_header_parser.sv` - Streaming L2/L3 parser (MAC, EtherType, IPv4 addresses).
* `pcap_reader.c` - Native C program using `libpcap` to parse raw binary network packets offline.
* `traffic.pcap` - Local packet trace (keep out of git; jumbo captures can be multi-GB).
* `simulation.log` - Output log file mapping packet records.

##  Architecture & Data Flow
1. **Initialization:** The SystemVerilog testbench invokes `open_pcap()` via DPI-C.
2. **Packet Fetching:** The simulator loops up to `MAX_PACKETS` (default **8**). For each packet, C returns the captured length (`caplen`).
3. **Hardware Streaming:** Bytes are driven on the clock negedge so they are stable for the DUT on posedge, with interface flags:
   * `tstart`: Asserted on byte 0 of a packet.
   * `tlast`: Asserted on the final byte of a packet.
   * `tvalid`: Validates active data stream.
4. **Packet sizing (`pkt_size_filter`):** A two-state machine (`IDLE`/`COUNT`) counts `tvalid` beats and pulses `pkt_done` with runt / standard / jumbo flags.
5. **Header parse (`pkt_header_parser`):** Latches dest/src MAC on bytes 0–11, EtherType on 12–13, and IPv4 addresses on 26–33. Pulses `hdr_valid` with `is_ipv4` / `is_non_ipv4` / `is_truncated`.

[ Wireshark (.pcap) ] ➔ [ libpcap (C-DPI) ] ➔ [ SystemVerilog Testbench ] ➔ [ pkt_size_filter + pkt_header_parser ]

## ⚡ Automation Controls (Makefile Commands)

The project includes a robust `Makefile` to quickly manage your verification workflow:

* **Compile and Run Simulation** (default: 8 packets; override as needed):
  ```bash
  make
  make MAX_PACKETS=32
  ```
* **Open Waveform File (VCD) in GTKWave:**
  ```bash
  make wave
  ```
* **Wipe Build Artifacts and Logs:**
  ```bash
  make clean
  ```

## Example run (`make MAX_PACKETS=8`)

A healthy replay prints one `[HDR]` line when L2/L3 fields are ready (byte 33 for IPv4) and one `[DUT]` line when the frame ends (`tlast` → `pkt_done`). MACs swapping direction while IPs stay `192.168.1.1 ↔ 192.168.1.2` is a two-host conversation, not a parser bug.

```
[C-DPI] Successfully opened traffic.pcap
[SV] Streaming up to 8 packets into size filter + header parser
[SV] Processing Packet #1 (Length: 74 bytes)
[HDR] dst=badc18c5a289  src=2a6b39583009  etype=0x0800      IPv4  192.168.1.1 -> 192.168.1.2
[DUT] Classified packet: 74 bytes -> STANDARD
[SV] Processing Packet #2 (Length: 74 bytes)
[HDR] dst=2a6b39583009  src=badc18c5a289  etype=0x0800      IPv4  192.168.1.2 -> 192.168.1.1
[DUT] Classified packet: 74 bytes -> STANDARD
[SV] Processing Packet #3 (Length: 66 bytes)
[HDR] dst=badc18c5a289  src=2a6b39583009  etype=0x0800      IPv4  192.168.1.1 -> 192.168.1.2
[DUT] Classified packet: 66 bytes -> STANDARD
[SV] Processing Packet #4 (Length: 103 bytes)
[HDR] dst=badc18c5a289  src=2a6b39583009  etype=0x0800      IPv4  192.168.1.1 -> 192.168.1.2
[DUT] Classified packet: 103 bytes -> STANDARD
[SV] Processing Packet #5 (Length: 66 bytes)
[HDR] dst=2a6b39583009  src=badc18c5a289  etype=0x0800      IPv4  192.168.1.2 -> 192.168.1.1
[DUT] Classified packet: 66 bytes -> STANDARD
[SV] Processing Packet #6 (Length: 67 bytes)
[HDR] dst=2a6b39583009  src=badc18c5a289  etype=0x0800      IPv4  192.168.1.2 -> 192.168.1.1
[DUT] Classified packet: 67 bytes -> STANDARD
[SV] Processing Packet #7 (Length: 66 bytes)
[HDR] dst=badc18c5a289  src=2a6b39583009  etype=0x0800      IPv4  192.168.1.1 -> 192.168.1.2
[DUT] Classified packet: 66 bytes -> STANDARD
[SV] Processing Packet #8 (Length: 70 bytes)
[HDR] dst=badc18c5a289  src=2a6b39583009  etype=0x0800      IPv4  192.168.1.1 -> 192.168.1.2
[DUT] Classified packet: 70 bytes -> STANDARD

[SV] Reached packet cap of 8. Stopping stream.

[SV] Simulation finished. Streamed 8 packets.
[DUT] Size    runt=0  standard=8  jumbo=0
[DUT] Header  ipv4=8  non-ipv4=0  truncated=0
```

In GTKWave, each `tvalid` burst is one frame: `tstart` on the first beat, `tlast` on the last, `hdr_valid` one cycle after byte 33, `pkt_done` one cycle after `tlast`. `dst_mac` / `src_mac` / `src_ip` / `dst_ip` hold until the next packet overwrites them. At millisecond zoom `clk` looks solid; zoom into one burst to see the 10 ns clock.

##  Progressive Roadmap

Development scales progressively out from the core environment:

- [x] **Milestone 1: Environment Setup** – Successfully stream `.pcap` files into Verilator using DPI-C libraries.
- [x] **Milestone 2: Simulation Control** – Implement safe runtime exits and packet capping.
- [x] **Milestone 3: Packet Sizing Filter** – Verilog state machine classifies runt (<64), standard, and jumbo (>1500) frames.
- [x] **Milestone 4: L2/L3 Header Parser** – Extract dest/src MAC, EtherType, IPv4 addresses; flag non-IPv4 and truncated frames.


