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
##  File Structurwe
* `Makefile` - Orchestrates the compilation, simulation runs, and waveform generation.
* `tb_pcap_dpi.sv` - SystemVerilog testbench importing C-DPI functions and driving hardware buses.
* `pcap_reader.c` - Native C program using `libpcap` to parse raw binary network packets offline.
* `traffic.pcap` - Your target packet trace file captured from Wireshark.
* `simulation.log` - Output log file mapping packet records.

##  Architecture & Data Flow
1. **Initialization:** The SystemVerilog testbench invokes `open_pcap()` via DPI-C.
2. **Packet Fetching:** The simulator loops up to **1,000 packets**. For each packet, C queries the packet length.
3. **Hardware Streaming:** Bytes are streamed sequentially into the Verilog design on every positive edge of the clock (`clk`), accompanied by interface flags:
   * `tstart`: Asserted on byte 0 of a packet.
   * `tlast`: Asserted on the final byte of a packet.
   * `tvalid`: Validates active data stream.

[ Wireshark (.pcap) ] ➔ [ libpcap (C-DPI) ] ➔ [ SystemVerilog Testbench ] ➔ [ Your Verilog Module ]

## ⚡ Automation Controls (Makefile Commands)

The project includes a robust `Makefile` to quickly manage your verification workflow:

* **Compile and Run Simulation:**
  ```bash
  make
  ```
* **Open Waveform File (VCD) in GTKWave:**
  ```bash
  make wave
  ```
* **Wipe Build Artifacts and Logs:**
  ```bash
  make clean
  ```

##  Progressive Roadmap

Development scales progressively out from the core environment:

- [x] **Milestone 1: Environment Setup** – Successfully stream `.pcap` files into Verilator using DPI-C libraries.
- [x] **Milestone 2: Simulation Control** – Implement safe runtime exits and packet capping (e.g., stopping at 1,000 packets).
- [ ] **Milestone 3: Packet Sizing Filter** – Construct a Verilog state machine to monitor packet size and categorize standard frames vs. massive jumbo frames (>1500 bytes).
- [ ] **Milestone 4: L2/L3 Header Parser** – Deep extract EtherType, IPv4 addresses, and check hardware framing limits.


