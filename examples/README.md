# Example runs

This directory is the compact record of what a green Pcap2HDL replay looks like. The narrative in [Readme.md](../Readme.md) stays short; the logs here are the source of truth for counts, tags, and handshake order.

| Path | In git? | Role |
|------|---------|------|
| `*.log` (this folder) | Yes (`!examples/*.log` in `.gitignore`) | DUT stdout with Verilator footers stripped |
| `soft_roce_gtkwave.jpg` | Yes | GTKWave still of RoCE (`hdr_is_roce`, dest port `0x12b7`) |
| `traffic.pcap`, `soft_roce.pcap`, `ns1_iperf6.pcap`, `ns1_vlan100.pcap`, `ns1_vlan100_ip6.pcap`, `ci.pcap` | No | Local captures / generated CI file |
| `simulation_trace.vcd` | No | Last `make` dump; open with `make wave` |

Regenerate a log by running the command in the first line of that file (`$ make …`), then copy `simulation.log` (drop lines from `Verilog $finish` onward). Do not commit `.pcap` files.

## Index

| File | Command | Gate |
|------|---------|------|
| [traffic_8pkt.log](traffic_8pkt.log) | `make MAX_PACKETS=8` | `ipv4=8 ipv6=0 tcp=8 hs=1 seq_ok=5 seq_err=0` `CSUM ok=8 mis=0` `RSS mis=0` `[NIC] off` |
| [soft_roce_8pkt.log](soft_roce_8pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=8` | `roce=8 msg=1 ack=1 psn_gap=0 icrc ok=8` `CSUM mis=0` |
| [soft_roce_16pkt.log](soft_roce_16pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=16` | `roce=16 msg=3 ack=3 icrc ok=16` |
| [ci_nic.log](ci_nic.log) | `python3 scripts/gen_pcap.py ci.pcap && make NIC=1 PCAP=ci.pcap MAX_PACKETS=8 BP=2` | streamed 7; `arp=1 vxlan=1 ipv6=2 vlan=2 trunc=1` `CSUM mis=0` `RSS mis=0` `[NIC] rx=7 mis=0` |
| [ipv6_20pkt.log](ipv6_20pkt.log) | `make NIC=1 PCAP=ns1_iperf6.pcap MAX_PACKETS=20` | `ipv6=20 tcp=17 hs=2 seq_ok=11 seq_err=0` `CSUM skip=20 mis=0` `RSS mis=0` `[NIC] rx=20` |
| [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) | `make PCAP=soft_roce.pcap MAX_PACKETS=8` then `make wave` | `hdr_is_roce`, UDP dest `0x12b7` (4791) |
| [../docs/wireshark_replay.png](../docs/wireshark_replay.png) | `make DUMP=replay.pcap` then open `replay.pcap` | Same Ethernet frames the AXIS master accepted |
| [bpf_udp.log](bpf_udp.log) | `make FILTER='udp'` | streamed 0; `matched=0 skipped=1000` on `traffic.pcap` |
| [../docs/gtkwave_8pkt.jpg](../docs/gtkwave_8pkt.jpg) | `make MAX_PACKETS=8` then `make wave` | `tvalid` / `tstart` / `tlast` bursts |

Related commands (no dedicated log file; gates must match the parent capture):

| Command | Meaning |
|---------|---------|
| `make` | Default `PCAP=traffic.pcap`, `MAX_PACKETS=100`, observers only (`[NIC] off`) |
| `make NIC=1` | Compile `nic_rx`; `[NIC] rx=` must equal streamed packets |
| `make NIC=1 NIC_PAUSE=1` | Slave toggles `s_tready` (not the same as `BP`) |
| `make BP=1` | Bench `tready` low every other cycle |
| `make BP=2` | Extra random `tready`, AND-ed with the slave when `NIC=1` |
| `make PACE=1` | IFG from pcap timestamps, capped by `PACE_MAX_US` (default 100) |
| `make AXIS_W=64` | Eight-byte beats; rebuilds; DUT counts unchanged; much less sim time on jumbo/TSO frames |
| `make FILTER='tcp port 5201'` | libpcap BPF; HDL only sees matches (`matched` / `skipped`) |
| `make FILTER='udp'` | See [bpf_udp.log](bpf_udp.log) |
| `make PCAP=soft_roce.pcap FILTER='udp port 4791'` | Keep RoCE, drop other UDP/TCP |
| `make NIC=1 PCAP=ns1_vlan100.pcap MAX_PACKETS=20` | Local 802.1Q IPv4 iperf; dump parent veth (see below) |
| `make NIC=1 PCAP=ns1_vlan100_ip6.pcap MAX_PACKETS=20` | Local 802.1Q IPv6 iperf; same parent dump (`ether proto 0x8100`) |
| `make PCAP=replay.pcap` | Replay a `DUMP=` file; DUT summary must match the dump source |

## How to read a log line

| Prefix | When | What it means |
|--------|------|----------------|
| `[SV]` | Bench | File open, DLT, packet index, `caplen` vs wire length, timestamp, cap/EOF |
| `[C-DPI]` | C | libpcap open, BPF install, `matched` / `skipped` at the end |
| `[CSUM]` | After IPv4 header fold | `ffff OK` is RFC 1071 over the **whole** header (including the stored checksum field). IPv6 never prints this; those frames `skip`. |
| `[HDR]` | `hdr_valid` | MACs, EtherType, L3/L4. Tagged frames: `VLAN vid=N` (outer type stays `0x8100`). IPv4 dotted quads; IPv6 32 hex digits (no colons). Ports `0` if next-header is not TCP/UDP (ICMPv6). |
| `[RSS]` | After parse, hashed L3 | Queue `0..3` = hash % 4. `DPI=… MISMATCH` would increment `mis` (C vs HDL). Silent match is `q=N hash=…` only. |
| `[TCP]` | TCP tracker event | `SYN_OK`, `SYNACK_OK`, `HS_DONE`, `SEQ_OK`, `SEQ_ERR`, `FIN_OK`, `RST_OK` |
| `[TRK]` | RoCE tracker | `OK`, `MSG_DONE`, `ACK_OK`, `PSN_ERR`, `PSN_GAP` |
| `[DUT]` | `tlast` or summary | Size class, `LEN_MISMATCH`, ICRC hex, end-of-run counters |
| `[NIC]` | End of run | `off` without `NIC=1`. With the flag: `rx`, `drop`, `byte_mis`, `mis` |
| `[COV]` | End of run | Size bins and TCP flag / RoCE opcode coverage (not SystemVerilog `covergroup`) |

**Size class** (`pkt_size_filter`, `tkeep` popcount): runt &lt; 64, standard 64–1500, jumbo **&gt; 1500** (`JUMBO_THRESH`). A 54-byte IPv4 TCP SYN is **runt** even though headers parsed; that is length, not a parse fail.

### Jumbo frames and Verilator time

`JUMBO` is only a length label. It does not run extra protocol logic. Default `DATA_W=8` is one byte per clock, so a 29026-byte iperf payload is about **29 000 beats**. Two of those cost as much sim time as hundreds of 66-byte ACKs.

Those sizes are typical **TSO/GSO**: the host hands tcpdump one large TCP segment, not a 1500-byte Ethernet frame. Example log shape:

```text
[SV] Processing Packet #27 (captured 66 / wire 66 bytes)
[DUT] Classified packet: 66 bytes -> STANDARD
[SV] Processing Packet #28 (captured 29026 / wire 29026 bytes)
[DUT] Classified packet: 29026 bytes ->    JUMBO
```

Do not drop jumbo in the DUT to go faster: those frames carry TCP payload; skipping them breaks `SEQ_OK`.

Faster replay, same DUT counts:

```bash
make AXIS_W=64 MAX_PACKETS=50
```

That is eight bytes per beat (~3628 beats for a 29026-byte frame instead of ~29026). Rebuilds.

Capture MTU-sized frames instead of TSO blobs (then recapture iperf):

```bash
sudo ethtool -K veth0 tso off gso off gro off
```

Use the veth (or NIC) name you dump with tcpdump. `FILTER='tcp port 5201'` still streams jumbo data frames if they match. Cap work with `MAX_PACKETS`.

**`iplen` vs frame length:** Untagged Ethernet 14 + IP total length. One 802.1Q tag: **18** + IP. IPv4 total length is the IPv4 header field. IPv6 `iplen` in the log is **40 + payload length**. Example: 94-byte untagged IPv6 SYN → `iplen=80`.

**`plen` on TCP:** TCP payload bytes used by the tracker for next-seq (`SEQ_OK`). Handshake ACKs have `plen=0`.

**RSS:** Microsoft Toeplitz. IPv4 TCP/UDP uses 12 bytes (4-tuple); other IPv4 uses 8. IPv6 TCP/UDP uses 36 bytes; other IPv6 uses 32. Same 40-byte key in `hdl/pkt_rss.sv` and `dpi/pcap_reader.c`. `mis` must stay 0. ARP and truncated frames `rss_skip`.

**Checksum scoreboard:** `CSUM mis` is C vs HDL on IPv4 only. `skip` counts ARP, trunc, IPv6, and non-IPv4. `ok` + `err` + `skip` should cover hashed-or-skipped headers for that run.

## `traffic_8pkt.log` — IPv4 iperf TCP

Command: `make MAX_PACKETS=8` (default `traffic.pcap`). Rebuild is not required if you only change `PCAP` / `MAX_PACKETS`.

Two hosts, `192.168.1.1` ↔ `192.168.1.2`, dest port **5201**, source port **34612**. MAC pair `2a6b39583009` / `badc18c5a289`. Numbers below match [traffic_8pkt.log](traffic_8pkt.log).

| # | Bytes | What | Tracker |
|---|-------|------|---------|
| 1 | 74 | SYN `iplen=60` (20 IP + 40 TCP) | `SYN_OK` |
| 2 | 74 | SYN-ACK | `SYNACK_OK` |
| 3 | 66 | ACK `iplen=52` | `HS_DONE` |
| 4 | 103 | PSH ACK `plen=37` (iperf cookie) | `SEQ_OK` |
| 5 | 66 | ACK | `SEQ_OK` |
| 6 | 67 | PSH ACK `plen=1` | `SEQ_OK` |
| 7 | 66 | ACK | `SEQ_OK` |
| 8 | 70 | PSH ACK `plen=4` | `SEQ_OK` |

`seq_ok=5` is packets 4–8, not the handshake. `hs=1` is one completed three-way handshake. Every frame `[CSUM] ffff OK`. RSS: client 4-tuple → `q=0 hash=3eb75670`; server reverse → `q=2 hash=ca4e0aee` (`q0=5 q2=3`). `[NIC] off` because this log was taken without `NIC=1`.

Dump round-trip: `make DUMP=replay.pcap` then `make PCAP=replay.pcap MAX_PACKETS=8` must reprint the same `hs=1 seq_ok=5 CSUM mis=0 RSS mis=0`. Wireshark: [docs/wireshark_replay.png](../docs/wireshark_replay.png).

GTKWave after this run: `tvalid` bursts, `tstart`/`tlast`, `hdr_is_ipv4`, `hdr_is_tcp`. Still: [docs/gtkwave_8pkt.jpg](../docs/gtkwave_8pkt.jpg).

## `soft_roce_8pkt.log` / `soft_roce_16pkt.log` — Soft-RoCEv2

Command: `make PCAP=soft_roce.pcap MAX_PACKETS=8` or `16`. Capture helper: `docs/soft_roce_veth.md` (`scripts/soft_roce_veth.sh`). UDP dest **4791** (`0x12b7`). Outer IPv4 `192.168.10.1` → `192.168.10.2`, QP `0x11`.

Eight-packet story (first message, then reverse traffic):

| # | Tag | Notes |
|---|-----|--------|
| 1 | `SEND_FIRST` | PSN `0xe1b96c`, `[TRK] OK`, ICRC printed |
| 2–3 | `SEND_MIDDLE` | PSN +1 each |
| 4 | `SEND_LAST` **AckReq** | `[TRK] MSG_DONE` |
| 5 | `ACK` | `iplen=48`, **runt** (62-byte frame), `[TRK] ACK_OK` |
| 6–8 | more Send | Reverse-direction Send on the same QP; 8-pkt cap stops mid-message (`msg=1 ack=1`) |

`MAX_PACKETS=16` finishes **three** messages (`msg=3 ack=3`, three runt ACKs) and starts the next `SEND_FIRST`. Next Send PSN continues (`0xe1b96f` then later `0xb30060` on the reverse initiator in this file — two directions, same QP id). `icrc ok=8` / `ok=16`: last 4 bytes of a **complete** frame. Truncated RoCE would `icrc skip`, not `err`.

RSS in this capture stays on `q=1` for all hashed frames (`q1=8` / `q1=16`). IPv4 headers still `[CSUM] ffff OK`.

GTKWave: [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) — add `hdr_is_roce`, `dst_port`, `bth_psn`, `icrc_ok`.

## `ci_nic.log` — synthetic seven-frame CI pcap

`scripts/gen_pcap.py` (Python stdlib, no Scapy) writes, in order:

1. **ARP** request, EtherType `0x0806`, 42 bytes → runt, no IPv4 csum, RSS skip.
2. **IPv4 TCP SYN** 54 bytes → runt by size, still `[CSUM] ffff OK`, `RSS q=0 hash=3eb75670` (same 4-tuple as `traffic_8pkt` SYN), `SYN_OK`. Not `hs` (no SYN-ACK in this file).
3. **VXLAN** UDP/4789, VNI 100, inner Ethernet → `STANDARD`, hashed as IPv4 UDP 4-tuple `q=3`.
4. **Runt** 19-byte IPv4-looking stub → `TRUNC`, `LEN_MISMATCH` (`captured=19` vs garbage `14+iplen`). Expected: `trunc=1`, `mismatch=1`.
5. **IPv6 TCP SYN** EtherType `0x86dd`, `fd00::1:34612` → `fd00::2:5201`, `iplen=60`, `hop=64`, `RSS q=0 hash=fca58788`, `SYN_OK`. No `[CSUM]` line.
6. **802.1Q IPv4 TCP SYN** outer `0x8100`, VID 100, same 4-tuple as frame 2, L3 at byte 18 → `[HDR] ... VLAN vid=100  IPv4 ...`, `[CSUM] ffff OK`, same RSS hash as the untagged SYN.
7. **802.1Q IPv6 TCP SYN** outer `0x8100`, VID 100, inner `0x86dd`, same 4-tuple as frame 5 → `[HDR] ... VLAN vid=100  IPv6 ...`, same RSS hash as the untagged IPv6 SYN, `CSUM skip`.

`BP=2` is in the log header (`extra random tready`). Counts must match `BP=0`. `[NIC] rx=7 drop=0 byte_mis=0 mis=0`. `CSUM skip=4` = ARP + trunc + two IPv6. `RSS skip=2` = ARP + trunc. GitHub Actions greps `Streamed 7 packets`, `ipv6=2`, `vlan=2`, `arp=1`, `vxlan=1`, `mis=0`.

`tcp=4` is the two IPv4 SYNs plus the two IPv6 SYNs. `ipv4=3` is those two IPv4 SYNs plus VXLAN outer IPv4 (VXLAN is not counted as `udp` in the header bins because it is classified VXLAN).

## `ipv6_20pkt.log` — IPv6 iperf (`ns1_iperf6.pcap`)

Local file, not in git. Typical capture:

```bash
sudo ip netns exec ns1 tcpdump -i veth1 ip6 -c 1000 -w ns1_iperf6.pcap
make NIC=1 PCAP=ns1_iperf6.pcap MAX_PACKETS=20
make wave
```

Kernel drops in tcpdump (`packets dropped by kernel`) do not corrupt the 1000 stored frames; they only mean the sniffer lagged behind iperf.

**Packets 1–3 — not TCP.** EtherType `0x86dd`, hop **255**, dest MAC `3333…` (IPv6 multicast) or link-local. Ports print as `0` because next-header is ICMPv6 (MLD / neighbor discovery), not 6 or 17. Still `ipv6` and RSS 2-tuple (32-byte key input). `tcp=17` on the summary = 20 − 3.

**Packets 4–14 — session A.** `fd00::1:44432` ↔ `fd00::2:5201`, hop 64.

| # | Event |
|---|--------|
| 4 | SYN `iplen=80` (40 IPv6 + 40 TCP) |
| 5 | SYN-ACK |
| 6 | ACK → `HS_DONE` |
| 7 | PSH ACK `plen=37` `iplen=109` (14+109=123) |
| 8–14 | ACK / PSH with `SEQ_OK` |

**Packets 15–19 — session B.** Same addresses, source port **44438** (second iperf stream). Another `HS_DONE`, then data.

**Packet 20** returns to session A (`44432`) with `SEQ_OK` — the CAM is 128-bit 4-tuple, four sessions max (`NUM_SESS=4`).

`CSUM skip=20`: IPv6 has no IPv4 header checksum. `RSS mis=0`. `[NIC] rx=20`. GTKWave: `u_snoop` / `u_parser` → `hdr_is_ipv6`, `src_ip6`, `dst_ip6` (128-bit hex). Keep `MAX_PACKETS` small; a 1000-packet VCD is large.

Parser scope: **40-byte IPv6 base header only**. Hop-by-hop, routing, and fragment headers still leave L4 at the wrong offset (parked). Tagged IPv6 uses the same L3 offset as tagged IPv4 (byte 18); QinQ is parked.

## 802.1Q IPv4 (`ns1_vlan100.pcap`)

Local file, not in git. Synthetic VID 100 SYN is frame 6 of [ci_nic.log](ci_nic.log). Keep `make MAX_PACKETS=8` on untagged `traffic.pcap` (`hs=1 seq_ok=5`).

Capture on the **parent** veth (`veth1`), not `veth1.100`. The VLAN subinterface usually strips `0x8100`, so the pcap looks untagged.

```bash
sudo modprobe 8021q

sudo ip netns exec ns1 ip link add link veth1 name veth1.100 type vlan id 100
sudo ip netns exec ns1 ip addr add 192.168.100.1/24 dev veth1.100
sudo ip netns exec ns1 ip link set veth1.100 up

sudo ip netns exec ns2 ip link add link veth2 name veth2.100 type vlan id 100
sudo ip netns exec ns2 ip addr add 192.168.100.2/24 dev veth2.100
sudo ip netns exec ns2 ip link set veth2.100 up
```

Do not put `192.168.100.x` on untagged `veth1` / `veth2`.

```bash
sudo ip netns exec ns1 tcpdump -i veth1 ether proto 0x8100 -c 1000 -w ns1_vlan100.pcap

sudo ip netns exec ns2 iperf3 -s -B 192.168.100.2 -p 5201
sudo ip netns exec ns1 iperf3 -c 192.168.100.2 -B 192.168.100.1 -p 5201 -t 8
```

Wireshark: EtherType `0x8100`, VLAN ID 100, inner `0x0800`. Replay:

```bash
make NIC=1 PCAP=ns1_vlan100.pcap MAX_PACKETS=20
make wave
```

Expect `[HDR] ... etype=0x8100  VLAN vid=100  IPv4 ...`, `[CSUM] ffff OK` on TCP, `vlan=` equal to tagged frames, `CSUM mis=0` `RSS mis=0`. GTKWave: `u_snoop` / `u_parser` → `is_vlan`, `vlan_id`.

IPv6 on the same VID (CI frame 7 is a tagged IPv6 SYN; this capture is the live iperf path):

```bash
sudo ip netns exec ns1 ip -6 addr add fd00:100::1/64 dev veth1.100
sudo ip netns exec ns2 ip -6 addr add fd00:100::2/64 dev veth2.100
sudo ip netns exec ns2 iperf3 -s -6 -B fd00:100::2 -p 5201
sudo ip netns exec ns1 iperf3 -c fd00:100::2 -B fd00:100::1 -6 -p 5201 -t 8
sudo ip netns exec ns1 tcpdump -i veth1 ether proto 0x8100 -c 1000 -w ns1_vlan100_ip6.pcap
```

Replay:

```bash
make NIC=1 PCAP=ns1_vlan100_ip6.pcap MAX_PACKETS=20
make wave
```

Expect `[HDR] ... etype=0x8100  VLAN vid=100  IPv6 ...`, `CSUM skip` on those frames, `RSS mis=0`. CI synthetic tagged IPv6 SYN is frame 7 of [ci_nic.log](ci_nic.log) (`hash=fca58788`, same as untagged IPv6 SYN).

## Bring your own NIC

`make NIC=1` compiles `hdl/nic_rx.sv` (`-DEN_NIC`). Observers stay under `u_snoop` on the **same** AXIS as the slave; they do not sit after a FIFO. Gate: `rx` = streamed, `drop=0`, `byte_mis=0`, `mis=0`. Template pins and pause: [docs/nic.html](../docs/nic.html). `ci_nic.log` and `ipv6_20pkt.log` are the NIC-on examples; TCP/RoCE logs above were taken with NIC off.

## Coverage line (`[COV]`)

Printed because Verilator 5.032 does not compile `covergroup`. `tcp SYN=` counts SYN flags seen, not completed handshakes (`hs` is the tracker). IPv6 log `tcp SYN=4` = two sessions × SYN+SYN-ACK. RoCE `send=` vs `ack=` are BTH opcode bins.

## Full command list

```bash
make MAX_PACKETS=8
make NIC=1 MAX_PACKETS=8
make NIC=1 NIC_PAUSE=1 MAX_PACKETS=8
make BP=1 MAX_PACKETS=8
make BP=2 MAX_PACKETS=8
make PACE=1 MAX_PACKETS=8
make DUMP=replay.pcap MAX_PACKETS=8
make PCAP=replay.pcap MAX_PACKETS=8
make FILTER='tcp port 5201'
make FILTER='udp'
make PCAP=soft_roce.pcap MAX_PACKETS=8
make PCAP=soft_roce.pcap MAX_PACKETS=16
make PCAP=soft_roce.pcap FILTER='udp port 4791'
make AXIS_W=64 PCAP=soft_roce.pcap MAX_PACKETS=8
python3 scripts/gen_pcap.py ci.pcap
make NIC=1 PCAP=ci.pcap MAX_PACKETS=8 BP=2
make NIC=1 PCAP=ns1_iperf6.pcap MAX_PACKETS=20
make NIC=1 PCAP=ns1_vlan100.pcap MAX_PACKETS=20
make NIC=1 PCAP=ns1_vlan100_ip6.pcap MAX_PACKETS=20
make wave
make clean
```

Architecture and plusargs: [docs/architecture.html](../docs/architecture.html), [docs/index.html](../docs/index.html). Parked HDL: QinQ, IPv6 extension headers ([CONTRIBUTING.md](../CONTRIBUTING.md)).
