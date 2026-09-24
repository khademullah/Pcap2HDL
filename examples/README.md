# Example runs

Reference logs after M1–M4 (`ttl` / `iplen`, TCP handshake, RoCE PSN + AckReq). Verilator footers omitted.

| File | Command | Gate |
|------|---------|------|
| [traffic_8pkt.log](traffic_8pkt.log) | `make` | `tcp=8 hs=1 seq_ok=5 seq_err=0 mismatch=0` `RSS mis=0` |
| [../docs/wireshark_replay.png](../docs/wireshark_replay.png) | `make DUMP=replay.pcap` | Wireshark: 8 Ethernet frames; replay matches DUT |
| [soft_roce_8pkt.log](soft_roce_8pkt.log) | `make PCAP=soft_roce.pcap` | `roce=8 msg=1 ack=1 psn_gap=0 icrc ok=8` |
| [soft_roce_16pkt.log](soft_roce_16pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=16` | `msg=3 ack=3 psn_gap=0` |
| [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) | `make wave` | `hdr_is_roce`, `dst_port=0x12b7` |
| (same gates) | `make BP=1` | `tready` 50%; counts unchanged |
| (same gates) | `make FILTER='tcp port 5201'` | BPF in DPI-C; HDL still `hs=1 seq_ok=5` |
| (0 packets) | `make FILTER='udp'` | TCP capture; end of pcap before cap |

TCP handshake: SYN → SYN-ACK → ACK (`HS_DONE`), then PSH/ACK with next-expected `seq` (`SEQ_OK`). `iplen=60` on the 74-byte SYN (14+60).

RoCE: Send First/Middle/Last + AckReq on Last, reverse ACK (`iplen=48`, runt). Sixteen packets complete three messages; next Send on the same session continues PSN (`0xe1b96f` then `0xe1b970`). Complete frames check ICRC on the last 4 bytes (`ok=8` / `ok=16`); truncated captures are skipped, not failed.

```bash
make
make DUMP=replay.pcap
make PCAP=replay.pcap
make FILTER='tcp port 5201'
make FILTER='udp'
make PCAP=soft_roce.pcap FILTER='udp port 4791'
```

Main write-up: [Readme.md](../Readme.md).
