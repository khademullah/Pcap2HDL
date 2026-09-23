# Example runs

Golden logs from replaying `soft_roce.pcap` (Soft-RoCEv2, UDP/4791) after BTH decode.

| File | What it is |
|------|------------|
| [soft_roce_8pkt.log](soft_roce_8pkt.log) | `make PCAP=soft_roce.pcap` — 8 packets, `roce=8` |
| [soft_roce_16pkt.log](soft_roce_16pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=16` — 16 packets (pre-BTH log; opcodes not printed) |
| [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) | Wave view: `hdr_is_roce`, `dst_port=0x12b7` (4791), `ip_proto=17` |

An RC message is `SEND_FIRST` / `SEND_MIDDLE` / `SEND_LAST` on QP `0x11` with incrementing PSN, then a 62-byte `ACK` (runt: below 64-byte Ethernet minimum, still `ROCE`). The reverse direction starts a new PSN series (`0xb3005c`).

```
ROCE SEND_FIRST  qp=0x11 psn=0xe1b96c
ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96d
ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96e
ROCE SEND_LAST   qp=0x11 psn=0xe1b96f
ROCE ACK         qp=0x11 psn=0xe1b96f
```

```bash
make PCAP=soft_roce.pcap
make PCAP=soft_roce.pcap MAX_PACKETS=16
make wave
```

TCP/iperf output is in the main [Readme.md](../Readme.md) (`traffic.pcap`).
