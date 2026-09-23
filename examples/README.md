# Example runs

Golden logs from replaying `soft_roce.pcap` (Soft-RoCEv2, UDP/4791) with BTH decode and the QP/PSN tracker.

| File | What it is |
|------|------------|
| [soft_roce_8pkt.log](soft_roce_8pkt.log) | `make PCAP=soft_roce.pcap` — 8 packets, `roce=8`, `msg=1 ack=1` |
| [soft_roce_16pkt.log](soft_roce_16pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=16` — 16 packets, `msg=3 ack=3` |
| [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) | Wave view: `hdr_is_roce`, `dst_port=0x12b7` (4791), `ip_proto=17` |

An RC message is `SEND_FIRST` / `SEND_MIDDLE` / `SEND_LAST` on QP `0x11` with incrementing PSN (`[TRK] OK` then `MSG_DONE`), then a 62-byte `ACK` (`ACK_OK`, runt). Each direction is its own session (`0xe1b96c…` vs `0xb3005c…`). An 8-packet cap stops mid-message on the reverse path; 16 packets complete three messages (`msg=3 ack=3`) and start a fourth (`SEND_FIRST psn=0xb30060`). PSN continues across messages on the same session (`0xe1b96f` then `0xe1b970`).

```
ROCE SEND_FIRST  qp=0x11 psn=0xe1b96c   TRK OK
ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96d   TRK OK
ROCE SEND_MIDDLE qp=0x11 psn=0xe1b96e   TRK OK
ROCE SEND_LAST   qp=0x11 psn=0xe1b96f   TRK MSG_DONE
ROCE ACK         qp=0x11 psn=0xe1b96f   TRK ACK_OK
```

```bash
make PCAP=soft_roce.pcap
make PCAP=soft_roce.pcap MAX_PACKETS=16
make wave
```

TCP/iperf output is in the main [Readme.md](../Readme.md) (`traffic.pcap`).
