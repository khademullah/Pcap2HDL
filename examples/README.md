# Example runs

Golden logs and a GTKWave shot from replaying `soft_roce.pcap` (Soft-RoCEv2, UDP/4791).

| File | What it is |
|------|------------|
| [soft_roce_8pkt.log](soft_roce_8pkt.log) | `make PCAP=soft_roce.pcap` — 8 packets, `roce=8`, one 62 B RC Ack tagged RUNT |
| [soft_roce_16pkt.log](soft_roce_16pkt.log) | `make PCAP=soft_roce.pcap MAX_PACKETS=16` — 16 packets, `roce=16`, runt=3 |
| [soft_roce_gtkwave.jpg](soft_roce_gtkwave.jpg) | Wave view: `hdr_is_roce`, `dst_port=0x12b7` (4791), `ip_proto=17` (UDP) |

1082-byte frames are RC Send; 62-byte frames are RC Ack (below the Ethernet 64-byte size-filter floor, still `ROCE`).

```bash
make PCAP=soft_roce.pcap
make PCAP=soft_roce.pcap MAX_PACKETS=16
make wave
```

TCP/iperf golden output stays in the main [Readme.md](../Readme.md) example section (`traffic.pcap`).
