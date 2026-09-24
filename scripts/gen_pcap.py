#!/usr/bin/env python3
"""Build a tiny Ethernet pcap for parser/CI gates (ARP, IPv4 TCP, VXLAN, runt).

Uses the Python stdlib only so CI does not need Scapy. Output is local
(gitignored *.pcap). Example:

    python3 scripts/gen_pcap.py ci.pcap
    make PCAP=ci.pcap MAX_PACKETS=8 BP=2
"""
from __future__ import annotations

import argparse
import struct
import sys


def ip_csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def pcap_hdr() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def rec(raw: bytes, ts: int = 0) -> bytes:
    return struct.pack("<IIII", ts, 0, len(raw), len(raw)) + raw


def eth(dst: bytes, src: bytes, etype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    ihl = 5
    total = ihl * 4 + len(payload)
    hdr = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total,
            0,
            0,
            64,
            proto,
            0,
            src,
            dst,
        )
    )
    struct.pack_into("!H", hdr, 10, ip_csum(bytes(hdr)))
    return bytes(hdr) + payload


def tcp_syn(sport: int, dport: int) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, (5 << 4), 0x02, 65535, 0, 0)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def arp_request() -> bytes:
    dst = bytes.fromhex("ffffffffffff")
    src = bytes.fromhex("020000000001")
    sha = src
    spa = bytes.fromhex("c0a80101")
    tha = bytes(6)
    tpa = bytes.fromhex("c0a80102")
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sha + spa + tha + tpa
    return eth(dst, src, 0x0806, body)


def tcp_syn_frame() -> bytes:
    src_m = bytes.fromhex("020000000001")
    dst_m = bytes.fromhex("020000000002")
    payload = tcp_syn(34612, 5201)
    return eth(dst_m, src_m, 0x0800, ipv4(bytes.fromhex("c0a80101"), bytes.fromhex("c0a80102"), 6, payload))


def vxlan_frame() -> bytes:
    inner = eth(
        bytes.fromhex("02000000000a"),
        bytes.fromhex("02000000000b"),
        0x0800,
        ipv4(bytes.fromhex("0a000001"), bytes.fromhex("0a000002"), 17, udp(1234, 80, b"hi")),
    )
    vni = 100
    vxh = bytes([0x08, 0, 0, (vni >> 16) & 0xFF, (vni >> 8) & 0xFF, vni & 0xFF, 0, 0])
    outer = ipv4(bytes.fromhex("c0a80a01"), bytes.fromhex("c0a80a02"), 17, udp(4789, 4789, vxh + inner))
    return eth(bytes.fromhex("020000000002"), bytes.fromhex("020000000001"), 0x0800, outer)


def runt() -> bytes:
    return bytes.fromhex("0200000000020200000000010800") + b"short"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("out", nargs="?", default="ci.pcap")
    args = p.parse_args()
    frames = [arp_request(), tcp_syn_frame(), vxlan_frame(), runt()]
    blob = pcap_hdr() + b"".join(rec(f, i) for i, f in enumerate(frames))
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"wrote {args.out} ({len(frames)} frames)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
