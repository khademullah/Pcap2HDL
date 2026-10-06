"""ctypes front to dpi/pcap_reader.c (same libpcap path as the DPI-C bench)."""

from __future__ import annotations

import ctypes
import os
from ctypes import c_char_p, c_int, c_uint, c_ubyte


def _load():
    path = os.environ.get("PCAP_DPI_SO", os.path.join(os.path.dirname(__file__), "libpcap_dpi.so"))
    if not os.path.isfile(path):
        raise FileNotFoundError(f"pcap DPI shared object missing: {path}")
    lib = ctypes.CDLL(path)
    lib.open_pcap.argtypes = [c_char_p]
    lib.open_pcap.restype = c_int
    lib.fetch_next_packet.argtypes = []
    lib.fetch_next_packet.restype = c_int
    lib.set_pcap_filter.argtypes = [c_char_p]
    lib.set_pcap_filter.restype = c_int
    lib.get_bpf_match.restype = c_int
    lib.get_bpf_skip.restype = c_int
    lib.get_wire_len.restype = c_int
    lib.get_datalink.restype = c_int
    lib.get_packet_byte.restype = c_ubyte
    lib.get_rss_valid.restype = c_int
    lib.get_rss_hash.restype = c_uint
    lib.get_ip_csum_valid.restype = c_int
    lib.get_ip_csum_ok.restype = c_int
    lib.close_pcap.restype = None
    return lib


class PcapDpi:
    def __init__(self):
        self._lib = _load()

    def open(self, filename: str) -> None:
        if self._lib.open_pcap(filename.encode()) != 0:
            raise RuntimeError(f"open_pcap failed: {filename}")

    def set_filter(self, filt: str) -> None:
        if not filt:
            return
        if self._lib.set_pcap_filter(filt.encode()) != 0:
            raise RuntimeError(f"BPF compile failed: {filt}")

    def fetch(self) -> int:
        return int(self._lib.fetch_next_packet())

    def byte(self) -> int:
        return int(self._lib.get_packet_byte())

    def rss(self) -> tuple[bool, int]:
        ok = self._lib.get_rss_valid() != 0
        return ok, int(self._lib.get_rss_hash())

    def csum_err(self) -> bool:
        if self._lib.get_ip_csum_valid() == 0:
            return False
        return self._lib.get_ip_csum_ok() == 0

    def close(self) -> None:
        self._lib.close_pcap()


def read_run_env() -> dict:
    cfg = {"PCAP": "ci.pcap", "MAX_PACKETS": "8", "FILTER": ""}
    marker = os.path.join(os.path.dirname(__file__), "run.env")
    if os.path.isfile(marker):
        with open(marker, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k] = v.strip().strip('"').strip("'")
        return cfg
    for k in ("PCAP", "MAX_PACKETS", "FILTER"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg
