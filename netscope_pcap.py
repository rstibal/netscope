# -*- coding: utf-8 -*-
"""
PCAP export and import.

Writing is done by hand — the classic libpcap format is a 24-byte global
header followed by a 16-byte header per packet, and doing it directly avoids
a round trip through scapy for what is a very simple structure.

Reading goes through scapy's rdpcap, which handles both .pcap and .pcapng and
all the endianness and linktype variations that show up in files from other
tools.
"""

from __future__ import annotations

import os
import struct
import tempfile

PCAP_MAGIC_USEC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


# A frame that arrived with no Ethernet header gets one made for it when the
# file has to be Ethernet. Zeroed deliberately: an invented MAC address that
# looked plausible would be worse than one that is obviously not real.
_SYNTH_ETH_V4 = b"\x00" * 12 + b"\x08\x00"
_SYNTH_ETH_V6 = b"\x00" * 12 + b"\x86\xdd"


def write_pcap(records, snaplen=65535, linktype=None):
    """
    Build a .pcap file in memory.

    `records` is an iterable of (timestamp, raw_bytes, original_length) or
    (timestamp, raw_bytes, original_length, link_layer), where link_layer is
    "eth" or "raw". original_length is what was on the wire; raw_bytes may be
    shorter if the capture was snapped, and pcap represents that honestly with
    the two separate length fields.

    A .pcap file declares one link type for the whole file, but capturing every
    adapter at once can mix them: a tunnel adapter — a VPN's, typically — may
    hand up bare IP where an ordinary NIC hands up Ethernet. Writing those into
    a file labelled Ethernet makes Wireshark read the first 14 bytes of each IP
    header as MAC addresses, which is silent nonsense. So the link type is
    chosen from what is actually present, and only a genuinely mixed capture is
    normalised to Ethernet by prefixing the bare-IP frames with a zeroed header.
    """
    rows = [(r[0], r[1], r[2], (r[3] if len(r) > 3 else "eth"))
            for r in records if r[1]]
    kinds = {k for _ts, _d, _n, k in rows}
    if linktype is None:
        linktype = LINKTYPE_RAW if kinds == {"raw"} else LINKTYPE_ETHERNET
    synthesise = linktype == LINKTYPE_ETHERNET and "raw" in kinds

    out = bytearray()
    out += struct.pack("<IHHiIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, snaplen, linktype)
    for ts, data, orig_len, kind in rows:
        if synthesise and kind == "raw":
            header = _SYNTH_ETH_V6 if (data[0] >> 4) == 6 else _SYNTH_ETH_V4
            data = header + data
            orig_len += len(header)
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:            # rounding can tip it over
            sec += 1
            usec -= 1_000_000
        incl = len(data)
        out += struct.pack("<IIII", sec, usec, incl, max(orig_len, incl))
        out += data
    return bytes(out)


def read_pcap(data: bytes):
    """
    Parse a .pcap or .pcapng file into scapy packets.

    Returns (packets, error). scapy wants a path, so the bytes go through a
    temp file that is always cleaned up.
    """
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        from scapy.utils import rdpcap
        return rdpcap(tmp), None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def sniff_linktype(data: bytes):
    """Best-effort look at a pcap header, so we can warn about odd captures."""
    if len(data) < 24:
        return None
    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAP_MAGIC_USEC:
        return struct.unpack("<I", data[20:24])[0]
    if magic == 0xD4C3B2A1:
        return struct.unpack(">I", data[20:24])[0]
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    return None
