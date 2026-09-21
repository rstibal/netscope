"""
NBNS (NetBIOS Name Service, RFC 1002) decoding, for host naming.

Legacy, but Windows machines still send it. Names are "first-level encoded":
each of 16 raw bytes is split into two nibbles, each nibble mapped to a
letter A-P — a scheme that predates DNS. The last of those 16 bytes is a
service suffix (0x20 for a file server, 0x00 for a plain workstation, and so
on), not part of the name itself.

parse() is deliberately descriptive only: it never decides whose name an
address belongs to. A broadcast query ("who has this name?") says nothing
trustworthy about the sender, so attributing a name from one would be a
guess dressed as a decode. Only the caller, seeing whether a packet is a
Name Registration/Refresh (the sender claiming a name for itself) or a
positive Name Query Response (an explicit name -> address answer), knows
enough to call store.note_host() -- the same separation netscope_dhcp.parse()
keeps from DhcpTracker's lease correlation.
"""
from __future__ import annotations

import struct

NAME_SUFFIXES = {
    0x00: "Workstation", 0x03: "Messenger", 0x06: "RAS Server",
    0x1B: "Domain Master Browser", 0x1C: "Domain Controller",
    0x1D: "Master Browser", 0x1E: "Browser Election", 0x20: "File Server",
    0x21: "RAS Client",
}

OPCODE_NAMES = {0: "query", 5: "registration", 6: "release", 7: "wack",
                8: "refresh"}


def _decode_name(encoded: bytes):
    """The first-level decode: 32 encoded bytes -> (name, suffix byte)."""
    raw = bytearray(16)
    for i in range(16):
        hi = encoded[2 * i] - 0x41
        lo = encoded[2 * i + 1] - 0x41
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None, None
        raw[i] = (hi << 4) | lo
    suffix = raw[15]
    name = bytes(raw[:15]).decode("latin-1", "replace").rstrip(" \x00")
    return name, suffix


def _read_name_literal(payload: bytes, offset: int):
    if offset >= len(payload) or payload[offset] != 0x20:
        return None
    encoded = payload[offset + 1:offset + 33]
    if len(encoded) != 32:
        return None
    name, suffix = _decode_name(encoded)
    if name is None:
        return None
    end = offset + 33          # length(1) + encoded(32) -> terminator here
    if end >= len(payload) or payload[end] != 0x00:
        return None
    return name, suffix, end + 1


def _read_name(payload: bytes, offset: int):
    """
    One NBNS-encoded name field: a length byte, the 32-byte encoding, a
    terminating zero -- or, commonly in real Windows traffic, a DNS-style
    compression pointer back to the name already given in the question.
    Returns (name, suffix, offset after this field) or None.
    """
    if offset >= len(payload):
        return None
    if payload[offset] & 0xC0 == 0xC0:
        if offset + 2 > len(payload):
            return None
        ptr = struct.unpack_from("!H", payload, offset)[0] & 0x3FFF
        target = _read_name_literal(payload, ptr)
        if target is None:
            return None
        name, suffix, _ = target
        return name, suffix, offset + 2
    return _read_name_literal(payload, offset)


def parse(payload: bytes):
    if len(payload) < 12:
        return None
    flags = struct.unpack_from("!H", payload, 2)[0]
    response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHH", payload, 4)

    offset = 12
    name = suffix = None
    if qdcount:
        got = _read_name(payload, offset)
        if got is None:
            return None
        name, suffix, offset = got
        offset += 4          # QUESTION_TYPE + QUESTION_CLASS

    ips = []
    for _ in range(ancount + nscount + arcount):
        got = _read_name(payload, offset)
        if got is None:
            break
        rname, rsuffix, offset = got
        if name is None:
            name, suffix = rname, rsuffix
        if offset + 10 > len(payload):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", payload, offset)
        offset += 10
        if offset + rdlen > len(payload):
            break
        rdata = payload[offset:offset + rdlen]
        offset += rdlen
        if rtype == 0x0020:
            for j in range(0, len(rdata) - 5, 6):
                ips.append(".".join(str(b) for b in rdata[j + 2:j + 6]))

    if name is None:
        return None
    return {
        "opcode": OPCODE_NAMES.get(opcode, f"opcode {opcode}"),
        "response": response,
        "name": name,
        "suffix": suffix,
        "service": NAME_SUFFIXES.get(suffix, ""),
        "ips": ips,
    }


def summarise(nb):
    kind = ("response " if nb["response"] else "") + nb["opcode"]
    label = nb["name"] + (f" <{nb['service']}>" if nb["service"] else "")
    if nb["ips"]:
        return f"{kind}  {label} → {', '.join(nb['ips'])}"
    return f"{kind}  {label}"
