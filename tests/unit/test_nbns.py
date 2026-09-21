import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_nbns as N

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


def encode_name(name, suffix):
    """Inverse of N._decode_name: 15 chars (space-padded) + a suffix byte,
    first-level encoded into 32 bytes."""
    raw = name.encode("latin-1")[:15].ljust(15, b" ") + bytes([suffix])
    out = bytearray(32)
    for i, b in enumerate(raw):
        out[2 * i] = 0x41 + (b >> 4)
        out[2 * i + 1] = 0x41 + (b & 0xF)
    return bytes(out)


def header(opcode, response, qdcount=0, ancount=0, nscount=0, arcount=0, trn_id=0x1234):
    flags = (0x8000 if response else 0) | ((opcode & 0xF) << 11)
    return struct.pack("!HHHHHH", trn_id, flags, qdcount, ancount, nscount, arcount)


def question(name, suffix, qtype=0x0020, qclass=1):
    return bytes([0x20]) + encode_name(name, suffix) + bytes([0]) + \
           struct.pack("!HH", qtype, qclass)


def rr_literal(name, suffix, rtype, rdata, ttl=0, rclass=1):
    return (bytes([0x20]) + encode_name(name, suffix) + bytes([0]) +
            struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata)


def rr_pointer(ptr, rtype, rdata, ttl=0, rclass=1):
    return (struct.pack("!H", 0xC000 | ptr) +
            struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata)


def nb_rdata(*ips):
    out = b""
    for ip in ips:
        out += b"\x00\x00" + bytes(int(o) for o in ip.split("."))
    return out


# ---- 1. Too short / not NBNS at all. ----
check("too short is not NBNS", N.parse(bytes(8)) is None)

# ---- 2. A plain broadcast query carries the name but no attributable IPs. ----
pkt = header(0, False, qdcount=1) + question("WORKGROUP", 0x1E)
nb = N.parse(pkt)
check("plain query decodes the name", nb is not None and nb["name"] == "WORKGROUP", str(nb))
check("plain query has no IPs to attribute", nb["ips"] == [], str(nb))
check("plain query opcode/response read correctly",
      nb["opcode"] == "query" and nb["response"] is False, str(nb))
check("suffix maps to a known service label",
      nb["suffix"] == 0x1E and nb["service"] == "Browser Election", str(nb))

# ---- 3. Name Registration Request: name in the question, address via a
#         compression pointer back to it in the Additional section -- the
#         common shape real Windows hosts actually send.
qname = question("ROBS-PC", 0x00)
ar = rr_pointer(12, 0x0020, nb_rdata("192.168.1.50"))
pkt = header(5, False, qdcount=1, arcount=1) + qname + ar
nb = N.parse(pkt)
check("registration decodes via a compressed RR name",
      nb is not None and nb["name"] == "ROBS-PC", str(nb))
check("registration carries the registering address",
      nb["ips"] == ["192.168.1.50"], str(nb))
check("registration opcode read correctly", nb["opcode"] == "registration", str(nb))

# ---- 4. Positive Name Query Response: literal RR name (no question to
#         point back to), possibly more than one address for a multi-homed
#         host.
an = rr_literal("FILESERVER", 0x20, 0x0020, nb_rdata("10.0.0.5", "10.0.0.6"))
pkt = header(0, True, ancount=1) + an
nb = N.parse(pkt)
check("positive response decodes the literal name",
      nb is not None and nb["name"] == "FILESERVER", str(nb))
check("positive response carries both addresses",
      nb["ips"] == ["10.0.0.5", "10.0.0.6"], str(nb))
check("positive response is flagged as a response", nb["response"] is True, str(nb))
check("file-server suffix labelled", nb["service"] == "File Server", str(nb))

# ---- 5. A truncated Additional record after a good question still returns
#         the name from the question, minus the IP it never got to.
pkt = header(5, False, qdcount=1, arcount=1) + question("PARTIAL", 0x00) + bytes([0x20])
nb = N.parse(pkt)
check("truncated trailing record -> no crash, question name kept",
      nb is not None and nb["name"] == "PARTIAL" and nb["ips"] == [], str(nb))

# ---- 6. A malformed encoded name (bytes outside A-P) is rejected, not guessed at.
bad = bytearray(question("X" * 15, 0))
bad[1] = 0x30   # '0' is outside the A-P encoding range
check("malformed name encoding -> None", N.parse(header(0, False, qdcount=1) + bytes(bad)) is None)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
