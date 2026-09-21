# -*- coding: utf-8 -*-
"""
DHCP decoding — lease visibility and rogue-server detection.

DHCP is the one protocol that names a host before it has sent a single other
packet: a DISCOVER/REQUEST carries the client's own hostname (option 12),
readable well before DNS or mDNS would reveal it, and an OFFER/ACK says which
server handed out the lease — which matters because anyone on the same
broadcast domain can run a second DHCP server and start handing out addresses
of its own choosing.

Only DHCPv4/BOOTP over UDP 67/68 is parsed. Like netscope_ftp.py and
netscope_smb.py this reads raw option-TLV bytes off the wire rather than
scapy's DHCP layer, so it works the same way against a live packet, an
imported .pcap, or a demo-mode fabrication.
"""

from __future__ import annotations

import struct
import time

MAGIC_COOKIE = b"\x63\x82\x53\x63"

MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_VENDOR_CLASS = 60

# Bounds on how much state a long-running capture accumulates.
MAX_LEASES = 500          # distinct client MACs remembered for the dashboard
MAX_PENDING = 2048        # in-flight (unacknowledged) transactions


def _mac(chaddr: bytes, hlen: int) -> str:
    n = hlen if 0 < hlen <= 16 else 6
    return ":".join("%02x" % b for b in chaddr[:n])


def _ip(b) -> str:
    return ".".join(str(x) for x in b) if b and len(b) == 4 else ""


def _parse_options(data: bytes) -> dict:
    opts = {}
    i, n = 0, len(data)
    while i < n:
        tag = data[i]
        if tag == 255:              # End
            break
        if tag == 0:                # Pad
            i += 1
            continue
        if i + 1 >= n:
            break
        length = data[i + 1]
        val = data[i + 2:i + 2 + length]
        if len(val) < length:
            break                   # truncated option: stop rather than misread
        opts[tag] = val
        i += 2 + length
    return opts


def parse(payload: bytes):
    """
    Decode one BOOTP/DHCP message, or None if this payload is not one.

    Returns msg_type, the transaction id, the client's MAC and hostname (when
    offered), the address involved, the answering server, and the lease terms
    — everything the dashboard and the rogue-server check need.
    """
    if len(payload) < 240 or payload[236:240] != MAGIC_COOKIE:
        return None
    try:
        op, hlen = payload[0], payload[2]
        xid = struct.unpack_from("!I", payload, 4)[0]
        yiaddr = payload[16:20]
        siaddr = payload[20:24]
        chaddr = payload[28:44]
    except Exception:
        return None

    opts = _parse_options(payload[240:])
    msg_type_num = opts[OPT_MSG_TYPE][0] if opts.get(OPT_MSG_TYPE) else 0
    if msg_type_num not in MSG_TYPES:
        return None

    lease_secs = None
    if len(opts.get(OPT_LEASE_TIME, b"")) == 4:
        lease_secs = struct.unpack("!I", opts[OPT_LEASE_TIME])[0]

    hostname = opts.get(OPT_HOSTNAME, b"").decode("utf-8", "replace").strip("\x00")
    dns_opt = opts.get(OPT_DNS, b"")

    return {
        "op": "request" if op == 1 else "reply",
        "msg_type": MSG_TYPES[msg_type_num],
        "xid": xid,
        "mac": _mac(chaddr, hlen),
        "your_ip": _ip(yiaddr),
        "requested_ip": _ip(opts.get(OPT_REQUESTED_IP)),
        "server_id": _ip(opts.get(OPT_SERVER_ID)) or _ip(siaddr),
        "hostname": hostname,
        "vendor_class": opts.get(OPT_VENDOR_CLASS, b"").decode("latin-1", "replace"),
        "lease_secs": lease_secs,
        "subnet": _ip(opts.get(OPT_SUBNET_MASK)),
        "router": _ip(opts.get(OPT_ROUTER)),
        "dns": [_ip(dns_opt[i:i + 4]) for i in range(0, len(dns_opt) - 3, 4)],
    }


def summarise(d: dict) -> str:
    bits = [d["msg_type"]]
    if d.get("hostname"):
        bits.append(d["hostname"])
    ip = d.get("your_ip") or d.get("requested_ip")
    if ip:
        bits.append(ip)
    if d.get("server_id") and d["msg_type"] in ("OFFER", "ACK", "NAK"):
        bits.append("from " + d["server_id"])
    return "  ".join(bits)


class DhcpTracker:
    """
    One instance shared across the whole capture (or one demo run).

    Correlates a DISCOVER/REQUEST — which names the client and, on a renewal,
    the wanted address — with the OFFER/ACK that answers it, by transaction
    id, and keeps a bounded table of the most recent completed lease per
    client MAC for the dashboard.
    """

    def __init__(self):
        self._pending = {}          # xid -> {"mac":, "hostname":, "requested_ip":}
        self._leases = {}           # mac -> lease dict
        # Every DHCP server identifier seen answering, so the caller (the
        # alert rules) can tell a second, unexpected server from the first.
        self.servers = set()

    def observe(self, payload: bytes, ts=None):
        d = parse(payload)
        if d is None:
            return None
        ts = ts if ts is not None else time.time()

        if d["op"] == "request":
            pend = self._pending.get(d["xid"])
            if pend is None:
                if len(self._pending) >= MAX_PENDING:
                    self._pending.pop(next(iter(self._pending)), None)
                pend = self._pending[d["xid"]] = {}
            if d.get("hostname"):
                pend["hostname"] = d["hostname"]
            if d.get("requested_ip"):
                pend["requested_ip"] = d["requested_ip"]
            pend["mac"] = d["mac"]
        elif d["msg_type"] in ("OFFER", "ACK", "NAK") and d.get("server_id"):
            self.servers.add(d["server_id"])
            if d["msg_type"] == "ACK":
                pend = self._pending.get(d["xid"], {})
                ip = d.get("your_ip") or pend.get("requested_ip", "")
                hostname = pend.get("hostname", "")
                existing = self._leases.get(d["mac"])
                lease = {
                    "mac": d["mac"],
                    "ip": ip,
                    "hostname": hostname or (existing or {}).get("hostname", ""),
                    "server": d["server_id"],
                    "lease_secs": d.get("lease_secs"),
                    "router": d.get("router"),
                    "dns": d.get("dns"),
                    "first_seen": (existing or {}).get("first_seen", ts),
                    "last_seen": ts,
                }
                self._leases[d["mac"]] = lease
                if len(self._leases) > MAX_LEASES:
                    oldest = min(self._leases, key=lambda k: self._leases[k]["last_seen"])
                    self._leases.pop(oldest, None)
                self._pending.pop(d["xid"], None)
        return d

    def list(self):
        return sorted(self._leases.values(), key=lambda l: -l["last_seen"])

    def latest(self, mac):
        """The most recently completed lease for one client MAC, or None."""
        return self._leases.get(mac)
