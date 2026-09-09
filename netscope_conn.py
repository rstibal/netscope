# -*- coding: utf-8 -*-
"""
The connection table — what is open right now, rather than what just went past.

The packet list answers "what happened"; this answers "what is my machine
talking to at this moment, and which program is doing it". Those are different
questions, and the second is usually the one you actually have.

Two sources are joined here:

* The OS socket table (psutil), which is authoritative about what exists and
  what state it is in, and knows the owning PID — but knows nothing about
  volume, because the kernel does not hand out per-socket byte counts through
  any interface psutil exposes.
* Flow accounting off the capture, which knows exactly how many bytes moved in
  each direction — but only sees packets, so it cannot tell you that a socket
  is LISTENing or that a connection is idle rather than gone.

Neither is sufficient alone. The join key is the connection's 5-tuple,
normalised so both directions land in the same bucket.
"""

from __future__ import annotations

import socket
import time
from collections import OrderedDict

try:
    import psutil
except Exception:                                   # pragma: no cover
    psutil = None


# A flow is dropped once it has been silent this long, so a long-running
# capture does not accumulate a row per host it ever spoke to.
FLOW_IDLE = 900.0
MAX_FLOWS = 4000
# How long a flow with no matching socket still counts as "just closed".
RECENT_CLOSED = 90.0
# The socket table is expensive to enumerate; the dashboard polls, so cache.
SOCKET_TTL = 1.0
# Seconds of per-connection activity kept for the inline sparkline.
SPARK_SECONDS = 40


def _ip(addr) -> str:
    """psutil hands back IPv6 addresses with a scope id attached."""
    return str(addr or "").split("%")[0]


WILDCARD = ("0.0.0.0", "::", "")


def flow_key(proto, a_ip, a_port, b_ip, b_port, iface=""):
    """
    A direction-independent key for one conversation on one adapter.

    Sorting the two endpoints means a packet out and the reply back land on the
    same row — without it every connection appears twice and neither half has
    the whole byte count.

    The adapter is part of the key because a VPN puts the same data on the wire
    twice: the real conversation on the tunnel adapter, and the encapsulated
    copy on the physical NIC. Those are two different conversations and merging
    them would double every byte count. It also keeps a packet seen on two
    adapters — a bridge and its member, say — from being counted twice.
    """
    a, b = (_ip(a_ip), int(a_port or 0)), (_ip(b_ip), int(b_port or 0))
    lo, hi = (a, b) if a <= b else (b, a)
    return (proto, iface or "", lo[0], lo[1], hi[0], hi[1])


def key_endpoints(key):
    """The two (ip, port) ends of a flow key."""
    _proto, _iface, a_ip, a_port, b_ip, b_port = key
    return (a_ip, a_port), (b_ip, b_port)


def _quality(f, rec, now):
    """
    Update the health numbers for one conversation from one packet.

    Everything here is derived from what is already on the wire in plaintext,
    so it works against encrypted traffic too — you cannot read a TLS session
    but you can time its handshake and count its retransmissions.

    Deliberately cheap and stateless-per-packet: a few comparisons and no
    per-segment history. Tracking every sequence number to tell a true
    retransmission from a reordered segment costs memory proportional to the
    window and still only guesses, so this counts the honest thing — segments
    covering ground already seen — and calls it that.
    """
    d = rec.get("decoded") or {}
    direction = rec.get("dir") or "in"

    tcp = d.get("tcp")
    if tcp:
        flags = tcp.get("flags") or ""
        # Handshake RTT: the outbound SYN to the SYN/ACK that answers it. One
        # clean round trip, measured before any application data muddies it.
        if "S" in flags and "A" not in flags and direction == "out":
            f["_syn"] = now
        elif "S" in flags and "A" in flags and direction == "in":
            if f["_syn"] is not None and f["rtt"] is None:
                f["rtt"] = round((now - f["_syn"]) * 1000, 1)

        seq = tcp.get("seq")
        plen = int(rec.get("payload_len") or 0)
        if seq is not None:
            if plen:
                end = seq + plen
                prev = f["_next"].get(direction)
                if prev is not None and end <= prev:
                    f["resent"] += 1
                elif prev is None or end > prev:
                    f["_next"][direction] = end
            else:
                # A bare ACK repeating the last one is the classic loss signal.
                ack = tcp.get("ack")
                if ack is not None and "A" in flags:
                    last, count = f["_ack"].get(direction, (None, 0))
                    if ack == last:
                        count += 1
                        if count >= 2:          # the third identical ACK
                            f["dup_ack"] += 1
                    else:
                        count = 0
                    f["_ack"][direction] = (ack, count)

    tls = d.get("tls")
    if tls:
        if tls.get("handshake") == "ClientHello" and f["_hello"] is None:
            f["_hello"] = now
        elif (tls.get("record") == "ApplicationData" and f["_hello"] is not None
                and f["tls_ms"] is None):
            f["tls_ms"] = round((now - f["_hello"]) * 1000, 1)


def spark_series(f, now, seconds=SPARK_SECONDS):
    """
    The last `seconds` of a flow's activity as bytes per second, oldest first.

    Gaps are filled here rather than on the capture path: a connection that was
    silent for forty seconds should read as forty seconds of silence, but
    storing that silence would cost an array per idle flow.
    """
    bk = f.get("_bk") or {}
    if not bk:
        return []
    end = int(now)
    return [bk.get(sec, 0) for sec in range(end - seconds + 1, end + 1)]


class FlowTable:
    """Per-conversation byte and packet counters, fed from the capture."""

    def __init__(self, max_flows=MAX_FLOWS):
        self._flows = OrderedDict()
        self.max_flows = max_flows
        self._last_prune = 0.0

    def observe(self, rec):
        """
        Account one packet. Called on the capture path, so it stays cheap:
        a dict lookup, a few adds, and a prune that only runs once a minute.
        """
        sport, dport = rec.get("sport"), rec.get("dport")
        if sport is None or dport is None:
            return                                  # no ports, no connection
        # Not defaulted to "tcp": guessing would merge a UDP conversation with
        # a TCP one that happens to share both ports, and the row would then
        # claim a protocol nobody observed.
        proto = rec.get("transport") or "?"
        iface = rec.get("iface") or ""
        key = flow_key(proto, rec.get("src"), sport, rec.get("dst"), dport, iface)

        now = rec.get("ts") or time.time()
        f = self._flows.get(key)
        if f is None:
            f = {"first": now, "last": now, "in": 0, "out": 0, "packets": 0,
                 "process": rec.get("process") or "", "pid": rec.get("pid"),
                 "rhost": "", "proto": proto, "iface": iface,
                 # -- connection quality, filled in by _quality() below
                 "rtt": None,        # TCP handshake, ms
                 "tls_ms": None,     # ClientHello to first ApplicationData, ms
                 "resent": 0,        # segments covering ground already seen
                 "dup_ack": 0,       # repeated bare ACKs — the shape of loss
                 "_syn": None, "_hello": None,
                 "_next": {}, "_ack": {},
                 # Second -> bytes, for the activity sparkline. A dict rather
                 # than a fixed ring because most flows are idle most of the
                 # time: an idle one costs a couple of entries instead of a
                 # full array of zeros, and the gaps are filled at read time.
                 "_bk": {}}
            self._flows[key] = f
        length = int(rec.get("length") or 0)
        if rec.get("dir") == "out":
            f["out"] += length
        else:
            f["in"] += length
        f["packets"] += 1
        f["last"] = now
        sec = int(now)
        bk = f["_bk"]
        bk[sec] = bk.get(sec, 0) + length
        if len(bk) > SPARK_SECONDS + 20:
            cutoff = sec - SPARK_SECONDS
            for k in [k for k in bk if k < cutoff]:
                del bk[k]
        # Later packets often carry attribution the first one lacked, and the
        # hostname only turns up once a DNS reply or a ClientHello goes by.
        if not f["process"] and rec.get("process"):
            f["process"] = rec["process"]
            f["pid"] = rec.get("pid")
        if not f["rhost"] and rec.get("rhost"):
            f["rhost"] = rec["rhost"]
        _quality(f, rec, now)
        self._flows.move_to_end(key)
        self._prune(now)

    def _prune(self, now):
        if now - self._last_prune < 60.0 and len(self._flows) <= self.max_flows:
            return
        self._last_prune = now
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)
        # OrderedDict is in least-recently-active order, so the idle ones are
        # all at the front and the walk stops at the first live entry.
        while self._flows:
            key, f = next(iter(self._flows.items()))
            if now - f["last"] <= FLOW_IDLE:
                break
            self._flows.popitem(last=False)

    def get(self, key):
        return self._flows.get(key)

    def snapshot(self):
        return dict(self._flows)

    def clear(self):
        self._flows.clear()


class SocketTable:
    """Cached view of the OS socket table."""

    def __init__(self, ttl=SOCKET_TTL):
        self.ttl = ttl
        self._at = 0.0
        self._rows = []
        self.available = psutil is not None
        self.error = "" if psutil is not None else "psutil is not installed"

    def rows(self, now=None):
        now = now or time.time()
        if self._rows and now - self._at < self.ttl:
            return self._rows
        if not self.available:
            return []
        out = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.laddr:
                    continue
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                out.append({
                    "proto": proto,
                    "state": c.status or "",
                    "pid": c.pid,
                    "laddr": _ip(c.laddr[0]), "lport": int(c.laddr[1]),
                    "raddr": _ip(c.raddr[0]) if c.raddr else "",
                    "rport": int(c.raddr[1]) if c.raddr else 0,
                })
            self.error = ""
        except (psutil.AccessDenied, PermissionError):
            self.error = ("the socket table needs administrator rights — "
                          "run NetScope elevated to see every process")
        except Exception as exc:
            self.error = str(exc)
        self._rows = out
        self._at = now
        return out


def build_view(sockets, flows, name_for_pid=None, host_for_ip=None, now=None):
    """
    Merge the socket table with flow accounting into what the dashboard shows.

    Returns three lists, because they answer three different questions:
    open connections (what is talking), listeners (what could be talked to),
    and recently closed flows (what just stopped) — that last one matters
    because short connections are gone from the socket table long before you
    finish reading the row.
    """
    now = now or time.time()
    name_for_pid = name_for_pid or (lambda pid: "")
    host_for_ip = host_for_ip or (lambda ip: "")

    table = flows.snapshot()

    # Index every flow by each of its two endpoints, and again by port alone.
    # A connected socket can be found by its full tuple, but an *unconnected*
    # UDP socket has no remote address at all — one socket carries many
    # conversations — so it can only be found by its local end. Requiring the
    # full tuple was why every unconnected UDP conversation (DNS, mDNS, QUIC
    # from some clients, and a VPN's own tunnel socket) matched nothing and
    # fell through to "recently closed" while still being attributed to the
    # right process everywhere else in the app.
    # Dicts, not lists, because a flow whose two ends share a port indexes
    # itself twice otherwise — and same-port-both-ends is not exotic: mDNS
    # (5353), NTP (123) and OpenVPN in its usual configuration all look like
    # that, and the duplicate showed up as the same conversation listed twice.
    by_endpoint, by_port = {}, {}
    for key in table:
        proto = key[0]
        for ip, port in key_endpoints(key):
            by_endpoint.setdefault((proto, ip, port), {})[key] = None
            by_port.setdefault((proto, port), {})[key] = None

    open_rows, listening, matched = [], [], set()

    def row_for(s, key, listen):
        f = table.get(key) if key else None
        proc = (f or {}).get("process") or ""
        if not proc and s["pid"]:
            proc = name_for_pid(s["pid"]) or ""
        raddr, rport = s["raddr"], s["rport"]
        if f and not raddr:
            # An unconnected socket does not know its peer; the flow does.
            for ip, port in key_endpoints(key):
                if (ip, port) != (s["laddr"], s["lport"]):
                    raddr, rport = ip, port
                    break
        return {
            "proto": s["proto"],
            "state": s["state"] or ("LISTEN" if listen else ""),
            "pid": s["pid"],
            "process": proc or "-",
            "laddr": s["laddr"], "lport": s["lport"],
            "raddr": raddr, "rport": rport,
            "iface": (f or {}).get("iface", ""),
            "rhost": (f or {}).get("rhost") or (host_for_ip(raddr) if raddr else ""),
            "in": (f or {}).get("in", 0),
            "out": (f or {}).get("out", 0),
            "packets": (f or {}).get("packets", 0),
            "spark": spark_series(f, now) if f else [],
            "rtt": (f or {}).get("rtt"),
            "tls_ms": (f or {}).get("tls_ms"),
            "resent": (f or {}).get("resent", 0),
            "dup_ack": (f or {}).get("dup_ack", 0),
            "age": round(now - f["first"], 1) if f else None,
            "idle": round(now - f["last"], 1) if f else None,
            "closed": False,
        }

    for s in sockets:
        tcp_listen = s["state"] == "LISTEN"
        if s["raddr"]:
            # Connected: the tuple identifies it, but it may have been seen on
            # more than one adapter, and each of those is its own row.
            keys = [k for k in by_endpoint.get((s["proto"], s["raddr"], s["rport"]), [])
                    if (s["laddr"], s["lport"]) in key_endpoints(k)]
            if not keys:
                open_rows.append(row_for(s, None, False))
            for k in keys:
                matched.add(k)
                open_rows.append(row_for(s, k, False))
            continue

        if tcp_listen:
            listening.append(row_for(s, None, True))
            continue

        # Unconnected — almost always UDP. Find every conversation that used
        # this local end. A wildcard bind (0.0.0.0) has no address to match on,
        # so fall back to the port, which is what attribution keys on too.
        if s["laddr"] in WILDCARD:
            keys = list(by_port.get((s["proto"], s["lport"]), []))
        else:
            keys = list(by_endpoint.get((s["proto"], s["laddr"], s["lport"]), []))
        keys = [k for k in keys if k not in matched]
        if not keys:
            listening.append(row_for(s, None, True))
            continue
        for k in keys:
            matched.add(k)
            open_rows.append(row_for(s, k, False))

    closed = []
    for key, f in table.items():
        if key in matched:
            continue
        if now - f["last"] > RECENT_CLOSED:
            continue
        proto, _iface, a_ip, a_port, b_ip, b_port = key
        # The endpoint with the well-known port is almost always the remote
        # one; failing that, the higher port is ours.
        if a_port < b_port:
            l_ip, l_port, r_ip, r_port = b_ip, b_port, a_ip, a_port
        else:
            l_ip, l_port, r_ip, r_port = a_ip, a_port, b_ip, b_port
        closed.append({
            "proto": proto, "state": "closed", "pid": f.get("pid"),
            "process": f.get("process") or "-",
            "laddr": l_ip, "lport": l_port, "raddr": r_ip, "rport": r_port,
            "iface": f.get("iface", ""),
            "rhost": f.get("rhost") or host_for_ip(r_ip),
            "in": f["in"], "out": f["out"], "packets": f["packets"],
            "spark": spark_series(f, now),
            "rtt": f.get("rtt"), "tls_ms": f.get("tls_ms"),
            "resent": f.get("resent", 0), "dup_ack": f.get("dup_ack", 0),
            "age": round(now - f["first"], 1),
            "idle": round(now - f["last"], 1),
            "closed": True,
        })

    # A listening row that never matched a flow has no bytes; keep them in a
    # stable order rather than an arbitrary one.
    busiest = lambda r: -(r["in"] + r["out"])
    open_rows.sort(key=busiest)
    closed.sort(key=lambda r: r["idle"])
    listening.sort(key=lambda r: (r["proto"], r["lport"]))
    return open_rows, listening, closed
