#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetScope - a local packet monitor with a web dashboard.

Captures live network traffic on this machine and serves a browser dashboard
on 127.0.0.1 showing every packet: which process, where it went, the decoded
protocol, and the raw bytes in hex.

This is a diagnostic tool for your own machine. It requires administrator
rights and the Npcap driver (the same one Wireshark uses).

Usage:
    NetScope.exe                       # auto-pick interface, open browser
    NetScope.exe --iface "Wi-Fi"       # capture on a named interface
    NetScope.exe --filter "port 443"   # start with a BPF filter
    NetScope.exe --port 8477           # change the dashboard port
    NetScope.exe --demo                # fake traffic, no admin/Npcap needed
    NetScope.exe --list                # list interfaces and exit
    NetScope.exe --no-extract          # capture only, don't rebuild files
    NetScope.exe --read capture.pcap   # analyse a saved capture offline
    NetScope.exe --toasts              # desktop notifications for alerts
    NetScope.exe --tray                # run in the notification area
    NetScope.exe --install-task        # start in the tray at logon (elevated)
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import queue
import random
import re
import secrets
import socket
import struct
import sys
import threading
import time
import webbrowser
from collections import deque, defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.21.1"

# How many packets to keep in the live ring buffer.
RING_SIZE = 20000
# How many bytes of each packet to retain for the hex view.
SNAPLEN = 2048
# How often the adapter list may be re-read from the OS.
IFACE_REFRESH = 4.0
# How often a running all-interfaces capture looks for adapters that appeared.
IFACE_WATCH = 8.0
# How often to refresh the port -> process mapping (seconds).
PROC_REFRESH = 1.0
# Keep a closed socket's port -> process mapping this long, so short-lived
# connections stay attributable after they disappear from the socket table.
PROC_RETAIN = 120.0
# Shortest gap between socket-table refreshes forced by an unattributed packet.
MISS_REFRESH_MIN = 0.4

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Optional imports. We degrade gracefully so --demo works anywhere.
# ---------------------------------------------------------------------------

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from netscope_smb import SmbTracker
from netscope_ftp import FTPCorrelator
from netscope_dhcp import DhcpTracker, summarise as dhcp_summary
from netscope_streams import (StreamTracker, ObjectStore, ObjectScanner,
                              TEXTUAL)
from netscope_pcap import write_pcap, read_pcap
from netscope_quic import (parse_quic, summarise as quic_summary,
                           sni_from_client_hello, build_client_initial,
                           build_split_client_initials, InitialReassembler,
                           CRYPTO_OK as QUIC_CRYPTO_OK)
from netscope_alerts import AlertEngine, DesktopNotifier, RULE_WHY
from netscope_conn import FlowTable, SocketTable, build_view
from netscope_l2 import (describe_icmp, describe_frame, mac_label,
                         owner_label, parse_ra, UNOWNED)
from netscope_nbns import parse as parse_nbns, summarise as nbns_summary
from netscope_history import (HistoryStore, default_db_path,
                              load_settings, save_setting)
import netscope_tray as tray

SCAPY_ERROR = None
try:
    from scapy.config import conf as scapy_conf

    scapy_conf.verb = 0
    from scapy.sendrecv import AsyncSniffer
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw

    SCAPY_OK = True
except Exception as exc:  # pragma: no cover
    SCAPY_OK = False
    SCAPY_ERROR = str(exc)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    """True if we have the privileges packet capture needs."""
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _icmp6_type(pkt):
    """(type, code) for an ICMPv6 packet, or None. Scapy splits ICMPv6 across
    a family of layer classes, so go by the IPv6 next-header instead."""
    try:
        ip6 = pkt.getlayer(IPv6)
        if ip6 is None or int(ip6.nh) != 58:
            return None
        body = bytes(ip6.payload)
        if len(body) < 2:
            return None
        return int(body[0]), int(body[1])
    except Exception:
        return None


def dname(raw) -> str:
    """Decode a DNS/SNI hostname.

    The idna codec chokes on the trailing root dot scapy leaves on qnames
    (it reads as an empty label), so strip it before decoding and fall back
    to a lenient decode for anything idna rejects.
    """
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw.rstrip(".")
    raw = raw.rstrip(b".")
    try:
        return raw.decode("idna")
    except Exception:
        return raw.decode("utf-8", "replace")


_UNSAFE_NAME = re.compile(r'[\x00-\x1f\x7f"\\/:*?<>|]')


def pcap_stats_for(sock):
    """
    (received, buffer_dropped, iface_dropped) straight from the capture
    driver, or None when this socket cannot report it.

    This is the number that says whether anything else in the app can be
    trusted. A Python capture path cannot keep up with a busy link, libpcap's
    kernel buffer overflows, and the driver discards frames silently — byte
    totals, the attribution percentage, the connection table and any alert
    whose packet went missing are all quietly wrong, with nothing on screen
    saying so.

    scapy exposes no stats method of its own, but it bundles the libpcap
    bindings and its socket keeps the raw handle, so the counter is one call
    away. Verified against a real capture: with nothing draining the buffer,
    102,882 packets seen and 102,672 reported dropped.
    """
    handle = getattr(getattr(sock, "pcap_fd", None), "pcap", None)
    if handle is None:
        return None            # a raw AF_PACKET socket, or no socket at all
    try:
        from ctypes import byref
        from scapy.libs.winpcapy import pcap_stats, pcap_stat
    except Exception:
        return None            # no libpcap on this machine; nothing to report
    try:
        st = pcap_stat()
        if pcap_stats(handle, byref(st)) != 0:
            return None
        return int(st.ps_recv), int(st.ps_drop), int(st.ps_ifdrop)
    except Exception:
        return None


def safe_filename(name: str, fallback: str = "netscope-object") -> str:
    """
    Make a wire-supplied name safe to put in a Content-Disposition header and
    to hand a browser as a filename.

    Rebuilt files are named by whatever the server on the other end said, which
    is not a name this machine chose. A double quote or a CR/LF ends the header
    early and lets the rest be written by someone else; a path separator aims
    the save somewhere other than the download folder. Strip both, along with
    the characters Windows will not accept in a filename at all.
    """
    name = _UNSAFE_NAME.sub("_", (name or "").strip())
    name = name.lstrip(".") or fallback          # no leading dots, no empties
    return name[:120]


def safe_ascii(data: bytes, limit: int = 160) -> str:
    out = []
    for b in data[:limit]:
        out.append(chr(b) if 32 <= b < 127 else ".")
    return "".join(out)


# ---------------------------------------------------------------------------
# Protocol decoders
# ---------------------------------------------------------------------------

TLS_RECORD_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
    b"PATCH ", b"TRACE ", b"CONNECT ", b"HTTP/1.",
)


# The ClientHello parser lives in netscope_quic — QUIC needs the full version
# to read the hostname out of a decrypted Initial, and there is no reason to
# keep two copies of it.
_sni_from_client_hello = sni_from_client_hello


def decode_tls(payload: bytes):
    """Recognise a TLS record and, for a ClientHello, extract the hostname."""
    if len(payload) < 6:
        return None
    rtype = payload[0]
    if rtype not in TLS_RECORD_TYPES:
        return None
    ver = struct.unpack("!H", payload[1:3])[0]
    if ver >> 8 != 0x03:
        return None
    rec_len = struct.unpack("!H", payload[3:5])[0]
    info = {
        "record": TLS_RECORD_TYPES[rtype],
        "version": TLS_VERSIONS.get(ver, f"0x{ver:04x}"),
        "length": rec_len,
    }
    if rtype == 0x16:
        hs = payload[5:]
        if hs:
            htype = hs[0]
            info["handshake"] = {
                0x01: "ClientHello",
                0x02: "ServerHello",
                0x0B: "Certificate",
                0x0C: "ServerKeyExchange",
                0x0E: "ServerHelloDone",
                0x10: "ClientKeyExchange",
                0x14: "Finished",
            }.get(htype, f"Type {htype}")
            if htype == 0x01:
                sni = _sni_from_client_hello(hs)
                if sni:
                    info["sni"] = sni
    return info


def decode_http(payload: bytes):
    """Parse a plaintext HTTP request or response head."""
    if not payload.startswith(HTTP_METHODS):
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1", "replace")
        headers = {}
        for line in lines[1:24]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("latin-1", "replace").strip()] = \
                    v.decode("latin-1", "replace").strip()
        return {"start_line": first, "headers": headers}
    except Exception:
        return None


def decode_dns(dns):
    """
    Summarise a scapy DNS layer into queries and answers.

    Takes the DNS object itself rather than a packet, so it works both for
    real DNS (pkt[DNS], scapy's own dissection off port 53) and for mDNS/
    LLMNR, which share DNS's exact wire format but arrive on ports 5353 and
    5355 that scapy does not bind DNS to -- those are decoded by handing this
    a DNS() built directly from the raw payload instead.
    """
    if dns is None:
        return None
    out = {"id": int(dns.id), "response": bool(dns.qr), "queries": [], "answers": []}
    try:
        if dns.qd:
            recs = dns.qd if isinstance(dns.qd, (list, tuple)) else [dns.qd]
            for q in recs:
                try:
                    qtype = q.get_field("qtype").i2repr(q, q.qtype)
                except Exception:
                    qtype = str(getattr(q, "qtype", "?"))
                out["queries"].append({"name": dname(getattr(q, "qname", b"")),
                                       "type": qtype})
    except Exception:
        pass
    try:
        for i in range(int(dns.ancount or 0)):
            rr = dns.an[i]
            data = rr.rdata
            if isinstance(data, bytes):
                data = dname(data)
            try:
                rtype = rr.get_field("type").i2repr(rr, rr.type)
            except Exception:
                rtype = str(getattr(rr, "type", "?"))
            out["answers"].append({
                "name": dname(getattr(rr, "rrname", b"")),
                "type": rtype,
                "data": str(data),
            })
    except Exception:
        pass
    return out


def _dns_info(d):
    """The packet-list info line for a decode_dns() result -- shared by real
    DNS, mDNS and LLMNR so all three read the same way."""
    if d["response"]:
        names = ", ".join(a["data"] for a in d["answers"][:3]) or "no answer"
        q = d["queries"][0]["name"] if d["queries"] else ""
        return f"response  {q} → {names}"
    q = d["queries"][0] if d["queries"] else {"name": "?", "type": "?"}
    return f"query  {q['type']}  {q['name']}"


# ---------------------------------------------------------------------------
# Process attribution: map a local port back to the program that owns it
# ---------------------------------------------------------------------------


class ProcessResolver:
    """Maintains a (port, proto) -> process-name map, refreshed in the background."""

    def __init__(self):
        self._map = {}
        self._seen_at = {}
        self._names = {}
        self._last_forced = 0.0
        self._local_ips = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.available = psutil is not None
        self.refresh()

    def start(self):
        if self._thread or not self.available:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="proc-resolver")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(PROC_REFRESH):
            try:
                self.refresh()
            except Exception:
                pass

    def refresh(self):
        if not self.available:
            return
        now = time.time()
        seen = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.laddr or not c.pid:
                    continue
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                seen[(c.laddr.port, proto)] = c.pid
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception:
            pass

        # Merge into the existing map and age out stale entries rather than
        # replacing wholesale — a socket that closed a second ago should still
        # name its owner for the packets we already captured.
        with self._lock:
            new_map = dict(self._map)
        for k, pid in seen.items():
            new_map[k] = pid
        for k in seen:
            self._seen_at[k] = now
        for k, t in list(self._seen_at.items()):
            if now - t > PROC_RETAIN:
                self._seen_at.pop(k, None)
                new_map.pop(k, None)

        ips = set()
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(a.address.split("%")[0])
        except Exception:
            pass

        with self._lock:
            self._map = new_map
            if ips:
                self._local_ips = ips

    def note_miss(self):
        """
        A packet we could not attribute — refresh the socket table now.

        Short-lived connections open and close inside a poll interval and so
        never appear in any snapshot. Refreshing on demand catches many of
        them while they are still open. Rate-limited, because enumerating
        every socket is not cheap and a burst of unattributable broadcast
        traffic must not turn into a refresh storm.
        """
        now = time.time()
        if now - self._last_forced < MISS_REFRESH_MIN:
            return False
        self._last_forced = now
        try:
            self.refresh()
            return True
        except Exception:
            return False

    def name_for_pid(self, pid: int) -> str:
        if pid in self._names:
            return self._names[pid]
        name = f"pid {pid}"
        try:
            name = psutil.Process(pid).name()
        except Exception:
            pass
        self._names[pid] = name
        return name

    def lookup(self, sport, dport, proto, src, dst):
        """Return (process_name, pid, direction) for a packet."""
        with self._lock:
            local_ips = self._local_ips
            pmap = self._map

        outbound = src in local_ips if local_ips else None
        if outbound is None:
            outbound = (sport, proto) in pmap

        local_port = sport if outbound else dport
        pid = pmap.get((local_port, proto))
        if pid is None:
            # Fall back to the other side; some sockets only register one way.
            pid = pmap.get((dport if outbound else sport, proto))
        name = self.name_for_pid(pid) if pid else "-"
        return name, pid, ("out" if outbound else "in")

    @property
    def local_ips(self):
        with self._lock:
            return set(self._local_ips)


# ---------------------------------------------------------------------------
# Packet store: ring buffer plus rolling statistics
# ---------------------------------------------------------------------------


class PacketStore:
    def __init__(self, size: int = RING_SIZE):
        self._lock = threading.Lock()
        self._ring = deque(maxlen=size)
        self._raw = {}
        self._seq = 0
        self.started_at = time.time()
        self.by_process = defaultdict(lambda: {"in": 0, "out": 0, "packets": 0})
        self.by_host = defaultdict(lambda: {"in": 0, "out": 0, "packets": 0})
        self.by_proto = defaultdict(int)
        self.total_in = 0
        self.total_out = 0
        self.total_packets = 0
        self.unowned = 0
        self.dns_cache = {}
        self._buckets = deque(maxlen=90)  # one second each
        self._cur_bucket = None
        # Per-conversation counters for the Connections tab. Fed from add(),
        # which is the one choke point every record passes through — live
        # capture, demo, an imported pcap and --read all land here.
        self.flows = FlowTable()

    def add(self, rec: dict, raw: bytes):
        with self._lock:
            self._seq += 1
            rec["seq"] = self._seq
            oldest = self._ring[0]["seq"] if self._ring else None
            self._ring.append(rec)
            if raw:
                self._raw[self._seq] = raw[:SNAPLEN]
            # Drop raw bytes for packets that fell out of the ring.
            if oldest is not None and len(self._ring) == self._ring.maxlen:
                self._raw.pop(oldest, None)

            size = rec["length"]
            direction = rec["dir"]
            self.total_packets += 1
            if direction == "out":
                self.total_out += size
            else:
                self.total_in += size

            p = self.by_process[rec["process"]]
            p[direction] += size
            p["packets"] += 1

            peer = rec["remote"]
            h = self.by_host[peer]
            h[direction] += size
            h["packets"] += 1

            self.by_proto[rec["proto"]] += 1
            try:
                self.flows.observe(rec)
            except Exception:
                pass                    # accounting must never drop a packet
            if rec["process"] in UNOWNED:
                self.unowned += 1

            sec = int(rec["ts"])
            if self._cur_bucket is None or self._cur_bucket["t"] != sec:
                self._cur_bucket = {"t": sec, "in": 0, "out": 0}
                self._buckets.append(self._cur_bucket)
            self._cur_bucket[direction] += size
            return rec["seq"]

    def note_host(self, ip, name):
        """Record a hostname learned from something other than DNS (QUIC SNI)."""
        if ip and name:
            with self._lock:
                self.dns_cache.setdefault(ip, name)

    def note_dns(self, answers):
        with self._lock:
            for a in answers:
                if a["type"] in ("A", "AAAA") and a["data"]:
                    self.dns_cache[a["data"]] = a["name"]

    def hostname(self, ip: str):
        return self.dns_cache.get(ip)

    def since(self, seq: int, limit: int = 600):  # noqa: D401
        with self._lock:
            out = [r for r in self._ring if r["seq"] > seq]
        if len(out) > limit:
            out = out[-limit:]
        return out

    def export_records(self):
        """(timestamp, bytes, wire_length, link_layer) for every buffered packet."""
        with self._lock:
            out = []
            for r in self._ring:
                raw = self._raw.get(r["seq"])
                if raw:
                    out.append((r["ts"], raw, r["length"], r.get("l2", "eth")))
            return out

    def get_raw(self, seq: int):
        with self._lock:
            return self._raw.get(seq)

    def get_record(self, seq: int):
        with self._lock:
            for r in reversed(self._ring):
                if r["seq"] == seq:
                    return r
        return None

    def stats(self):
        with self._lock:
            procs = sorted(
                ({"name": k, **v} for k, v in self.by_process.items()),
                key=lambda d: d["in"] + d["out"], reverse=True)[:12]
            hosts = sorted(
                ({"host": k, "name": self.dns_cache.get(k, ""), **v}
                 for k, v in self.by_host.items()),
                key=lambda d: d["in"] + d["out"], reverse=True)[:12]
            buckets = list(self._buckets)[-60:]
            return {
                "total_in": self.total_in,
                "total_out": self.total_out,
                "total_packets": self.total_packets,
                "attributed": self.total_packets - self.unowned,
                "attribution_pct": (round(100.0 * (self.total_packets - self.unowned)
                                          / self.total_packets, 1)
                                    if self.total_packets else 0.0),
                "elapsed": time.time() - self.started_at,
                "processes": procs,
                "hosts": hosts,
                "protocols": dict(sorted(self.by_proto.items(),
                                         key=lambda kv: -kv[1])),
                "timeline": buckets,
            }

    def clear(self):
        with self._lock:
            self._ring.clear()
            self._raw.clear()
            self.by_process.clear()
            self.by_host.clear()
            self.by_proto.clear()
            self.total_in = self.total_out = self.total_packets = 0
            self.unowned = 0
            self._buckets.clear()
            self._cur_bucket = None
            self.started_at = time.time()


class ReverseResolver:
    """
    Best-effort, opt-in reverse DNS for IPs nothing on the wire has already
    named.

    Unlike every other naming source in this app (DNS, DHCP, mDNS/LLMNR/
    NBNS, TLS/QUIC SNI), this one sends queries out rather than just
    listening -- so it defaults off, and a caller only reaches it at all
    once passive naming has already failed for that IP.

    Runs in a small pool of daemon threads so a slow or unresponsive
    resolver never blocks packet processing; a result lands through the
    same store.note_host() every other naming source uses, so nothing
    downstream needs to know it came from here. Failures are negative-
    cached, since a lot of the public internet has no PTR record at all and
    a busy capture would otherwise re-query the same dead address forever.
    """
    WORKERS = 4
    MAX_QUEUED = 200
    NEGATIVE_TTL = 600          # seconds before a failed lookup is retried
    # A tray instance can run for days. This is a safety net against a
    # runaway capture, not a budget meant to be hit in ordinary use -- 20,000
    # distinct external IPs is far beyond what even a very busy machine sees
    # in a day, but the cap still exists so nothing grows completely
    # unbounded if it somehow is.
    MAX_ATTEMPTS = 20000

    def __init__(self, store: PacketStore, enabled: bool = False):
        self.store = store
        self.enabled = enabled
        self._queue = queue.Queue(maxsize=self.MAX_QUEUED)
        self._queued = set()        # ips currently queued or being resolved
        self._negative = {}         # ip -> retry-not-before timestamp
        self._attempts = 0
        self._resolved = 0
        self._lock = threading.Lock()
        self._settings_sink = None

    def start(self):
        for _ in range(self.WORKERS):
            threading.Thread(target=self._worker, daemon=True,
                             name="rdns").start()

    def request(self, ip: str):
        """Queue ip for a background reverse lookup. Cheap to call on every
        packet that lacks a name -- most calls bail out immediately."""
        if not self.enabled or not ip:
            return
        with self._lock:
            if ip in self._queued or self._attempts >= self.MAX_ATTEMPTS:
                return
            if self._negative.get(ip, 0) > time.time():
                return
            if self.store.hostname(ip):
                return
            self._queued.add(ip)
            self._attempts += 1
        try:
            self._queue.put_nowait(ip)
        except queue.Full:
            with self._lock:
                self._queued.discard(ip)

    def _worker(self):
        while True:
            self._resolve_one(self._queue.get())

    def _resolve_one(self, ip):
        """The blocking part, split out from _worker() so it can be tested
        without a real thread or a real DNS server."""
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.store.note_host(ip, name)
            with self._lock:
                self._resolved += 1
        except Exception:
            with self._lock:
                self._negative[ip] = time.time() + self.NEGATIVE_TTL
        finally:
            with self._lock:
                self._queued.discard(ip)

    def stats(self):
        """For the Alerts panel, so 'nothing is getting labeled' is
        answerable by looking rather than by asking -- attempted vs.
        resolved, and whether the run-long safety cap has been reached."""
        with self._lock:
            return {
                "attempted": self._attempts,
                "resolved": self._resolved,
                "pending": len(self._queued),
                "cap_reached": self._attempts >= self.MAX_ATTEMPTS,
            }

    # -- persistence, same shape as AlertEngine's -----------------------

    def attach_settings(self, load, save):
        self._settings_sink = save
        try:
            stored = load() or {}
        except Exception:
            return
        if "reverse_dns" in stored:
            self.enabled = bool(stored["reverse_dns"])

    def set_enabled(self, on: bool):
        self.enabled = bool(on)
        if self._settings_sink is not None:
            try:
                self._settings_sink("reverse_dns", self.enabled)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Capture engine
# ---------------------------------------------------------------------------


class CaptureEngine:
    _ifaces_read = 0.0          # last OS re-read, shared across instances
    def __init__(self, store: PacketStore, resolver: ProcessResolver,
                 streams: StreamTracker = None, alerts: AlertEngine = None,
                 history: HistoryStore = None, dhcp: DhcpTracker = None,
                 reverse: ReverseResolver = None):
        self.store = store
        self.resolver = resolver
        self.streams = streams
        self.alerts = alerts
        self.history = history
        self.smb = SmbTracker()
        self.ftp = FTPCorrelator()
        self.quic = InitialReassembler()
        self.dhcp = dhcp or DhcpTracker()
        self.reverse = reverse
        self.sniffer = None
        self.sniffers = []          # [(iface_name, AsyncSniffer, socket_or_None)]
        self.stress_us = 0          # --stress-drops: microseconds per packet
        self.new_ifaces = []        # adapters attached after the capture began
        self._watch_stop = threading.Event()
        self._watcher = None
        self.ifaces = []
        self.spec = "default"
        self.iface = None
        self.bpf = ""
        self.running = False
        self.error = None
        self._lock = threading.Lock()

    # -- interface discovery -------------------------------------------------

    @staticmethod
    def refresh_interfaces(force=False):
        """
        Re-read the adapter list from the operating system.

        scapy enumerates once when it is imported and caches the result in
        conf.ifaces forever. Started from a logon task, NetScope is usually
        running before Wi-Fi has associated and before a VPN's adapter exists,
        so those adapters stayed invisible no matter how many times the
        dashboard was refreshed — the page was asking the server, and the
        server was re-reading a snapshot taken at boot. Only restarting the
        whole app, which re-imported scapy, ever fixed it.

        Rate-limited because this queries the OS, and the dropdown asks on
        every poll.
        """
        if not SCAPY_OK:
            return
        now = time.time()
        if not force and now - CaptureEngine._ifaces_read < IFACE_REFRESH:
            return
        CaptureEngine._ifaces_read = now
        try:
            from scapy.config import conf
            conf.ifaces.reload()
        except Exception:
            pass

    @staticmethod
    def interfaces(refresh=True):
        if not SCAPY_OK:
            return []
        if refresh:
            CaptureEngine.refresh_interfaces()
        out = []
        try:
            from scapy.interfaces import get_working_ifaces
            for i in get_working_ifaces():
                out.append({
                    "name": getattr(i, "name", str(i)),
                    "description": getattr(i, "description", "") or getattr(i, "name", ""),
                    "ip": getattr(i, "ip", "") or "",
                    "mac": getattr(i, "mac", "") or "",
                })
        except Exception:
            try:
                from scapy.config import conf
                for n in conf.ifaces.data:
                    out.append({"name": str(n), "description": str(n), "ip": "", "mac": ""})
            except Exception:
                pass
        return out

    @staticmethod
    def default_iface():
        try:
            from scapy.config import conf
            return getattr(conf.iface, "name", str(conf.iface))
        except Exception:
            return None

    # -- lifecycle -----------------------------------------------------------

    @staticmethod
    def resolve_ifaces(spec):
        """
        Turn an --iface value into a list of interface names.

        Accepts a single name, a comma-separated list, or "all" for every
        adapter that currently has an address. Loopback is only included when
        asked for by name — on a normal machine it is pure noise.
        """
        names = [i["name"] for i in CaptureEngine.interfaces()]
        if not spec or spec == "default":
            # Watching everything is the sane default: picking one adapter and
            # hoping it is the busy one is how you end up staring at an empty
            # capture while the traffic goes past on the other NIC.
            spec = "all"
        if spec == "auto":
            d = CaptureEngine.default_iface()
            return [d] if d else names[:1]
        if spec == "all":
            usable = [i for i in CaptureEngine.interfaces()
                      if i.get("ip") and not i["ip"].startswith("127.")]
            return [i["name"] for i in usable] or names
        wanted = [s.strip() for s in spec.split(",") if s.strip()]
        # Be forgiving about description-vs-name, since the dropdown shows
        # descriptions and people copy those.
        out = []
        for w in wanted:
            if w in names:
                out.append(w)
                continue
            match = next((i["name"] for i in CaptureEngine.interfaces()
                          if w.lower() in (i.get("description") or "").lower()), None)
            out.append(match or w)
        return out

    def start(self, iface=None, bpf=""):
        with self._lock:
            if self.running:
                self.stop_locked()
            if not SCAPY_OK:
                self.error = f"Scapy unavailable: {SCAPY_ERROR}"
                return False

            self.spec = iface or "default"
            self.ifaces = self.resolve_ifaces(self.spec)
            self.iface = ", ".join(self.ifaces) if self.ifaces else None
            self.bpf = bpf or ""
            self.error = None

            # Validate the BPF expression up front. A bad filter otherwise
            # kills the sniffer's own thread after start() has already
            # returned, which looks exactly like "no traffic" to the user.
            if self.bpf:
                try:
                    from scapy.arch.common import compile_filter
                    compile_filter(self.bpf, iface=self.ifaces[0] if self.ifaces else None)
                except Exception as exc:
                    self.error = f"filter {self.bpf!r} rejected — {exc}"
                    self.running = False
                    return False

            # One sniffer per adapter. Each callback closes over its own
            # interface name so every packet knows where it was seen —
            # otherwise a multi-adapter capture is an unreadable mix.
            self.sniffers = []
            failures = []
            for name in (self.ifaces or [None]):
                # Open the socket here rather than letting AsyncSniffer do it.
                # The sniffer keeps its sockets local to its own run loop, so
                # a socket it opened is unreachable afterwards — and the
                # capture-drop counter lives on that socket's pcap handle.
                # If opening fails for any reason we hand the job back to the
                # sniffer and simply have no statistics, rather than not
                # capturing.
                try:
                    self.sniffers.append(self._open_sniffer(name))
                except Exception as exc:
                    failures.append(f"{name}: {exc}")

            if not self.sniffers:
                self.error = "; ".join(failures) or "no interface could be opened"
                self.running = False
                return False
            if failures:
                # Partial success is worth saying out loud rather than
                # quietly capturing less than the user asked for.
                self.error = "some interfaces failed — " + "; ".join(failures)
            self.sniffer = self.sniffers[0][1]
            self._stats_base = None
            self.new_ifaces = []
            # Watch for adapters that turn up later. Cheap: it sleeps between
            # checks and only acts when the set has actually changed.
            self._watch_stop.clear()
            if self._watcher is None or not self._watcher.is_alive():
                self._watcher = threading.Thread(target=self._watch_ifaces,
                                                 daemon=True, name="iface-watch")
                self._watcher.start()
            self.running = True
            threading.Timer(0.8, self._check_alive).start()
            return True

    def _open_sniffer(self, name):
        """
        Start capturing one adapter. Returns (name, sniffer, socket_or_None).

        The socket is opened here rather than by AsyncSniffer because the
        sniffer keeps its own sockets local to its run loop, and the capture's
        drop counter lives on that socket's pcap handle. If opening fails we
        hand the job back to the sniffer and simply have no statistics for that
        adapter, rather than not capturing it.
        """
        kwargs = {"prn": self._packet_handler(name), "store": False}
        sock = None
        try:
            from scapy.config import conf as _conf
            sock = _conf.L2listen(iface=name, filter=self.bpf or None)
            kwargs["opened_socket"] = sock
        except Exception:
            sock = None
            if name:
                kwargs["iface"] = name
            if self.bpf:
                kwargs["filter"] = self.bpf
        try:
            s = AsyncSniffer(**kwargs)
            s.start()
            return (name, s, sock)
        except Exception:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            raise

    def _watch_ifaces(self):
        """
        Pick up adapters that appear after the capture has started.

        Only when the user asked for everything: if they named specific
        adapters, attaching one they did not ask for would be wrong. Wi-Fi
        associating a minute after logon, a VPN connecting, a phone tethering
        — all of these used to be invisible for the life of the process,
        because the adapter set was resolved once at start and never revisited.
        """
        while not self._watch_stop.wait(IFACE_WATCH):
            if not self.running or self.spec not in ("all", "default", None, ""):
                continue
            try:
                self.refresh_interfaces(force=True)
                wanted = self.resolve_ifaces(self.spec)
            except Exception:
                continue
            with self._lock:
                if not self.running:
                    continue
                have = {n for n, _s, _k in self.sniffers}
                # Reap adapters whose capture thread has died — an adapter
                # that went away takes its sniffer with it.
                alive = []
                gone = []
                for entry in self.sniffers:
                    t = getattr(entry[1], "thread", None)
                    if t is not None and not t.is_alive():
                        gone.append(entry)
                    else:
                        alive.append(entry)
                if gone:
                    self.sniffers = alive
                    have = {n for n, _s, _k in alive}
                    threading.Thread(target=self._close_sockets, args=(gone,),
                                     daemon=True, name="pcap-close").start()
                added = []
                for name in wanted:
                    if name in have:
                        continue
                    try:
                        self.sniffers.append(self._open_sniffer(name))
                        added.append(name)
                    except Exception:
                        pass            # it may not be ready yet; try again later
                if added or gone:
                    self.ifaces = [n for n, _s, _k in self.sniffers]
                    self.iface = ", ".join(self.ifaces) if self.ifaces else None
                    self.new_ifaces = added

    def capture_stats(self):
        """
        What the driver received and had to discard, across every adapter.

        Returns None when no socket can report it — an offline capture, demo
        mode, or a raw AF_PACKET fallback — so the dashboard can stay silent
        rather than claim zero drops it has not actually verified.
        """
        recv = drop = ifdrop = 0
        answered = False
        # Under the lock: stop() frees these handles, and reading one after it
        # has been closed is a segfault rather than an exception.
        with self._lock:
            entries = list(getattr(self, "sniffers", []))
        for entry in entries:
            sock = entry[2] if len(entry) > 2 else None
            if sock is None:
                continue
            got = pcap_stats_for(sock)
            if got is None:
                continue
            answered = True
            recv += got[0]
            drop += got[1]
            ifdrop += got[2]
        if not answered:
            return None
        lost = drop + ifdrop
        total = recv + lost
        return {
            "received": recv,
            "dropped": lost,
            "buffer_dropped": drop,
            "iface_dropped": ifdrop,
            # Share of what reached the driver that it could not hand over.
            "loss_pct": round(lost * 100.0 / total, 2) if total else 0.0,
        }

    def _check_alive(self):
        if not self.running:
            return
        dead = [n for n, s, _sock in self.sniffers
                if getattr(s, "thread", None) is not None
                and not s.thread.is_alive()]
        if dead and len(dead) == len(self.sniffers):
            self.running = False
            self.error = (f"capture stopped on {', '.join(map(str, dead))} — "
                          "check the interface and that Npcap is installed")
        elif dead:
            self.error = f"capture stopped on {', '.join(map(str, dead))}"

    def stop_locked(self):
        self._watch_stop.set()
        entries = list(getattr(self, "sniffers", []))
        # Drop the references before anything is closed: capture_stats() must
        # not be able to reach a handle that is about to be freed.
        self.sniffers = []
        self.sniffer = None
        self.running = False
        for entry in entries:
            try:
                entry[1].stop(join=False)
            except Exception:
                pass
        if any((e[2] if len(e) > 2 else None) is not None for e in entries):
            threading.Thread(target=self._close_sockets, args=(entries,),
                             daemon=True, name="pcap-close").start()

    @staticmethod
    def _close_sockets(entries):
        """
        Close capture sockets only once their sniffer thread has let go.

        A socket passed to AsyncSniffer with opened_socket= is ours to close;
        the sniffer will not do it. But closing a pcap handle while that
        thread is still blocked reading it frees memory out from under a
        running thread, and the process segfaults — there is no exception to
        catch. AsyncSniffer used to own these sockets and closed them after
        its own thread had exited; taking ownership to reach the drop counter
        means taking on that ordering too. Joining happens off the caller's
        thread so stopping the capture stays responsive.
        """
        for entry in entries:
            s = entry[1]
            sock = entry[2] if len(entry) > 2 else None
            t = getattr(s, "thread", None)
            if t is not None:
                try:
                    t.join(timeout=3.0)
                except Exception:
                    pass
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def stop(self):
        with self._lock:
            self.stop_locked()

    # -- the hot path --------------------------------------------------------

    def _packet_handler(self, iface_name):
        """A prn bound to one adapter, so the packet carries its origin."""
        def handler(pkt):
            # --stress-drops slows this deliberately. Drops only happen when
            # the handler cannot drain libpcap's buffer in time, which on a
            # quiet link never occurs — so without a way to stall on purpose
            # the alarm is unverifiable on the machine that needs it.
            if self.stress_us:
                time.sleep(self.stress_us / 1e6)
            self._on_packet(pkt, iface_name)
        return handler

    def _on_packet(self, pkt, iface_name=None):
        try:
            rec, raw, payload = self._build(pkt)
            if rec:
                rec["iface"] = iface_name or (self.ifaces[0] if self.ifaces else "")
                self.store.add(rec, raw)
                if self.alerts is not None:
                    self.alerts.inspect(rec, payload)
                if self.history is not None:
                    self.history.record(rec)
        except Exception:
            pass

    def ingest_file(self, packets):
        """Feed packets read from a .pcap through the same decoding path."""
        count = 0
        for pkt in packets:
            self._on_packet(pkt)
            count += 1
        return count

    def close_streams(self):
        """After an offline load, let the scanner see the streams immediately."""
        for st in self.streams.dirty_streams() if self.streams else []:
            st.closed = True

    def _build(self, pkt):
        ts = float(getattr(pkt, "time", time.time()))
        length = len(pkt)
        try:
            raw_bytes = bytes(pkt)
        except Exception:
            raw_bytes = b""
        src = dst = ""
        sport = dport = None
        proto = "OTHER"
        info = ""
        decoded = {}

        if IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            ipver = 4
            ttl = ip.ttl
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            src, dst = ip.src, ip.dst
            ipver = 6
            ttl = ip.hlim
        elif ARP in pkt:
            a = pkt[ARP]
            src, dst = a.psrc, a.pdst
            proto = "ARP"
            info = f"who-has {a.pdst} tell {a.psrc}" if a.op == 1 else f"{a.psrc} is-at {a.hwsrc}"
            ipver, ttl = 4, None
            decoded["arp"] = {"op": int(a.op), "sender_ip": a.psrc,
                              "sender_mac": a.hwsrc, "target_ip": a.pdst}
        else:
            # Not IP, IPv6 or ARP. These used to show as OTHER with '?' for
            # both addresses; now they get named and carry real MACs.
            ipver, ttl = None, None
            described = describe_frame(pkt, raw_bytes)
            if described:
                proto, info, src, dst = described
                decoded["l2"] = {"src_mac": mac_label(src), "dst_mac": mac_label(dst),
                                 "summary": info}
            else:
                eth = pkt.getlayer(Ether)
                src = getattr(eth, "src", "?") if eth else "?"
                dst = getattr(eth, "dst", "?") if eth else "?"

        payload = b""
        transport = None
        flags = ""
        tcp_seq = None

        if TCP in pkt:
            t = pkt[TCP]
            sport, dport = int(t.sport), int(t.dport)
            proto = "TCP"
            transport = "tcp"
            flags = str(t.flags)
            tcp_seq = int(t.seq)
            decoded["tcp"] = {
                "flags": flags, "seq": int(t.seq), "ack": int(t.ack),
                "window": int(t.window),
            }
            info = f"{sport} → {dport} [{flags}] win={t.window}"
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        elif UDP in pkt:
            u = pkt[UDP]
            sport, dport = int(u.sport), int(u.dport)
            proto = "UDP"
            transport = "udp"
            info = f"{sport} → {dport} len={u.len}"
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        elif ICMP in pkt:
            ic = pkt[ICMP]
            proto = "ICMP"
            info = describe_icmp(int(ic.type), int(ic.code))
            decoded["icmp"] = {"type": int(ic.type), "code": int(ic.code),
                               "meaning": info}
        elif ipver == 6 and _icmp6_type(pkt) is not None:
            t6, c6 = _icmp6_type(pkt)
            proto = "ICMPv6"
            info = describe_icmp(t6, c6, v6=True)
            decoded["icmp"] = {"type": t6, "code": c6, "meaning": info,
                               "version": 6}
            if t6 == 134:
                ra = parse_ra(bytes(pkt[IPv6].payload))
                if ra:
                    ra["router"] = src
                    decoded["ra"] = ra
        elif ipver == 4 and getattr(pkt.getlayer(IP), "proto", None) == 2:
            proto = "IGMP"
            info = "Multicast group management"

        # Application-layer decoding
        hint = ""
        host_hint = ""
        ftp_meta = None
        if payload:
            self.ftp.sweep(ts)
            if 21 in (sport, dport):
                self.ftp.observe_control(src, sport, dst, dport, payload,
                                         dport == 21, ts)
                proto = "FTP"
                hint = "FTP"
                info = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:200]
            if not hint:
                ftp_meta = self.ftp.match_data(src, sport, dst, dport)
                if ftp_meta:
                    proto = "FTP-DATA"
                    hint = "FTP-DATA"
                    info = f"FTP data: {ftp_meta['name']}"
            if not hint and 445 in (sport, dport):
                smb = self.smb.parse(payload)
                if smb:
                    proto = "SMB2" if smb["messages"][0].get("dialect") != "SMB1" else "SMB"
                    decoded["smb"] = smb
                    info = smb["summary"]
                    hint = "SMB"
            if not hint and transport == "udp" and ({67, 68} & {sport, dport}):
                d = self.dhcp.observe(payload, ts)
                if d:
                    proto = "DHCP"
                    hint = "DHCP"
                    decoded["dhcp"] = d
                    info = dhcp_summary(d)
                    # A DISCOVER/REQUEST names the client machine before it has
                    # sent a single other packet — worth remembering against
                    # the address DHCP is about to hand it, the same way a TLS
                    # SNI or a DNS answer teaches the store a hostname.
                    lease_ip = d.get("your_ip") or d.get("requested_ip")
                    if d.get("hostname") and lease_ip:
                        self.store.note_host(lease_ip, d["hostname"])
                    if d["msg_type"] == "ACK" and self.history is not None:
                        lease = self.dhcp.latest(d["mac"])
                        if lease:
                            self.history.record_dhcp_lease(lease)
            if not hint and transport == "udp" and 137 in (sport, dport):
                nb = parse_nbns(payload)
                if nb:
                    proto = "NBNS"
                    hint = "NBNS"
                    decoded["nbns"] = nb
                    info = nbns_summary(nb)
                    # Only a registration/refresh (a host claiming a name for
                    # itself) or a positive query response (an explicit
                    # name -> address answer) says whose name this is. A
                    # plain broadcast query does not, and parse_nbns() leaves
                    # that judgment to us rather than guessing.
                    if nb["ips"] and (nb["opcode"] in ("registration", "refresh")
                                     or (nb["opcode"] == "query" and nb["response"])):
                        for ip in nb["ips"]:
                            self.store.note_host(ip, nb["name"])
            if not hint:
                tls = decode_tls(payload)
                if tls:
                    proto = "TLS"
                    hint = "TLS"
                    decoded["tls"] = tls
                    bits = [tls["record"], tls.get("version", "")]
                    if tls.get("handshake"):
                        bits.append(tls["handshake"])
                    if tls.get("sni"):
                        bits.append(f"→ {tls['sni']}")
                        host_hint = tls["sni"]
                    info = "  ".join(b for b in bits if b)
                else:
                    http = decode_http(payload)
                    if http:
                        proto = "HTTP"
                        hint = "HTTP"
                        decoded["http"] = http
                        host_hint = http["headers"].get("Host", "")
                        info = http["start_line"] + (
                            f"   [{host_hint}]" if host_hint else "")

            # QUIC rides on UDP and carries a recoverable hostname in its
            # Initial packet — without this, HTTP/3 traffic is just "UDP 443".
            if not hint and transport == "udp":
                qinfo = parse_quic(payload, sport, dport, reassembler=self.quic)
                if qinfo:
                    proto = "QUIC"
                    hint = "QUIC"
                    decoded["quic"] = qinfo
                    info = quic_summary(qinfo)
                    if qinfo.get("sni"):
                        host_hint = qinfo["sni"]

        if DNS in pkt:
            d = decode_dns(pkt[DNS])
            if d:
                proto = "DNS"
                decoded["dns"] = d
                info = _dns_info(d)
                if d["response"]:
                    self.store.note_dns(d["answers"])
        elif payload and transport == "udp" and ({5353, 5355} & {sport, dport}):
            # mDNS and LLMNR are DNS-message-format-compatible, just on ports
            # scapy doesn't bind the DNS layer to -- build one from the raw
            # bytes instead of relying on scapy's own dissection.
            try:
                d = decode_dns(DNS(payload))
            except Exception:
                d = None
            if d and (d["queries"] or d["answers"]):
                proto = "MDNS" if 5353 in (sport, dport) else "LLMNR"
                decoded["dns"] = d
                info = _dns_info(d)
                if d["response"]:
                    self.store.note_dns(d["answers"])

        pname, pid, direction = self.resolver.lookup(
            sport, dport, transport or "tcp", src, dst)

        if pname == "-":
            # Nudge the socket table: a connection that opened and closed
            # between polls is often still alive right now, and this is much
            # cheaper than polling continuously.
            if transport and self.resolver.note_miss():
                pname, pid, direction = self.resolver.lookup(
                    sport, dport, transport, src, dst)
        if pname == "-":
            dmac = (decoded.get("l2") or {}).get("dst_mac", "") or \
                (pkt.getlayer(Ether).dst if pkt.getlayer(Ether) else "")
            pname = owner_label(proto, dmac, dst or "")

        remote = dst if direction == "out" else src

        rhost = self.store.hostname(remote) or ""
        if not rhost and host_hint and direction == "out":
            rhost = host_hint
            self.store.note_host(remote, host_hint)
        if not rhost and self.reverse is not None:
            self.reverse.request(remote)

        # Hand TCP segments to the reassembler so a connection can later be
        # read as one conversation and its files rebuilt.
        stream_id = None
        if self.streams is not None and transport == "tcp" and tcp_seq is not None:
            try:
                stream_id = self.streams.observe(
                    src, sport, dst, dport, tcp_seq, payload, ts, pname,
                    flags=flags, hint=hint, host=host_hint, ftp_meta=ftp_meta)
            except Exception:
                pass

        rec = {
            "ts": ts,
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
            "src": src, "dst": dst,
            "sport": sport, "dport": dport,
            "proto": proto,
            "length": length,
            "process": pname,
            "pid": pid,
            "dir": direction,
            "remote": remote,
            "rhost": rhost,
            "info": info,
            "ipver": ipver,
            "ttl": ttl,
            "payload_len": len(payload),
            "stream": stream_id,
            # The transport, as distinct from "proto" above, which is the
            # application protocol the decoders identified. The connection
            # table keys on this, since DNS may be either.
            "transport": transport,
            # Which link layer this frame actually has. A tunnel adapter can
            # hand up bare IP with no Ethernet header, and a .pcap file carries
            # exactly one link type for the whole file — so the exporter has to
            # know rather than assume.
            "l2": "eth" if Ether in pkt else "raw",
            "iface": "",
            "decoded": decoded,
        }
        return rec, bytes(pkt), payload


# ---------------------------------------------------------------------------
# Demo engine: synthetic traffic so the UI works without Npcap or admin
# ---------------------------------------------------------------------------


class DemoEngine:
    HOSTS = [
        ("142.250.80.46", "www.google.com", "chrome.exe"),
        ("104.18.32.7", "api.wpengine.com", "php.exe"),
        ("13.107.42.14", "outlook.office365.com", "olk.exe"),
        ("151.101.1.140", "cdn.jsdelivr.net", "chrome.exe"),
        ("52.96.165.146", "teams.microsoft.com", "ms-teams.exe"),
        ("192.168.1.1", "router.lan", "System"),
        ("140.82.114.4", "github.com", "Code.exe"),
    ]

    LOCAL = "192.168.1.20"
    MAC_LOCAL = "aa:bb:cc:00:11:22"
    MAC_GW = "aa:bb:cc:99:88:77"

    @classmethod
    def frame(cls, src, sport, dst, dport, payload, proto="tcp", seq=0,
              outbound=True, ttl=64):
        """
        Build a real Ethernet/IP/TCP-or-UDP frame around a demo payload.

        Without this the demo's stored bytes are bare payloads, which makes an
        exported .pcap unreadable in Wireshark and unimportable back into
        NetScope. Building genuine frames keeps demo mode honest.
        """
        if not SCAPY_OK:
            return payload
        try:
            eth = Ether(src=cls.MAC_LOCAL if outbound else cls.MAC_GW,
                        dst=cls.MAC_GW if outbound else cls.MAC_LOCAL)
            ip = IP(src=src, dst=dst, ttl=ttl)
            if proto == "udp":
                layer = UDP(sport=sport, dport=dport)
            else:
                layer = TCP(sport=sport, dport=dport, seq=seq, flags="PA")
            pkt = eth / ip / layer
            if payload:
                pkt = pkt / Raw(load=payload)
            return bytes(pkt)
        except Exception:
            return payload

    def __init__(self, store: PacketStore, resolver=None, streams=None,
                 alerts: AlertEngine = None, history: HistoryStore = None,
                 dhcp: DhcpTracker = None):
        self.store = store
        self.streams = streams
        self.alerts = alerts
        self.history = history
        self.smb = SmbTracker()
        self.quic = InitialReassembler()
        self.dhcp = dhcp or DhcpTracker()
        self.running = False
        self.error = None
        self.iface = "demo0"
        self.ifaces = ["demo0"]
        self.spec = "demo0"
        self.bpf = ""
        self._stop = threading.Event()
        self._thread = None
        self._seeded = False
        # Conversations the demo currently considers open, so the Connections
        # tab has something coherent to show: (sport, dport, ip) ->
        # (opened, closed_or_None, process).
        self._conns = {}
        self._sock_lock = threading.Lock()
        self._live = 0                   # conversations currently playing out

    @staticmethod
    def interfaces(refresh=True):
        return [{"name": "demo0", "description": "Synthetic demo traffic",
                 "ip": "192.168.1.20", "mac": "00:11:22:33:44:55"}]

    @staticmethod
    def resolve_ifaces(spec):
        return ["demo0"]

    @staticmethod
    def default_iface():
        return "demo0"

    def start(self, iface=None, bpf=""):
        if self.running:
            return True
        self.ifaces = ["demo0"]
        self.spec = "demo0"
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="demo")
        self._thread.start()
        self.running = True
        return True

    def stop(self):
        self._stop.set()
        self.running = False

    # -- synthetic file-transfer traffic ------------------------------------
    #
    # These build genuine HTTP and SMB2 bytes and push them through the same
    # reassembler and decoders the live capture uses, so the Streams and Files
    # tabs show real output rather than mocked-up rows.

    DEMO_PDF = (b"%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
                b"trailer<</Root 1 0 R>>\n%%EOF\n")

    DEMO_PNG = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAWklEQVR42u3QMQEAAAgDoJvc"
        "6BFPBqQ5tQwLCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
        "CAgICAgICAgICAgICAgICPwPfAG0mwGB1i5A5wAAAABJRU5ErkJggg==")

    def _http_exchanges(self):
        """(request, response) byte pairs for one keep-alive connection."""
        host = b"files.example.com"

        def resp(status, ctype, body, extra=b""):
            return (b"HTTP/1.1 " + status + b"\r\n"
                    b"Server: nginx\r\nContent-Type: " + ctype + b"\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    + extra + b"Connection: keep-alive\r\n\r\n" + body)

        pdf = self.DEMO_PDF * 6
        png = self.DEMO_PNG
        js = json.dumps({"orders": [{"id": 1041, "total": "182.40"},
                                    {"id": 1042, "total": "76.10"}]},
                        indent=1).encode()
        xlsx = b"PK\x03\x04" + os.urandom(2200)
        boundary = b"----NetScopeDemoBoundary"
        upload = (b"--" + boundary + b"\r\n"
                  b'Content-Disposition: form-data; name="file"; '
                  b'filename="expenses-august.xlsx"\r\n'
                  b"Content-Type: application/vnd.openxmlformats-officedocument."
                  b"spreadsheetml.sheet\r\n\r\n" + xlsx + b"\r\n--" + boundary + b"--\r\n")

        return [
            (b"GET /reports/q3-invoice.pdf HTTP/1.1\r\nHost: " + host +
             b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
             resp(b"200 OK", b"application/pdf", pdf,
                  b'Content-Disposition: attachment; filename="q3-invoice.pdf"\r\n')),

            (b"GET /assets/logo.png HTTP/1.1\r\nHost: " + host +
             b"\r\nReferer: http://files.example.com/reports/\r\n\r\n",
             resp(b"200 OK", b"image/png", png)),

            (b"GET /api/orders.json HTTP/1.1\r\nHost: " + host +
             b"\r\nAccept: application/json\r\n\r\n",
             resp(b"200 OK", b"application/json", js)),

            (b"POST /upload HTTP/1.1\r\nHost: " + host +
             b"\r\nContent-Type: multipart/form-data; boundary=" + boundary +
             b"\r\nContent-Length: " + str(len(upload)).encode() + b"\r\n\r\n" + upload,
             resp(b"201 Created", b"text/plain", b"stored\n")),
        ]

    def _emit_tcp(self, data, outbound, server_ip, server_port, cport, proc,
                  host, hint, seqs):
        """Chop a byte blob into MSS-sized segments and push them through."""
        MSS = 1400
        d = 0 if outbound else 1
        for i in range(0, max(len(data), 1), MSS):
            chunk = data[i:i + MSS]
            if not chunk:
                break
            seq = seqs[d]
            seqs[d] += len(chunk)
            now = time.time()
            sid = None
            if self.streams is not None:
                src, sport = ((self.LOCAL, cport) if outbound
                              else (server_ip, server_port))
                dst, dport = ((server_ip, server_port) if outbound
                              else (self.LOCAL, cport))
                sid = self.streams.observe(src, sport, dst, dport, seq, chunk,
                                           now, proc, flags="PA", hint=hint,
                                           host=host)
            head = chunk[:80]
            decoded = {}
            if hint == "HTTP" and (head.startswith(b"GET") or head.startswith(b"POST")
                                   or head.startswith(b"HTTP/1.")):
                proto = "HTTP"
                info = head.split(b"\r\n")[0].decode("latin-1", "replace")
                http = decode_http(chunk)
                if http:
                    decoded["http"] = http
            elif hint == "SMB":
                proto = "SMB2"
                parsed = self.smb.parse(chunk)
                info = parsed["summary"] if parsed else "SMB2"
                if parsed:
                    decoded["smb"] = parsed
            elif hint == "FTP":
                proto = "FTP"
                info = chunk.decode("latin-1", "replace").strip()
            else:
                proto = "TCP"
                info = f"{'→' if outbound else '←'} {len(chunk)} bytes of payload"
            rec = {
                "ts": now,
                "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
                "src": self.LOCAL if outbound else server_ip,
                "dst": server_ip if outbound else self.LOCAL,
                "sport": cport if outbound else server_port,
                "dport": server_port if outbound else cport,
                "proto": proto, "length": len(chunk) + 66,
                "process": proc, "pid": abs(hash(proc)) % 9000 + 1000,
                "dir": "out" if outbound else "in",
                "remote": server_ip, "rhost": host,
                "info": info, "ipver": 4, "ttl": 64 if outbound else 117,
                "payload_len": len(chunk), "stream": sid, "iface": "demo0",
                "transport": "tcp",
                "decoded": decoded,
            }
            raw = self.frame(rec["src"], rec["sport"], rec["dst"], rec["dport"],
                             chunk, "tcp", seq, outbound, rec["ttl"])
            rec["length"] = len(raw)
            self.store.add(rec, raw)
            if self.alerts is not None:
                self.alerts.inspect(rec, chunk)
            if self.history is not None:
                self.history.record(rec)
            self._stop.wait(0.004)

    def _seed_http(self):
        seqs = [1000, 5000]
        cport = random.randint(49152, 65535)
        for req, resp in self._http_exchanges():
            self._emit_tcp(req, True, "203.0.113.24", 80, cport, "chrome.exe",
                           "files.example.com", "HTTP", seqs)
            self._emit_tcp(resp, False, "203.0.113.24", 80, cport, "chrome.exe",
                           "files.example.com", "HTTP", seqs)

    # -- SMB2 frame construction -------------------------------------------

    @staticmethod
    def _smb_hdr(cmd, msgid, tree, session, response=False):
        h = bytearray(64)
        h[0:4] = b"\xfeSMB"
        struct.pack_into("<H", h, 4, 64)
        struct.pack_into("<H", h, 6, 1)
        struct.pack_into("<H", h, 12, cmd)
        struct.pack_into("<H", h, 14, 1)
        struct.pack_into("<I", h, 16, 1 if response else 0)
        struct.pack_into("<Q", h, 24, msgid)
        struct.pack_into("<I", h, 36, tree)
        struct.pack_into("<Q", h, 40, session)
        return h

    @staticmethod
    def _nbss(smb: bytes):
        return b"\x00" + len(smb).to_bytes(3, "big") + smb

    def _smb_frames(self):
        """A realistic little file-share session, as genuine SMB2 bytes."""
        SESSION, TREE = 0x4A7F00000011, 0x21
        fid = os.urandom(16)
        share = "\\\\NAS\\Media".encode("utf-16-le")
        fname = "vacation-2026.mp4".encode("utf-16-le")
        out = []

        # TREE_CONNECT
        body = bytearray(8)
        struct.pack_into("<H", body, 0, 9)
        struct.pack_into("<H", body, 4, 72)
        struct.pack_into("<H", body, 6, len(share))
        out.append((self._smb_hdr(3, 1, 0, SESSION) + body + share, True))
        r = bytearray(16)
        struct.pack_into("<H", r, 0, 16)
        out.append((self._smb_hdr(3, 1, TREE, SESSION, True) + r, False))

        # CREATE (open for read)
        body = bytearray(56)
        struct.pack_into("<H", body, 0, 57)
        struct.pack_into("<I", body, 24, 0x00000001)      # FILE_READ_DATA
        struct.pack_into("<I", body, 36, 1)               # open
        struct.pack_into("<H", body, 44, 120)
        struct.pack_into("<H", body, 46, len(fname))
        out.append((self._smb_hdr(5, 2, TREE, SESSION) + body + fname, True))
        r = bytearray(88)
        struct.pack_into("<H", r, 0, 89)
        struct.pack_into("<Q", r, 48, 4_284_119_552)      # EndOfFile
        r[64:80] = fid
        out.append((self._smb_hdr(5, 2, TREE, SESSION, True) + r, False))

        # READ x2
        for i, off in enumerate((0, 65536)):
            body = bytearray(48)
            struct.pack_into("<H", body, 0, 49)
            struct.pack_into("<I", body, 4, 65536)
            struct.pack_into("<Q", body, 8, off)
            body[16:32] = fid
            out.append((self._smb_hdr(8, 3 + i, TREE, SESSION) + body, True))
            r = bytearray(16)
            struct.pack_into("<H", r, 0, 17)
            struct.pack_into("<I", r, 4, 65536)
            out.append((self._smb_hdr(8, 3 + i, TREE, SESSION, True) + r, False))

        # WRITE a document back to the share
        doc = "taxes-2025.pdf".encode("utf-16-le")
        body = bytearray(56)
        struct.pack_into("<H", body, 0, 57)
        struct.pack_into("<I", body, 24, 0x00000002)      # FILE_WRITE_DATA
        struct.pack_into("<I", body, 36, 5)               # overwrite-or-create
        struct.pack_into("<H", body, 44, 120)
        struct.pack_into("<H", body, 46, len(doc))
        out.append((self._smb_hdr(5, 5, TREE, SESSION) + body + doc, True))
        fid2 = os.urandom(16)
        r = bytearray(88)
        struct.pack_into("<H", r, 0, 89)
        r[64:80] = fid2
        out.append((self._smb_hdr(5, 5, TREE, SESSION, True) + r, False))
        body = bytearray(48)
        struct.pack_into("<H", body, 0, 49)
        struct.pack_into("<I", body, 4, 284_119)
        body[16:32] = fid2
        out.append((self._smb_hdr(9, 6, TREE, SESSION) + body, True))

        # CLOSE
        body = bytearray(24)
        struct.pack_into("<H", body, 0, 24)
        body[8:24] = fid
        out.append((self._smb_hdr(6, 7, TREE, SESSION) + body, True))

        return [(self._nbss(bytes(s)), o) for s, o in out]

    def _seed_smb(self):
        seqs = [7000, 9000]
        cport = random.randint(49152, 65535)
        for frame, outbound in self._smb_frames():
            self._emit_tcp(frame, outbound, "192.168.1.10", 445, cport,
                           "explorer.exe", "nas.lan", "SMB", seqs)

    # -- QUIC ---------------------------------------------------------------

    def _emit_udp(self, payload, outbound, server_ip, server_port, cport, proc,
                  host):
        now = time.time()
        qinfo = parse_quic(payload, cport if outbound else server_port,
                           server_port if outbound else cport,
                           reassembler=self.quic)
        proto = "QUIC" if qinfo else "UDP"
        info = quic_summary(qinfo) if qinfo else f"{len(payload)} bytes"
        rec = {
            "ts": now,
            "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "src": self.LOCAL if outbound else server_ip,
            "dst": server_ip if outbound else self.LOCAL,
            "sport": cport if outbound else server_port,
            "dport": server_port if outbound else cport,
            "proto": proto, "length": len(payload) + 42,
            "process": proc, "pid": abs(hash(proc)) % 9000 + 1000,
            "dir": "out" if outbound else "in",
            "remote": server_ip,
            "rhost": (qinfo or {}).get("sni", "") or host,
            "info": info, "ipver": 4, "ttl": 64 if outbound else 117,
            "payload_len": len(payload), "stream": None, "iface": "demo0",
            "transport": "udp",
            "decoded": {"quic": qinfo} if qinfo else {},
        }
        raw = self.frame(rec["src"], rec["sport"], rec["dst"], rec["dport"],
                         payload, "udp", 0, outbound, rec["ttl"])
        rec["length"] = len(raw)
        self.store.add(rec, raw)
        if self.alerts is not None:
            self.alerts.inspect(rec, payload)
        if self.history is not None:
            self.history.record(rec)
        self._stop.wait(0.01)

    def _seed_quic(self):
        """Real, decryptable QUIC Initials plus follow-up 1-RTT traffic."""
        sessions = [
            ("142.250.80.46", "www.youtube.com", "chrome.exe", ("h3",)),
            ("104.18.32.7", "cdn.jsdelivr.net", "chrome.exe", ("h3", "h3-29")),
            ("52.96.165.146", "teams.microsoft.com", "ms-teams.exe", ("h3",)),
        ]
        for i, (ip, host, proc, alpn) in enumerate(sessions):
            cport = random.randint(49152, 65535)
            dcid, scid = os.urandom(8), os.urandom(8)
            # Alternate between a small ClientHello and an oversized one split
            # across packets, which is what a real browser sends.
            if i % 2:
                pkts = [build_client_initial(dcid, scid, host, alpn)]
            else:
                pkts = build_split_client_initials(dcid, scid, host, alpn,
                                                   size=2600)
            for pkt in pkts:
                if pkt:
                    self._emit_udp(pkt, True, ip, 443, cport, proc, host)
            # Server response and a few 1-RTT application packets.
            for _ in range(random.randint(2, 5)):
                short = bytes([0x40 | random.randint(0, 0x1F)]) + dcid + \
                    os.urandom(random.randint(80, 1100))
                self._emit_udp(short, random.random() < 0.4, ip, 443, cport,
                               proc, host)

    # -- DHCP -----------------------------------------------------------

    @staticmethod
    def _dhcp_opt(tag, value):
        return bytes([tag, len(value)]) + value

    @classmethod
    def _dhcp_packet(cls, op, msg_type, xid, mac, yiaddr=b"\x00\x00\x00\x00",
                     siaddr=b"\x00\x00\x00\x00", options=b""):
        pkt = bytearray(240)
        pkt[0] = op                 # 1 = request, 2 = reply
        pkt[1] = 1                  # htype: Ethernet
        pkt[2] = 6                  # hlen
        struct.pack_into("!I", pkt, 4, xid)
        pkt[16:20] = yiaddr
        pkt[20:24] = siaddr
        pkt[28:28 + len(mac)] = mac
        pkt[236:240] = b"\x63\x82\x53\x63"
        return bytes(pkt) + cls._dhcp_opt(53, bytes([msg_type])) + options + b"\xff"

    def _emit_dhcp(self, payload, outbound, src, dst, sport, dport):
        """One synthetic BOOTP/DHCP message, decoded the same way a real one
        would be so the tracker, the alert rule and the lease table all see
        genuine correlated state rather than a canned record."""
        now = time.time()
        d = self.dhcp.observe(payload, now)
        info = dhcp_summary(d) if d else ""
        rec = {
            "ts": now,
            "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": "DHCP", "length": len(payload) + 42,
            "process": "System", "pid": 4,
            "dir": "out" if outbound else "in",
            "remote": dst if outbound else src, "rhost": "",
            "info": info, "ipver": 4, "ttl": 64 if outbound else 255,
            "payload_len": len(payload), "stream": None, "iface": "demo0",
            "transport": "udp",
            "decoded": {"dhcp": d} if d else {},
        }
        raw = self.frame(src, sport, dst, dport, payload, "udp", 0, outbound,
                         rec["ttl"])
        rec["length"] = len(raw)
        self.store.add(rec, raw)
        if self.alerts is not None:
            self.alerts.inspect(rec, payload)
        if self.history is not None:
            self.history.record(rec)
            if d and d.get("msg_type") == "ACK":
                lease = self.dhcp.latest(d["mac"])
                if lease:
                    self.history.record_dhcp_lease(lease)

    def _seed_dhcp(self):
        """A realistic DISCOVER/OFFER/REQUEST/ACK, as genuine DHCP bytes —
        the one exchange that names a machine before it sends anything else,
        and the one an unexpected second server would answer instead."""
        mac = bytes(int(x, 16) for x in "aa:bb:cc:11:22:33".split(":"))
        xid = random.randint(0, 2**32 - 1)
        hostname = self._dhcp_opt(12, b"robs-laptop")
        client_ip = bytes([192, 168, 1, 77])
        server_ip = bytes([192, 168, 1, 1])
        lease = self._dhcp_opt(51, struct.pack("!I", 86400))
        server_id = self._dhcp_opt(54, server_ip)
        subnet = self._dhcp_opt(1, bytes([255, 255, 255, 0]))
        router = self._dhcp_opt(3, server_ip)
        dns = self._dhcp_opt(6, server_ip)

        discover = self._dhcp_packet(1, 1, xid, mac,
                                     options=hostname + self._dhcp_opt(60, b"MSFT 5.0"))
        offer = self._dhcp_packet(2, 2, xid, mac, yiaddr=client_ip, siaddr=server_ip,
                                  options=server_id + lease + subnet + router + dns)
        request = self._dhcp_packet(1, 3, xid, mac,
                                    options=hostname + self._dhcp_opt(50, client_ip) + server_id)
        ack = self._dhcp_packet(2, 5, xid, mac, yiaddr=client_ip, siaddr=server_ip,
                                options=server_id + lease + subnet + router + dns)

        BCAST, SERVER = "255.255.255.255", "192.168.1.1"
        for payload, outbound in ((discover, True), (offer, False),
                                  (request, True), (ack, False)):
            if outbound:
                self._emit_dhcp(payload, True, self.LOCAL, BCAST, 68, 67)
            else:
                self._emit_dhcp(payload, False, SERVER, self.LOCAL, 67, 68)
            self._stop.wait(0.05)

    # -- mDNS / LLMNR / NBNS: device self-announcement, for host naming -----

    def _emit_dns_like(self, payload, outbound, src, dst, sport, dport, proto):
        """One synthetic mDNS or LLMNR message, decoded through the exact
        same decode_dns() path a real one would take."""
        now = time.time()
        try:
            d = decode_dns(DNS(payload))
        except Exception:
            d = None
        info = _dns_info(d) if d else ""
        rec = {
            "ts": now,
            "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": proto, "length": len(payload) + 42,
            "process": "System", "pid": 4,
            "dir": "out" if outbound else "in",
            "remote": dst if outbound else src, "rhost": "",
            "info": info, "ipver": 4, "ttl": 64 if outbound else 255,
            "payload_len": len(payload), "stream": None, "iface": "demo0",
            "transport": "udp",
            "decoded": {"dns": d} if d else {},
        }
        raw = self.frame(src, sport, dst, dport, payload, "udp", 0, outbound,
                         rec["ttl"])
        rec["length"] = len(raw)
        self.store.add(rec, raw)
        if self.alerts is not None:
            self.alerts.inspect(rec, payload)
        if self.history is not None:
            self.history.record(rec)
        if d and d["response"]:
            self.store.note_dns(d["answers"])

    def _seed_mdns(self):
        """A smart-home device announcing its own address over mDNS,
        unprompted — the everyday case this decoder exists for."""
        payload = bytes(DNS(qr=1, aa=1, qdcount=0, qd=None,
                            an=DNSRR(rrname="attic-sensor.local.", type="A",
                                     ttl=120, rdata="192.168.1.65")))
        self._emit_dns_like(payload, False, "192.168.1.65", "224.0.0.251",
                            5353, 5353, "MDNS")

    def _seed_llmnr(self):
        """A Windows machine answering an LLMNR name lookup for itself, the
        way name resolution falls back once DNS has nothing."""
        cport = random.randint(49152, 65535)
        query = bytes(DNS(rd=0, qd=DNSQR(qname="DESKTOP-7FQAK2.", qtype="A")))
        self._emit_dns_like(query, True, self.LOCAL, "224.0.0.252", cport,
                            5355, "LLMNR")
        response = bytes(DNS(qr=1, aa=1,
                             qd=DNSQR(qname="DESKTOP-7FQAK2.", qtype="A"),
                             an=DNSRR(rrname="DESKTOP-7FQAK2.", type="A",
                                      ttl=30, rdata="192.168.1.46")))
        self._emit_dns_like(response, False, "192.168.1.46", self.LOCAL,
                            5355, cport, "LLMNR")

    # -- NBNS -----------------------------------------------------------

    @staticmethod
    def _nbns_name(name, suffix):
        raw = name.encode("latin-1")[:15].ljust(15, b" ") + bytes([suffix])
        out = bytearray(32)
        for i, b in enumerate(raw):
            out[2 * i] = 0x41 + (b >> 4)
            out[2 * i + 1] = 0x41 + (b & 0xF)
        return bytes([0x20]) + bytes(out) + bytes([0])

    @classmethod
    def _nbns_packet(cls, opcode, response, name, suffix, ip):
        """A Name Registration Request: a host claiming a name for itself,
        the address given as a compressed pointer back to the question —
        the shape real Windows registration traffic actually takes."""
        flags = (0x8000 if response else 0) | ((opcode & 0xF) << 11)
        header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), flags,
                             1, 0, 0, 1)
        qname = cls._nbns_name(name, suffix) + struct.pack("!HH", 0x0020, 1)
        rdata = b"\x00\x00" + bytes(int(o) for o in ip.split("."))
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 0x0020, 1, 0, len(rdata)) + rdata
        return header + qname + rr

    def _emit_nbns(self, payload, outbound, src, dst, sport, dport):
        now = time.time()
        nb = parse_nbns(payload)
        info = nbns_summary(nb) if nb else ""
        rec = {
            "ts": now,
            "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": "NBNS", "length": len(payload) + 42,
            "process": "System", "pid": 4,
            "dir": "out" if outbound else "in",
            "remote": dst if outbound else src, "rhost": "",
            "info": info, "ipver": 4, "ttl": 64 if outbound else 128,
            "payload_len": len(payload), "stream": None, "iface": "demo0",
            "transport": "udp",
            "decoded": {"nbns": nb} if nb else {},
        }
        raw = self.frame(src, sport, dst, dport, payload, "udp", 0, outbound,
                         rec["ttl"])
        rec["length"] = len(raw)
        self.store.add(rec, raw)
        if self.alerts is not None:
            self.alerts.inspect(rec, payload)
        if self.history is not None:
            self.history.record(rec)
        if nb and nb["ips"] and (nb["opcode"] in ("registration", "refresh")
                                 or (nb["opcode"] == "query" and nb["response"])):
            for ip in nb["ips"]:
                self.store.note_host(ip, nb["name"])

    def _seed_nbns(self):
        """Another device on the network registering its NetBIOS name —
        the one NBNS shape unambiguous enough to attribute a hostname from."""
        payload = self._nbns_packet(5, False, "OFFICE-PRINTER", 0x00,
                                    "192.168.1.201")
        self._emit_nbns(payload, False, "192.168.1.201", "255.255.255.255",
                        137, 137)

    # -- deliberately insecure traffic, to exercise the alert rules ---------

    def _seed_insecure(self):
        seqs = [3000, 4000]
        cport = random.randint(49152, 65535)
        creds = base64.b64encode(b"admin:hunter2").decode()
        self._emit_tcp(
            ("GET /admin/status HTTP/1.1\r\nHost: printer.lan\r\n"
             f"Authorization: Basic {creds}\r\n"
             "User-Agent: Mozilla/5.0\r\n\r\n").encode(),
            True, "192.168.1.31", 80, cport, "chrome.exe", "printer.lan",
            "HTTP", seqs)
        self._emit_tcp(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Content-Length: 24\r\n\r\n<html>Printer ready</html>",
            False, "192.168.1.31", 80, cport, "chrome.exe", "printer.lan",
            "HTTP", seqs)

        seqs2 = [6000, 6500]
        cport2 = random.randint(49152, 65535)
        body = b"log=robert&pwd=CorrectHorse&wp-submit=Log+In"
        self._emit_tcp(
            b"POST /wp-login.php HTTP/1.1\r\nHost: staging.local\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
            True, "192.168.1.44", 80, cport2, "chrome.exe", "staging.local",
            "HTTP", seqs2)

        seqs3 = [8000, 8500]
        cport3 = random.randint(49152, 65535)
        for line, out in ((b"220 vsFTPd 3.0.5 ready\r\n", False),
                          (b"USER deploy\r\n", True),
                          (b"331 Please specify the password.\r\n", False),
                          (b"PASS s3cr3t-deploy\r\n", True),
                          (b"230 Login successful.\r\n", False)):
            self._emit_tcp(line, out, "203.0.113.77", 21, cport3, "ftp.exe",
                           "legacy-ftp.example.com", "FTP", seqs3)

    def sockets(self):
        """
        Synthetic sockets for the demo's own conversations.

        The Connections tab deliberately ignores this machine's real socket
        table in demo mode — pairing real sockets with invented traffic would
        invite conclusions about connections that do not exist. But that left
        the whole tab empty, so the demo makes up sockets for the conversations
        it made up. Fake sockets for fake flows is internally consistent; it is
        mixing the two that misleads.
        """
        now = time.time()
        out = []
        with self._sock_lock:
            for (sport, dport, ip), (opened, closed, proc) in list(self._conns.items()):
                if closed and now - closed > 8:
                    self._conns.pop((sport, dport, ip), None)
                    continue
                out.append({
                    "proto": "tcp",
                    "state": "TIME_WAIT" if closed else "ESTABLISHED",
                    "pid": abs(hash(proc)) % 9000 + 1000,
                    "laddr": self.LOCAL, "lport": sport,
                    "raddr": ip, "rport": dport,
                })
        # One listener, so that view is not empty either.
        out.append({"proto": "tcp", "state": "LISTEN", "pid": 4,
                    "laddr": "0.0.0.0", "lport": 445, "raddr": "", "rport": 0})
        return out

    def _demo_packet(self, ts, outbound, ip, host, proc, sport, dport,
                     proto, info, decoded, payload_len, transport="tcp"):
        """One synthetic packet, stored exactly as a captured one would be."""
        local = self.LOCAL
        src, dst = (local, ip) if outbound else (ip, local)
        body = os.urandom(max(0, min(payload_len, 1400)))
        rec = {
            "ts": ts,
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
            "src": src, "dst": dst,
            "sport": sport if outbound else dport,
            "dport": dport if outbound else sport,
            "proto": proto, "length": payload_len + 66,
            "process": proc, "pid": abs(hash(proc)) % 9000 + 1000,
            "dir": "out" if outbound else "in",
            "remote": ip, "rhost": host,
            "info": info, "ipver": 4, "ttl": 64 if outbound else 117,
            "payload_len": payload_len,
            "stream": None, "iface": "demo0",
            "transport": transport,
            "decoded": decoded,
        }
        raw = self.frame(src, rec["sport"], dst, rec["dport"], body,
                         transport, random.randint(0, 2**30), outbound,
                         rec["ttl"])
        rec["length"] = len(raw)
        self.store.add(rec, raw)
        if self.alerts is not None:
            self.alerts.inspect(rec, b"")
        if self.history is not None:
            self.history.record(rec)

    def _emit_conversation(self, ip, host, proc):
        """
        One coherent TCP connection, handshake and all.

        The rest of the demo emits independent packets with a fresh random port
        each time, which is fine for filling a packet list but means no two
        packets ever belong to the same conversation. Nothing that measures a
        connection — handshake RTT, TLS setup, retransmission — has anything to
        work on. This emits a real sequence instead, with a chosen round trip
        so the numbers on screen mean what they say, and with loss often enough
        to be worth looking at.
        """
        now = time.time()
        sport, dport = random.randint(49152, 65535), 443
        with self._sock_lock:
            self._conns[(sport, dport, ip)] = (now, None, proc)
        rtt = random.uniform(0.006, 0.180)
        cseq, sseq = random.randint(0, 2**30), random.randint(0, 2**30)
        tcp = lambda flags, seq, ack: {"tcp": {"flags": flags, "seq": seq,
                                               "ack": ack, "window": 64240}}
        P = lambda dt, out, proto, info, dec, plen: self._demo_packet(
            now + dt, out, ip, host, proc, sport, dport, proto, info, dec, plen)

        P(0, True, "TCP", f"{sport} → {dport} [S] win=64240",
          tcp("S", cseq, 0), 0)
        P(rtt, False, "TCP", f"{dport} → {sport} [SA] win=65535",
          tcp("SA", sseq, cseq + 1), 0)
        P(rtt + .001, True, "TCP", f"{sport} → {dport} [A] win=64240",
          tcp("A", cseq + 1, sseq + 1), 0)

        P(rtt + .002, True, "TLS", f"Handshake  TLS 1.3  ClientHello  → {host}",
          {"tls": {"record": "Handshake", "version": "TLS 1.3",
                   "handshake": "ClientHello", "sni": host, "length": 517},
           **tcp("PA", cseq + 1, sseq + 1)}, 517)
        P(2 * rtt + .002, False, "TLS", "Handshake  TLS 1.3  ServerHello",
          {"tls": {"record": "Handshake", "version": "TLS 1.3",
                   "handshake": "ServerHello", "length": 1300},
           **tcp("PA", sseq + 1, cseq + 518)}, 1300)
        P(2 * rtt + .012, False, "TLS", "ApplicationData  TLS 1.3  len=64",
          {"tls": {"record": "ApplicationData", "version": "TLS 1.3",
                   "length": 64}, **tcp("PA", sseq + 1301, cseq + 518)}, 64)

        # The data phase runs in real time rather than fabricated offsets. The
        # handshake above needs invented sub-second timing to produce an honest
        # RTT, but if the whole conversation is emitted in one tight loop then
        # every connection lives for a fraction of a second — the activity
        # sparkline is a single needle and the age column never leaves zero.
        # Spreading it over real seconds is what makes the demo represent the
        # Connections tab rather than just fill the packet list.
        cs, ss = cseq + 518, sseq + 1365
        Q = lambda out, proto, info, dec, plen: self._demo_packet(
            time.time(), out, ip, host, proc, sport, dport, proto, info, dec, plen)
        for i in range(random.randint(4, 14)):
            if self._stop.is_set():
                break
            plen = random.randint(200, 1400)
            Q(False, "TLS", f"ApplicationData  TLS 1.3  len={plen}",
              {"tls": {"record": "ApplicationData", "version": "TLS 1.3",
                       "length": plen}, **tcp("PA", ss, cs)}, plen)
            if random.random() < 0.07:      # occasional, not the norm
                Q(False, "TLS",
                  f"ApplicationData  TLS 1.3  len={plen}  [resent]",
                  {"tls": {"record": "ApplicationData", "version": "TLS 1.3",
                           "length": plen}, **tcp("PA", ss, cs)}, plen)
                for k in range(3):
                    Q(True, "TCP", f"{sport} → {dport} [A] win=64240 [dup]",
                      tcp("A", cs, ss), 0)
            ss += plen
            self._stop.wait(random.uniform(0.3, 1.6))

        Q(True, "TCP", f"{sport} → {dport} [FA] win=64240", tcp("FA", cs, ss), 0)
        with self._sock_lock:
            if (sport, dport, ip) in self._conns:
                opened, _closed, pr = self._conns[(sport, dport, ip)]
                self._conns[(sport, dport, ip)] = (opened, time.time(), pr)

    def _loop(self):
        local = self.LOCAL
        if not self._seeded:
            self._seeded = True
            for seed in (self._seed_http, self._seed_smb, self._seed_quic,
                         self._seed_dhcp, self._seed_mdns, self._seed_llmnr,
                         self._seed_nbns, self._seed_insecure):
                try:
                    seed()
                except Exception:
                    pass
        # A program that only shows up later, so the "new program on the
        # network" alert has something honest to fire on.
        late = [("198.51.100.9", "updates.vendor.example", "SilentUpdater.exe"),
                ("203.0.113.200", "telemetry.example.net", "CrashReporter.exe")]
        started = time.time()

        while not self._stop.is_set():
            if time.time() - started > 25 and random.random() < 0.03 and late:
                ip, host, proc = late.pop(0)
            else:
                ip, host, proc = random.choice(self.HOSTS)
            # Every so often, start a whole connection rather than emit a lone
            # packet. On its own thread: a conversation now runs in real time
            # over several seconds, and doing that inline would stall every
            # other kind of traffic while it played out.
            if random.random() < 0.2 and self._live < 6:
                self._live += 1
                def run(ip=ip, host=host, proc=proc):
                    try:
                        self._emit_conversation(ip, host, proc)
                    except Exception:
                        pass
                    finally:
                        self._live -= 1
                threading.Thread(target=run, daemon=True, name="demo-conv").start()

            outbound = random.random() < 0.45
            kind = random.choices(
                ["tls", "dns", "tcp", "http"], weights=[60, 12, 22, 6])[0]
            sport = random.randint(49152, 65535)
            now = time.time()

            if kind == "dns":
                proto, dport, info = "DNS", 53, (
                    f"query  A  {host}" if outbound
                    else f"response  {host} → {ip}")
                decoded = {"dns": {"id": random.randint(1, 65535),
                                   "response": not outbound,
                                   "queries": [{"name": host, "type": "A"}],
                                   "answers": ([] if outbound else
                                               [{"name": host, "type": "A", "data": ip}])}}
                length = random.randint(70, 190)
                if not outbound:
                    self.store.dns_cache[ip] = host
            elif kind == "http":
                proto, dport = "HTTP", 80
                info = f"GET /wp-json/wp/v2/posts HTTP/1.1   [{host}]"
                decoded = {"http": {"start_line": "GET /wp-json/wp/v2/posts HTTP/1.1",
                                    "headers": {"Host": host,
                                                "User-Agent": "Mozilla/5.0",
                                                "Accept": "application/json"}}}
                length = random.randint(300, 900)
            elif kind == "tls":
                proto, dport = "TLS", 443
                if random.random() < 0.12:
                    info = f"Handshake  TLS 1.3  ClientHello  → {host}"
                    decoded = {"tls": {"record": "Handshake", "version": "TLS 1.3",
                                       "handshake": "ClientHello", "sni": host,
                                       "length": 517}}
                    length = 583
                else:
                    length = random.randint(90, 1514)
                    info = f"ApplicationData  TLS 1.3  len={length - 66}"
                    decoded = {"tls": {"record": "ApplicationData",
                                       "version": "TLS 1.3", "length": length - 66}}
            else:
                proto, dport = "TCP", random.choice([443, 80, 22, 3306])
                flags = random.choice(["S", "SA", "A", "PA", "FA", "R"])
                info = f"{sport} → {dport} [{flags}] win=64240"
                decoded = {"tcp": {"flags": flags, "seq": random.randint(0, 2**31),
                                   "ack": random.randint(0, 2**31), "window": 64240}}
                length = random.randint(54, 120)

            src, dst = (local, ip) if outbound else (ip, local)
            rec = {
                "ts": now,
                "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
                "src": src, "dst": dst,
                "sport": sport if outbound else dport,
                "dport": dport if outbound else sport,
                "proto": proto, "length": length,
                "process": proc, "pid": abs(hash(proc)) % 9000 + 1000,
                "dir": "out" if outbound else "in",
                "remote": ip, "rhost": host,
                "info": info, "ipver": 4, "ttl": 64 if outbound else 117,
                "payload_len": max(0, length - 66),
                "stream": None, "iface": "demo0",
                "transport": "udp" if proto == "DNS" else "tcp",
                "decoded": decoded,
            }
            body = os.urandom(max(0, min(length - 66, 1400)))
            raw = self.frame(src, rec["sport"], dst, rec["dport"], body,
                             "udp" if proto == "DNS" else "tcp",
                             random.randint(0, 2**30), outbound, rec["ttl"])
            rec["length"] = len(raw)
            self.store.add(rec, raw)
            if self.alerts is not None:
                self.alerts.inspect(rec, b"")
            if self.history is not None:
                self.history.record(rec)
            self._stop.wait(random.uniform(0.02, 0.35))


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

from netscope_ui import PAGE_HTML  # noqa: E402


# Most a single /api/stream call will hand the browser, per direction.
STREAM_VIEW_CAP = 512 * 1024


class App:
    def __init__(self, store, engine, resolver, token, demo=False,
                 streams=None, objects=None, scanner=None, alerts=None,
                 decoder=None, history=None, dhcp=None, reverse=None):
        self.store = store
        self.engine = engine
        # Reads .pcap files. Same object as `engine` for a live capture; a
        # separate decoder in demo mode, which has no packet-building path.
        self.decoder = decoder or engine
        self.resolver = resolver
        self.token = token
        self.demo = demo
        self.streams = streams
        self.objects = objects
        self.scanner = scanner
        self.alerts = alerts
        self.history = history
        self.dhcp = dhcp
        self.reverse = reverse
        self.source = None          # set when a .pcap has been loaded
        # Enumerated on demand rather than on a timer: the socket table is
        # expensive, and nobody needs it unless the Connections tab is open.
        self.sockets = SocketTable()


class DashboardServer(ThreadingHTTPServer):
    """
    Refuses to share its port with another NetScope.

    HTTPServer sets SO_REUSEADDR by default, and on Windows that option lets
    a second process bind the very same port while the first is still
    listening — the OS does not error, it just leaves both sockets bound and
    routes new connections to whichever one bound first. A second launch (a
    logon-task instance already running, then someone double-clicking the
    tray icon again) would silently start a decoy: its own token, its own
    printed URL, and every request that URL's browser tab makes lands on the
    *other* process instead, which does not recognise that token — a "bad
    token" 403 with no clue that the real cause is a second copy running.
    SO_EXCLUSIVEADDRUSE is the Windows option that makes that conflict fail
    at startup, where it can be explained, instead of arriving later as an
    unexplained 403.
    """
    allow_reuse_address = False

    def server_bind(self):
        if os.name == "nt":
            try:
                self.socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_EXCLUSIVEADDRUSE, 1)
            except (AttributeError, OSError):
                pass
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    server_version = f"NetScope/{VERSION}"
    app: App = None

    def log_message(self, fmt, *args):
        pass  # keep the console clean

    # -- plumbing ------------------------------------------------------------

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]", "::1")

    def _authed(self, qs):
        given = (qs.get("t", [""])[0]
                 or self.headers.get("X-NetScope-Token", ""))
        return secrets.compare_digest(given, self.app.token)

    # -- routes --------------------------------------------------------------

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "localhost only"})
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            if not self._authed(qs):
                return self._send(403, "<h1>403</h1><p>This link's access token is "
                                       "missing or wrong — a bookmark or an old tab "
                                       "goes stale every time NetScope restarts, "
                                       "since a fresh token is generated each run. "
                                       "Open the URL printed in the console, or use "
                                       "the tray icon's <b>Open dashboard</b> — both "
                                       "always carry the current token.</p>",
                                  "text/html; charset=utf-8")
            return self._send(200, PAGE_HTML, "text/html; charset=utf-8")

        if not self._authed(qs):
            return self._send(403, {"error": "bad token"})

        if path == "/api/state":
            since = int(qs.get("since", ["0"])[0])
            packets = self.store_since(since)
            return self._send(200, {
                "packets": packets,
                "stats": self.app.store.stats(),
                "status": self.status(),
            })

        if path == "/api/packet":
            seq = int(qs.get("seq", ["0"])[0])
            rec = self.app.store.get_record(seq)
            raw = self.app.store.get_raw(seq)
            if rec is None:
                return self._send(404, {"error": "packet not in buffer"})
            return self._send(200, {
                "record": rec,
                "raw_b64": base64.b64encode(raw).decode() if raw else "",
                "raw_len": len(raw) if raw else 0,
            })

        if path == "/api/buffer":
            # The whole ring, minus the per-packet decode trees, so the
            # display filter can search everything captured rather than only
            # the rows the browser happens to be holding.
            drop = ("decoded",)
            rows = [{k: v for k, v in r.items() if k not in drop}
                    for r in self.app.store.since(0, limit=RING_SIZE)]
            return self._send(200, {"packets": rows, "count": len(rows)})

        if path == "/api/export.pcap":
            records = self.app.store.export_records()
            blob = write_pcap(records, snaplen=SNAPLEN)
            name = "netscope-%s.pcap" % datetime.now().strftime("%Y%m%d-%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
            self.end_headers()
            try:
                self.wfile.write(blob)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/api/history":
            h = self.app.history
            if h is None or not h.enabled:
                return self._send(200, {"enabled": False,
                                        "error": (h.error if h else "disabled")})
            days = max(1, min(365, int(qs.get("days", ["30"])[0])))
            return self._send(200, {
                "enabled": True,
                "summary": h.summary(),
                "daily": h.daily(days),
                "hourly": h.hourly(),
                "processes": h.by_process(days, 15),
                "hosts": h.top_hosts(15),
                "new_hosts": h.new_hosts(7, 20),
                "alerts": h.alert_history(days, 100),
                "sessions": h.sessions(10),
                "days": days,
            })

        if path == "/api/connections":
            store = self.app.store
            # The socket table only means something when the packets came off
            # this machine's own wire. Against a saved capture it belongs to a
            # different machine entirely, and in demo mode the traffic is
            # invented — in both cases pairing real sockets with those flows
            # would invite conclusions about connections that do not exist.
            offline = bool(self.app.source)
            detached = offline or self.app.demo
            if self.app.demo and hasattr(self.app.engine, "sockets"):
                rows = self.app.engine.sockets()      # invented, like the traffic
            else:
                rows = [] if detached else self.app.sockets.rows()
            open_rows, listening, closed = build_view(
                rows, store.flows,
                name_for_pid=self.app.resolver.name_for_pid,
                host_for_ip=lambda ip: store.dns_cache.get(ip, ""))
            return self._send(200, {
                "connections": open_rows,
                "listening": listening,
                "closed": closed,
                "offline": offline,
                "demo": bool(self.app.demo),
                "detached": detached,
                "supported": self.app.sockets.available,
                "error": "" if detached else self.app.sockets.error,
            })

        if path == "/api/alerts":
            a = self.app.alerts
            return self._send(200, {
                "alerts": a.list(),
                "counts": a.counts(),
                "rules": a.rules,
                "why": RULE_WHY,
                "mutes": a.list_mutes(),
                "threshold_mb": a.threshold_mb,
                "toasts": a.notifier.enabled,
                "toasts_supported": IS_WINDOWS,
                "reverse_dns": bool(self.app.reverse and self.app.reverse.enabled),
                "reverse_dns_stats": self.app.reverse.stats() if self.app.reverse else None,
            })

        if path == "/api/streams":
            return self._send(200, {"streams": self.app.streams.list()})

        if path == "/api/stream":
            sid = int(qs.get("id", ["0"])[0])
            st = self.app.streams.get(sid)
            if st is None:
                return self._send(404, {"error": "stream no longer in buffer"})
            out = {"summary": st.summary(), "sides": {}}
            for d, name in ((0, "c2s"), (1, "s2c")):
                data, gaps = st.assemble(d)
                out["sides"][name] = {"total": len(data), "gaps": gaps}
            blocks, clipped = st.interleaved(cap=STREAM_VIEW_CAP * 2)
            out["blocks"] = [{"dir": d, "b64": base64.b64encode(b).decode()}
                             for d, b in blocks]
            out["clipped"] = clipped
            return self._send(200, out)

        if path == "/api/dhcp":
            return self._send(200, {
                "leases": self.app.dhcp.list() if self.app.dhcp else [],
            })

        if path == "/api/objects":
            return self._send(200, {
                "objects": self.app.objects.list(),
                "total_bytes": self.app.objects.total_bytes,
                "enabled": self.app.scanner.enabled if self.app.scanner else False,
            })

        if path == "/api/object":
            oid = int(qs.get("id", ["0"])[0])
            o = self.app.objects.get(oid)
            if o is None:
                return self._send(404, {"error": "object expired"})
            data = o["_data"]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            # The name came off the wire, so it is attacker-controlled: a quote
            # or a newline in it would inject a header, and a path separator
            # would aim the download somewhere it was not meant to go.
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % safe_filename(o["name"]))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/api/object_preview":
            oid = int(qs.get("id", ["0"])[0])
            o = self.app.objects.get(oid)
            if o is None:
                return self._send(404, {"error": "object expired"})
            data = o["_data"][:64 * 1024]
            return self._send(200, {
                "name": o["name"], "ctype": o["ctype"], "size": o["size"],
                "textual": o["textual"],
                "b64": base64.b64encode(data).decode(),
                "clipped": o["size"] > len(data),
            })

        if path == "/api/interfaces":
            eng = self.app.engine
            # Forced: this endpoint exists precisely to answer "what is
            # attached right now", and a cached answer is what made adapters
            # appearing after launch invisible until a restart.
            if hasattr(eng, "refresh_interfaces"):
                eng.refresh_interfaces(force=True)
            return self._send(200, {
                "interfaces": eng.interfaces(refresh=False),
                "current": eng.iface,
                "active": list(getattr(eng, "ifaces", []) or []),
                "spec": getattr(eng, "spec", "default"),
            })

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "localhost only"})
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._authed(qs):
            return self._send(403, {"error": "bad token"})
        length = int(self.headers.get("Content-Length") or 0)

        if u.path == "/api/import":
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return self._send(400, {"error": "no file received"})
            packets, err = read_pcap(raw)
            if err:
                return self._send(400, {"error": "could not read capture: " + err})
            self.app.engine.stop()
            self.app.store.clear()
            self.app.streams.clear()
            self.app.objects.clear()
            self.app.alerts.clear()
            dec = self.app.decoder
            n = dec.ingest_file(packets)
            dec.close_streams()
            self.app.source = qs.get("name", ["capture.pcap"])[0]
            return self._send(200, {
                "loaded": n, "name": self.app.source, "status": self.status()})

        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}

        if u.path == "/api/control":
            action = body.get("action")
            eng = self.app.engine
            if action == "start":
                want = body.get("iface") or None
                eng.start(want, body.get("filter") or "")
                if want:
                    save_setting("iface", want)
            elif action == "stop":
                eng.stop()
            elif action == "clear":
                self.app.store.clear()
                self.app.streams.clear()
                self.app.objects.clear()
            elif action == "extract":
                if self.app.scanner:
                    self.app.scanner.enabled = bool(body.get("enabled", True))
            elif action == "alerts":
                a = self.app.alerts
                for k, v in (body.get("rules") or {}).items():
                    if k in a.rules:
                        a.rules[k] = bool(v)
                if "threshold_mb" in body:
                    try:
                        a.threshold_mb = max(1, int(body["threshold_mb"]))
                        a._threshold_fired.clear()
                    except (TypeError, ValueError):
                        pass
                if "toasts" in body:
                    a.notifier.enabled = bool(body["toasts"])
                a.save_config()          # so a reboot does not undo the choice
                if "reverse_dns" in body and self.app.reverse is not None:
                    self.app.reverse.set_enabled(bool(body["reverse_dns"]))
            elif action == "mute":
                a = self.app.alerts
                rule, subject = body.get("rule"), body.get("subject")
                if rule and subject is not None:
                    mins = body.get("minutes")
                    a.mute(rule, subject, int(mins) if mins else None)
            elif action == "unmute":
                a = self.app.alerts
                if body.get("rule") and body.get("subject") is not None:
                    a.unmute(body["rule"], body["subject"])
            elif action == "dismiss_alert":
                try:
                    self.app.alerts.dismiss(int(body.get("id")))
                except (TypeError, ValueError):
                    pass
            elif action == "clear_alerts":
                self.app.alerts.clear()
            elif action == "history_flush":
                if self.app.history:
                    self.app.history.flush()
            elif action == "history_wipe":
                if self.app.history:
                    self.app.history.wipe()
            elif action == "history_retain":
                h = self.app.history
                if h:
                    try:
                        h.retain_days = max(1, int(body.get("retain_days", 90)))
                        h.alert_retain_days = max(
                            1, int(body.get("alert_retain_days", 30)))
                        h.prune()
                    except (TypeError, ValueError):
                        pass
            elif action == "restart":
                eng.stop()
                want = body.get("iface") or getattr(eng, "spec", None)
                eng.start(want, body.get("filter", eng.bpf))
                if want:
                    save_setting("iface", want)
            return self._send(200, {"status": self.status()})

        return self._send(404, {"error": "not found"})

    # -- helpers -------------------------------------------------------------

    def store_since(self, since):
        return self.app.store.since(since)

    def status(self):
        eng = self.app.engine
        return {
            "running": eng.running,
            "iface": eng.iface,
            "ifaces": list(getattr(eng, "ifaces", []) or []),
            "multi": len(getattr(eng, "ifaces", []) or []) > 1,
            "filter": eng.bpf,
            "error": eng.error,
            "demo": self.app.demo,
            "version": VERSION,
            "admin": is_admin(),
            "proc_attribution": bool(psutil) and (is_admin() or not IS_WINDOWS),
            "extract": self.app.scanner.enabled if self.app.scanner else False,
            "objects": len(self.app.objects.list()) if self.app.objects else 0,
            "dhcp_leases": len(self.app.dhcp.list()) if self.app.dhcp else 0,
            "alerts": self.app.alerts.counts() if self.app.alerts else {},
            "source": self.app.source,
            "quic_keys": QUIC_CRYPTO_OK,
            "packets": self.app.store.total_packets,
            "history": bool(self.app.history and self.app.history.enabled),
            "autostart": tray.task_status(),
            # None when nothing can report it, so the dashboard can stay quiet
            # rather than assert a clean capture it has not verified.
            "new_ifaces": list(getattr(eng, "new_ifaces", []) or []),
            "capture": (eng.capture_stats()
                        if hasattr(eng, "capture_stats") else None),
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def print_interfaces():
    rows = CaptureEngine.interfaces()
    if not rows:
        print("No capture interfaces found.")
        if not SCAPY_OK:
            print(f"  Scapy could not load: {SCAPY_ERROR}")
        if IS_WINDOWS:
            print("  Install Npcap from https://npcap.com and run as Administrator.")
        return
    print(f"{'NAME':<42} {'IP':<16} DESCRIPTION")
    for r in rows:
        print(f"{r['name'][:41]:<42} {r['ip'][:15]:<16} {r['description'][:60]}")


def _redirect_output_if_no_console():
    """
    A windows-subsystem build has no stdout at all.

    PyInstaller's --noconsole leaves sys.stdout as None, so every print in this
    file would either vanish or raise. Point them at a log file instead, so the
    startup banner — including the dashboard URL and its token — is still
    recoverable when something goes wrong and there is no console to read.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return None
    try:
        folder = os.path.dirname(default_db_path())
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "netscope.log")
        fh = open(path, "a", encoding="utf-8", buffering=1)
        fh.write("\n" + "=" * 60 + "\n")
        fh.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "  started\n")
        sys.stdout = fh
        sys.stderr = fh
        return path
    except Exception:
        class _Null:
            def write(self, *_a): pass
            def flush(self): pass
        sys.stdout = sys.stderr = _Null()
        return None


def main(argv=None):
    logfile = _redirect_output_if_no_console()
    ap = argparse.ArgumentParser(prog="NetScope", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", help="interface to capture on: a name, a comma-separated list, or 'all'")
    ap.add_argument("--filter", default="", help="BPF capture filter, e.g. 'tcp port 443'")
    ap.add_argument("--port", type=int, default=8477, help="dashboard port (default 8477)")
    ap.add_argument("--demo", action="store_true", help="synthetic traffic, no capture")
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser")
    ap.add_argument("--no-extract", action="store_true",
                    help="don't rebuild transferred files from streams")
    ap.add_argument("--read", metavar="FILE",
                    help="open a .pcap/.pcapng instead of capturing live")
    ap.add_argument("--toasts", action="store_true",
                    help="send Windows desktop notifications for alerts")
    ap.add_argument("--tray", action="store_true",
                    help="run in the system tray with the console hidden")
    ap.add_argument("--db", metavar="FILE", help="history database path")
    ap.add_argument("--no-history", action="store_true",
                    help="don't record history to disk")
    ap.add_argument("--retain-days", type=int, default=90,
                    help="how many days of history to keep (default 90)")
    ap.add_argument("--stress-drops", type=int, metavar="US", default=0,
                    help="stall the capture US microseconds per packet, to "
                         "verify the dropped-packet warning (try 500)")
    ap.add_argument("--install-task", "--install-autostart", dest="install_task",
                    action="store_true",
                    help="start NetScope in the tray at logon (scheduled task; "
                         "run from an elevated prompt)")
    ap.add_argument("--remove-task", "--remove-autostart", dest="remove_task",
                    action="store_true", help="undo --install-task")
    ap.add_argument("--task-status", action="store_true",
                    help="show whether the logon task is registered")
    ap.add_argument("--autostart-registry", action="store_true",
                    help="fallback: use an HKCU Run entry instead of a task "
                         "(only works for a non-elevated build)")
    ap.add_argument("--remove-autostart-registry", action="store_true",
                    help="remove the HKCU Run entry")
    ap.add_argument("--version", action="version", version=f"NetScope {VERSION}")
    args = ap.parse_args(argv)

    # NetScopeTray.exe is the same program built without a console. Running it
    # means you want the tray, so you never have to remember the flag.
    exe_name = os.path.basename(sys.executable if getattr(sys, "frozen", False)
                                else sys.argv[0]).lower()
    if "tray" in exe_name:
        args.tray = True
        args.no_browser = True

    if args.list:
        print_interfaces()
        return 0

    if args.task_status:
        print(f"NetScope {VERSION}")
        st = tray.task_status()
        if not st["supported"]:
            print("  Start on login: Windows only")
        elif not st["exists"]:
            print("  Start on login: not set up")
            print("    Run an elevated prompt and:  NetScope.exe --install-task")
        else:
            print("  Start on login: registered")
            print(f"    Runs:      {st['command']}")
            print(f"    As:        {st.get('run_as','')}")
            print(f"    State:     {st.get('state','')}")
            if st.get("last_run"):
                print(f"    Last run:  {st['last_run']}  (result {st.get('last_result','')})")
            # The commonest complaint about this feature is a console window at
            # every logon, and the answer is always visible right here.
            if tray.is_console_command(st.get("command")):
                twin, have_twin = tray.tray_twin()
                print("    Note:      this is the console build, so a console "
                      "window opens at every logon.")
                if have_twin:
                    print("               NetScopeTray.exe is available next to "
                          "it — re-run")
                    print("               'NetScope.exe --install-task' from an "
                          "elevated prompt to switch.")
                elif twin:
                    print(f"               NetScopeTray.exe is not there "
                          f"({twin}).")
                    print("               Build it with build.bat, put it in "
                          "that folder, then re-run --install-task.")
        reg = tray.autostart_status()
        if reg.get("enabled"):
            print(f"  Run-key entry also present: {reg['command']}")
        return 0

    if args.install_task:
        print(f"NetScope {VERSION}")
        exe, _, _ = tray._exe_and_args()
        low = exe.lower()
        if "\\temp\\" in low or "\\downloads\\" in low or "\\appdata\\local\\temp" in low:
            print(f"  Refusing: {exe}")
            print("  That looks like a temporary folder. Move NetScope.exe "
                  "somewhere permanent first —")
            print("  the task records this exact path and breaks if the file moves.")
            return 1
        twin, have_twin = tray.tray_twin()
        ok, detail = tray.install_task()
        if ok:
            print("  Start on login: registered as a scheduled task")
            print(f"    Runs:  {detail}")
            print("    It starts 20 seconds after logon, with administrator "
                  "rights and no UAC prompt,")
            print("    and has no execution time limit so it keeps running "
                  "indefinitely.")
            # Registering the console build is legitimate, but it is almost
            # never what someone setting up a logon start actually wants, and
            # silence here is how you find out at the next reboot instead.
            if twin and not have_twin:
                print()
                print("  NOTE: that is the console build — a console window "
                      "will open at every logon.")
                print(f"        NetScopeTray.exe was not found next to it: "
                      f"{twin}")
                print("        Build it with build.bat, copy it into that "
                      "folder, and run --install-task")
                print("        again; the task switches to it on its own once "
                      "the file is there.")
            print("\n  Test it now without rebooting:  schtasks /Run /TN NetScope")
            print("  Remove it later:                NetScope.exe --remove-task")
        else:
            print(f"  Start on login: FAILED — {detail}")
        return 0 if ok else 1

    if args.remove_task:
        ok, detail = tray.remove_task()
        print(f"NetScope {VERSION}")
        print("  Start on login: " + ("removed" if ok else "FAILED — " + detail))
        return 0 if ok else 1

    if args.autostart_registry:
        ok, detail = tray.enable_autostart()
        print(f"NetScope {VERSION}")
        if ok:
            print(f"  Run-key entry written:\n    {detail}")
            print("\n  Note: this only works for a build without --uac-admin.")
            print("  An elevated NetScope launched this way prompts for UAC at "
                  "every logon;")
            print("  use --install-task instead.")
        else:
            print(f"  FAILED — {detail}")
        return 0 if ok else 1

    if args.remove_autostart_registry:
        ok, detail = tray.disable_autostart()
        print(f"NetScope {VERSION}")
        print("  Run-key entry: " + ("removed" if ok else "FAILED — " + detail))
        return 0 if ok else 1

    print(f"NetScope {VERSION}")

    if not args.demo:
        if not SCAPY_OK:
            print(f"\n  Scapy could not load: {SCAPY_ERROR}")
            print("  Falling back to demo mode. Install Npcap from https://npcap.com")
            args.demo = True
        elif not is_admin():
            print("\n  Not running as Administrator - packet capture will likely fail.")
            print("  Right-click NetScope.exe and choose 'Run as administrator'.\n")

    store = PacketStore()
    resolver = ProcessResolver()
    resolver.start()

    streams = StreamTracker()
    objects = ObjectStore()
    scanner = ObjectScanner(streams, objects)
    scanner.enabled = not args.no_extract
    scanner.start()
    history = HistoryStore(path=args.db, retain_days=args.retain_days,
                           enabled=not args.no_history)
    alerts = AlertEngine(DesktopNotifier(enabled=args.toasts), history=history)
    alerts.attach_settings(load_settings, save_setting)
    dhcp = DhcpTracker()
    reverse = ReverseResolver(store)
    reverse.attach_settings(load_settings, save_setting)
    reverse.start()

    engine = (DemoEngine(store, streams=streams, alerts=alerts, history=history,
                         dhcp=dhcp)
              if args.demo
              else CaptureEngine(store, resolver, streams=streams,
                                 alerts=alerts, history=history, dhcp=dhcp,
                                 reverse=reverse))
    decoder = (CaptureEngine(store, resolver, streams=streams, alerts=alerts,
                             history=history, dhcp=dhcp, reverse=reverse)
              if args.demo else engine)
    if args.stress_drops and hasattr(engine, "stress_us"):
        engine.stress_us = max(0, args.stress_drops)
        print(f"  Stress:    stalling the capture {engine.stress_us}us per "
              f"packet — expect dropped packets. Testing only.")

    loaded = None
    if args.read:
        try:
            with open(args.read, "rb") as fh:
                packets, err = read_pcap(fh.read())
            if err:
                print(f"  Could not read {args.read}: {err}")
                return 1
            loaded = decoder.ingest_file(packets)
            decoder.close_streams()
            print(f"  Loaded:    {loaded} packets from {args.read}")
        except OSError as exc:
            print(f"  Could not open {args.read}: {exc}")
            return 1
    else:
        chosen = args.iface or load_settings().get("iface") or "all"
        ok = engine.start(chosen, args.filter)
        if not ok and engine.error:
            print(f"  Capture failed to start: {engine.error}")
            print("  The dashboard will still open; pick another interface there.")

    token = secrets.token_urlsafe(18)
    Handler.app = App(store, engine, resolver, token, demo=args.demo,
                      streams=streams, objects=objects, scanner=scanner,
                      alerts=alerts, decoder=decoder, history=history,
                      dhcp=dhcp, reverse=reverse)
    if args.read:
        Handler.app.source = os.path.basename(args.read)

    try:
        httpd = DashboardServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        msg = (f"Port {args.port} is already in use — NetScope may already "
               f"be running (check the tray icon or Task Manager). Open its "
               f"existing dashboard instead, or pick another port with "
               f"--port.")
        print(f"\n  {msg}\n  ({exc})\n")
        # In tray mode there may be no console anyone will ever see this on
        # (NetScopeTray.exe has none at all), so put it somewhere that is:
        # a message box the user has to dismiss, not a line of text nobody
        # is watching.
        if args.tray:
            tray.fatal_message("NetScope could not start", msg)
        return 1
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}/?t={token}"

    if args.read:
        mode = f"offline — {os.path.basename(args.read)}"
    elif args.demo:
        mode = "DEMO (synthetic traffic)"
    else:
        mode = f"capturing on {engine.iface}"
    print(f"  Mode:      {mode}")
    if not QUIC_CRYPTO_OK:
        print("  QUIC:      hostnames unavailable — 'cryptography' not installed")
    if engine.bpf:
        print(f"  Filter:    {engine.bpf}")
    print(f"  Extract:   {'on — rebuilding files from unencrypted streams' if scanner.enabled else 'off'}")
    if history.enabled:
        s = history.summary()
        span = f", data since {s['since']}" if s.get("since") else ", empty"
        print(f"  History:   {history.path}{span}")
        if alerts.baselining:
            print("             first run — recording a baseline, so "
                  "'never seen before' alerts start next time")
    elif history.error:
        print(f"  History:   unavailable — {history.error}")
    else:
        print("  History:   off")
    print(f"  Dashboard: {url}")
    if logfile:
        print(f"  Log:       {logfile}")
    print("\n  Press Ctrl+C to stop.\n")

    history.start(iface=getattr(engine, "iface", None), version=VERSION)

    if not args.no_browser and not args.tray:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    def shutdown():
        engine.stop()
        resolver.stop()
        scanner.stop()
        history.stop()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    if args.tray:
        if not tray.TRAY_OK:
            print(f"  Tray:      unavailable — {tray.TRAY_ERROR}")
            print("             (pip install pystray pillow)")
        else:
            hid = tray.hide_console()
            if hid:
                print("  Tray:      running in the notification area")
            elif tray.owns_console():
                print("  Tray:      running in the notification area")
            else:
                print("  Tray:      running in the notification area — this "
                      "console belongs to your shell, so it is left alone.")
                print("             Launch detached to avoid it entirely:")
                print("               Start-Process -WindowStyle Hidden "
                      f"'{sys.executable}' -ArgumentList '--tray'")
                print("             or use NetScopeTray.exe, which has no console.")
            threading.Thread(target=httpd.serve_forever, daemon=True,
                             name="http").start()

            last = {"bytes": 0, "t": time.time()}

            def status():
                st = store.stats()
                now = time.time()
                total = st["total_in"] + st["total_out"]
                dt = max(0.001, now - last["t"])
                rate = (total - last["bytes"]) / dt
                last["bytes"], last["t"] = total, now
                return {"rate": human_bytes(rate) + "/s",
                        "packets": st["total_packets"],
                        "alerts": alerts.counts(),
                        "running": engine.running}

            def toggle():
                if engine.running:
                    engine.stop()
                else:
                    engine.start(engine.iface, engine.bpf)

            icon = tray.Tray(url, on_quit=shutdown, on_toggle=toggle,
                             status_fn=status)
            try:
                icon.run()
            except KeyboardInterrupt:
                shutdown()
            return 0

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        engine.stop()
        resolver.stop()
        scanner.stop()
        history.stop()
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
