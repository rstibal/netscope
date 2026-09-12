# -*- coding: utf-8 -*-
"""
FTP control-channel parsing and data-connection correlation.

FTP splits a transfer across two TCP connections: a long-lived control
channel (port 21) carrying commands and status lines in plain text, and a
short-lived data channel — on a port negotiated *inside* the control
channel's text — that carries nothing but the raw bytes of one file. This
module reads the control channel far enough to know that the next connection
to some IP:port is about to deliver a named file, so that when that second
connection's first packet arrives (on an arbitrary port picked at negotiation
time), the stream tracker can be told what it is instead of guessing from the
port number.

Downloads only for now: RETR is tracked; STOR/STOU (uploads) are deliberately
ignored, so this never arms a data connection for anything but a download.
"""

from __future__ import annotations

import re

# 227 (PASV) and its close cousins all end in "(a,b,c,d,p1,p2)". Active mode
# has the client name the same six numbers in a PORT command instead.
PASV_RE = re.compile(rb"227[^(]*\(([\d,]+)\)")
PORT_RE = re.compile(rb"PORT (\d+,\d+,\d+,\d+,\d+,\d+)", re.I)
RETR_RE = re.compile(rb"^RETR\s+(.+?)\r?$", re.I | re.M)

# How long a negotiated data endpoint is honored before it's forgotten — the
# data connection normally opens within a second or two of PASV/PORT; a
# negotiation nobody acts on must not sit around forever.
PENDING_TTL = 30.0

# Housekeeping is cheap but pointless more than a few times a minute.
SWEEP_INTERVAL = 5.0


def _addr(nums: bytes):
    a, b, c, d, p1, p2 = (int(n) for n in nums.split(b","))
    return f"{a}.{b}.{c}.{d}", p1 * 256 + p2


class FTPCorrelator:
    """One instance shared across the whole capture."""

    def __init__(self):
        self._pending_cmd = {}     # control-conn key -> filename
        self._pending_addr = {}    # (ip, port) -> {"name": ...}
        self._expire = {}          # (ip, port) -> deadline
        self._last_sweep = 0.0

    @staticmethod
    def _ckey(a_ip, a_port, b_ip, b_port):
        return frozenset(((a_ip, a_port), (b_ip, b_port)))

    def observe_control(self, src, sport, dst, dport, payload, to_server, ts):
        """
        Feed one control-channel segment.

        to_server is True for a client->server segment (commands, PORT) and
        False for server->client (PASV replies). It comes from which side of
        this packet has port 21, not from the host-relative "direction" used
        elsewhere in the capture — this machine could be either the FTP
        client or the server.
        """
        ckey = self._ckey(src, sport, dst, dport)
        if to_server:
            m = RETR_RE.search(payload)
            if m:
                name = m.group(1).decode("latin-1", "replace").strip()
                self._pending_cmd[ckey] = name
            m = PORT_RE.search(payload)
            if m:
                self._arm(ckey, *_addr(m.group(1)), ts)
        else:
            m = PASV_RE.search(payload)
            if m:
                self._arm(ckey, *_addr(m.group(1)), ts)

    def _arm(self, ckey, ip, port, ts):
        name = self._pending_cmd.get(ckey)
        if not name:
            return              # no pending RETR: not a download, not tracked
        self._pending_addr[(ip, port)] = {"name": name, "direction": "download"}
        self._expire[(ip, port)] = ts + PENDING_TTL

    def match_data(self, src, sport, dst, dport):
        """
        Called for a connection that has no other protocol hint. Returns the
        pending download's metadata and consumes it, or None.
        """
        for ip, port in ((src, sport), (dst, dport)):
            meta = self._pending_addr.pop((ip, port), None)
            if meta is not None:
                self._expire.pop((ip, port), None)
                return meta
        return None

    def sweep(self, ts):
        """Drop negotiated endpoints nobody connected to. Self-throttled."""
        if ts - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = ts
        for k, deadline in list(self._expire.items()):
            if deadline < ts:
                self._pending_addr.pop(k, None)
                self._expire.pop(k, None)
