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
# has the client name the same six numbers in a PORT command instead. The
# extended forms (RFC 2428) are what curl and most modern clients send first:
# a 229 EPSV reply names only a port, on the server that sent it, and EPRT
# carries an address in either family between "|" delimiters.
PASV_RE = re.compile(rb"227[^(]*\(([\d,]+)\)")
EPSV_RE = re.compile(rb"229[^(]*\((.)\1\1(\d+)\1\)")
PORT_RE = re.compile(rb"^PORT (\d+,\d+,\d+,\d+,\d+,\d+)", re.I)
EPRT_RE = re.compile(rb"^EPRT (.)\d\1([^|]+)\1(\d+)\1", re.I)
RETR_RE = re.compile(rb"^RETR\s+(.+?)$", re.I)
# Every other command that consumes a negotiated data connection. After one of
# these the negotiation is spent, and a RETR that comes later needs its own.
OTHER_XFER_RE = re.compile(rb"^(STOR|STOU|APPE|LIST|NLST|MLSD)\b", re.I)

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
        # RFC 959 order is negotiate first (PASV/PORT), then name the file
        # (RETR) — the server only opens or accepts the data connection once
        # it knows what to send. So a negotiation has to wait, unnamed, for
        # the RETR that follows it. The reverse order is kept working too, in
        # case a client ever sends it, but a name waiting for a negotiation is
        # consumed by the first one, so it can never label a later transfer.
        self._pending_cmd = {}     # control-conn key -> filename awaiting PASV/PORT
        self._negotiated = {}      # control-conn key -> (ip, port, role, deadline)
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
            # Line by line and in order: a client may pipeline a PORT and
            # a RETR into one segment, and which came first matters.
            for line in payload.split(b"\n"):
                line = line.strip()
                m = PORT_RE.match(line)
                if m:
                    self._negotiate(ckey, *_addr(m.group(1)), "receiver", ts)
                    continue
                m = EPRT_RE.match(line)
                if m:
                    self._negotiate(ckey, m.group(2).decode("latin-1"),
                                    int(m.group(3)), "receiver", ts)
                    continue
                m = RETR_RE.match(line)
                if m:
                    name = m.group(1).decode("latin-1", "replace").strip()
                    self._retr(ckey, name, ts)
                    continue
                if OTHER_XFER_RE.match(line):
                    # Not a download: whatever was negotiated is spent on it.
                    self._negotiated.pop(ckey, None)
                    self._pending_cmd.pop(ckey, None)
        else:
            m = PASV_RE.search(payload)
            if m:
                self._negotiate(ckey, *_addr(m.group(1)), "sender", ts)
                return
            m = EPSV_RE.search(payload)
            if m:
                self._negotiate(ckey, src, int(m.group(2)), "sender", ts)

    def _negotiate(self, ckey, ip, port, role, ts):
        """role says which end of the file transfer (ip, port) is: PASV/EPSV
        name the server, which sends a download; PORT/EPRT name the client,
        which receives it."""
        name = self._pending_cmd.pop(ckey, None)
        if name:
            self._arm(ip, port, role, name, ts)
        else:
            self._negotiated[ckey] = (ip, port, role, ts + PENDING_TTL)

    def _retr(self, ckey, name, ts):
        neg = self._negotiated.pop(ckey, None)
        if neg is not None:
            self._arm(neg[0], neg[1], neg[2], name, ts)
        else:
            self._pending_cmd[ckey] = name

    def _arm(self, ip, port, role, name, ts):
        # The endpoint and its role travel with the name: whoever opens the
        # data connection is not necessarily the FTP client (in active mode
        # the server connects out), so extraction cannot assume which side of
        # the stream carries the file.
        self._pending_addr[(ip, port)] = {"name": name, "direction": "download",
                                          "endpoint": (ip, port), "role": role}
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
        for k, neg in list(self._negotiated.items()):
            if neg[3] < ts:
                self._negotiated.pop(k, None)
