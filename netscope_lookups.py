"""
Name lookups and how each one ended, for the Lookups view.

Every DNS query this machine sends is paired with its answer and kept for an
hour as one finished lookup: when it was asked, the name and record type, how
it ended, how long the answer took, who asked and which server.

How it ended is one of:

    ok        answered, with addresses or without. An empty answer is routine
              (an AAAA lookup for a name that only has IPv4) and is not a
              failure.
    nxdomain  the server said the name does not exist.
    error     the server reported anything else (SERVFAIL, REFUSED, ...).
    timeout   no answer within TIMEOUT seconds.

A burst of nxdomain is the shape of software hunting for a server by
generated names, and of a typo'd or dead hostname in a config; a burst of
timeout is the resolver or the network being down.

Only plain DNS is here. mDNS and LLMNR are multicast questions that nothing
answers "no" to, so "unanswered" would mean nothing; DNS a browser sends
encrypted (DoH/DoT) is not visible to a capture at all. On Windows most
queries are sent by the DNS Client service on behalf of other programs, so
the program on a lookup is usually svchost.exe: the name is the useful part.

A query and its answer are matched on (id, local port, server, adapter). A
query sent again before its answer is the same lookup, timed from the first.
"""
import threading
from collections import OrderedDict

from netscope_latency import SampleLog

RETAIN = 3600
MAX_EVENTS = 30000          # an hour at eight lookups a second
TIMEOUT = 5.0               # seconds a query is given before it is unanswered
MAX_PENDING = 4096          # questions waiting; a flood drops the oldest unreported

RCODE_NXDOMAIN = 3


class Lookups:
    def __init__(self, retain=RETAIN, max_events=MAX_EVENTS, timeout=TIMEOUT):
        # (ts, name, qtype, outcome, ms or None, process, server, iface)
        self.log = SampleLog(retain=retain, max_samples=max_events)
        self.timeout = timeout
        self._lock = threading.Lock()
        self._pending = OrderedDict()   # key -> (ts, name, qtype, process), oldest first

    def pending(self):
        with self._lock:
            return len(self._pending)

    def observe(self, rec):
        """
        Every packet comes through here, not only DNS: any packet's time is
        what shows that five seconds have passed without an answer.
        """
        ts = rec.get("ts")
        if ts is None:
            return
        with self._lock:
            if self._pending:
                self._expire(ts)
            if rec.get("proto") != "DNS" or rec.get("tunnel_outer"):
                return
            d = (rec.get("decoded") or {}).get("dns")
            if not d:
                return
            iface = rec.get("iface") or ""
            if not d.get("response"):
                if rec.get("dir") != "out":
                    return                      # someone else's question
                key = (d.get("id"), rec.get("sport"), rec.get("dst"), iface)
                if key in self._pending:
                    return                      # sent again: still the first
                qs = d.get("queries") or []
                name = (qs[0].get("name") if qs else "") or "?"
                qtype = (qs[0].get("type") if qs else "") or "?"
                self._pending[key] = (ts, str(name).rstrip("."), str(qtype),
                                      rec.get("process") or "-")
                while len(self._pending) > MAX_PENDING:
                    self._pending.popitem(last=False)
                return
            if rec.get("dir") != "in":
                return
            key = (d.get("id"), rec.get("dport"), rec.get("src"), iface)
            p = self._pending.pop(key, None)
            if p is None:
                return                          # no question seen, or already timed out
            rcode = d.get("rcode") or 0
            outcome = ("ok" if rcode == 0 else
                       "nxdomain" if rcode == RCODE_NXDOMAIN else "error")
            asked, name, qtype, process = p
            self.log.add((asked, name, qtype, outcome,
                          round((ts - asked) * 1000, 1), process, key[2] or "", iface))

    def _expire(self, now):
        # Oldest first, so the walk stops at the first one still in time.
        while self._pending:
            key, (asked, name, qtype, process) = next(iter(self._pending.items()))
            if now - asked <= self.timeout:
                break
            del self._pending[key]
            self.log.add((asked, name, qtype, "timeout", None, process,
                          key[2] or "", key[3]))

    def snapshot(self, after=None, gen=None, now=None):
        """
        As SampleLog.snapshot(). `now` is the present for a live capture:
        with nothing arriving, reading is what notices an unanswered query.
        """
        if now is not None:
            with self._lock:
                if self._pending:
                    self._expire(now)
        return self.log.snapshot(after=after, gen=gen)

    def clear(self):
        with self._lock:
            self._pending.clear()
        self.log.clear()
