"""
Handshake times kept over time, for the Latency view.

The connection table already times each outbound TCP handshake (the SYN to
the SYN/ACK that answers it; see _quality() in netscope_conn.py) and shows
the number on the connection's row. A row is one connection and is gone when
the connection is, so it can't answer "has this host been getting slower?"
or "is it this host or everything?". This keeps each timing as a sample for
an hour: when, how long, and whose connection to where.

One sample per new connection, so nothing here for a host reached over QUIC,
for a connection that stays open, or for one somebody else opened. Samples
live in memory only; the history database is not involved.

The page reads a slice at a time (snapshot(after=...)), the way it reads the
Timeline, so a poll costs what arrived since the last one and not the hour.
SampleLog is that store on its own; the Lookups view keeps its finished
lookups in one too (netscope_lookups.py).
"""
import threading
from collections import deque

RETAIN = 3600               # seconds kept, counted back from the newest sample
MAX_SAMPLES = 20000         # an hour at five or six new connections a second


class SampleLog:
    """
    Rows kept for `retain` seconds and at most `max_samples`, each a tuple
    whose first field is its time, read a slice at a time by id.
    """

    def __init__(self, retain=RETAIN, max_samples=MAX_SAMPLES):
        self._lock = threading.Lock()
        self.retain = retain
        self.max_samples = max_samples
        self._samples = deque()         # oldest first
        self._base = 0          # the id of _samples[0]: how many have been dropped
        self.gen = 1            # changes on clear(), so a reader starts over
        self.newest = 0

    def add(self, row):
        """Append one row; row[0] is its time. Called on the capture path."""
        with self._lock:
            self._samples.append(tuple(row))
            if row[0] > self.newest:
                self.newest = row[0]
            cutoff = self.newest - self.retain
            while self._samples and (len(self._samples) > self.max_samples
                                     or self._samples[0][0] < cutoff):
                self._samples.popleft()
                self._base += 1

    def snapshot(self, after=None, gen=None):
        """
        Rows from id `after` on, or all of them for a reader that has none
        or whose `gen` is from before a clear(). `start` is the id of the
        first one returned (later than `after` when older ones have been
        dropped) and `next` is what to pass as `after` next time.
        """
        with self._lock:
            start = self._base
            if gen == self.gen and after is not None and after > start:
                start = min(after, self._base + len(self._samples))
            skip = start - self._base
            rows = [list(s) for i, s in enumerate(self._samples) if i >= skip]
            return {"gen": self.gen, "start": start,
                    "next": self._base + len(self._samples),
                    "newest": self.newest, "retain": self.retain, "samples": rows}

    def clear(self):
        with self._lock:
            self._samples.clear()
            self._base = 0
            self.newest = 0
            self.gen += 1


class Latency(SampleLog):
    """(ts, ms, process, rhost, remote, rport, iface) per timed handshake."""

    def note(self, ts, ms, process, rhost, remote, rport, iface):
        """One timed handshake. Called on the capture path."""
        try:
            ms = float(ms)
            ts = float(ts)
        except (TypeError, ValueError):
            return
        if ms < 0:
            return
        self.add((ts, ms, process or "-", rhost or "", remote or "", rport, iface or ""))

    def snapshot(self, after=None, gen=None, name_for=None):
        """
        As SampleLog.snapshot(). `name_for(ip)` names a host that had no name
        when its handshake went by, which is the usual case: the name is in
        the ClientHello, and that comes after. The stored sample is left alone.
        """
        out = super().snapshot(after=after, gen=gen)
        if name_for is not None:
            for r in out["samples"]:
                if not r[3] and r[4]:
                    try:
                        r[3] = name_for(r[4]) or ""
                    except Exception:
                        pass
        return out
