"""Per-second traffic totals for the dashboard's Timeline view.

The packet ring holds at most RING_SIZE packets, which on a busy machine is
well under a minute; the Timeline shows up to an hour. So every packet is
also added here, as a byte and packet count against a key, per second.

The key is everything the display filter can ask about that stays the same
across a conversation's packets: program, remote host and address, local
address, direction, protocol, remote port and adapter. Per-packet fields
(info, length, pid, local port) are not kept, so the page can apply most
filters to this data and says plainly when it can't.

Keys are sent to the page once and referred to by index afterwards, so the
once-a-second update carries only numbers. The index table is compacted when
it grows too large; `gen` changes when that happens (or on clear), which tells
the page to drop what it has and fetch everything again.
"""

import bisect
import threading

RETAIN = 3600               # seconds kept, counted back from the newest packet
MAX_KEYS_PER_SEC = 400      # a scan would otherwise make one key per probe
MAX_KEYS = 20000


class Timeline:
    def __init__(self, retain=RETAIN):
        self._lock = threading.Lock()
        self.retain = retain
        self._order = []        # seconds held, ascending
        self._secs = {}         # second -> {key index: [bytes, packets]}
        self._keys = []         # key index -> key tuple
        self._index = {}        # key tuple -> key index
        self.gen = 1
        self.newest = 0

    @staticmethod
    def key_of(rec):
        out = rec.get("dir") == "out"
        remote = rec.get("remote") or (rec.get("dst") if out else rec.get("src")) or ""
        local = (rec.get("src") if out else rec.get("dst")) or ""
        rport = rec.get("dport") if out else rec.get("sport")
        return (rec.get("process") or "-", rec.get("rhost") or "", remote, local,
                "out" if out else "in", rec.get("proto") or "", rport,
                rec.get("iface") or "")

    @staticmethod
    def _lumped(key):
        # What a key collapses to once a second (or the table) is full: the
        # program and direction survive, which is what the lanes are made of.
        proc, _h, _r, local, d, _p, _port, iface = key
        return (proc, "", "(many)", local, d, "", None, iface)

    def _intern(self, key):
        i = self._index.get(key)
        if i is None:
            if len(self._keys) >= MAX_KEYS:
                self._compact()
                if len(self._keys) >= MAX_KEYS * 3 // 4:
                    key = self._lumped(key)
                    i = self._index.get(key)
                    if i is not None:
                        return i
            i = len(self._keys)
            self._keys.append(key)
            self._index[key] = i
        return i

    def _compact(self):
        used = sorted({k for b in self._secs.values() for k in b})
        remap = {old: new for new, old in enumerate(used)}
        self._keys = [self._keys[i] for i in used]
        self._index = {k: i for i, k in enumerate(self._keys)}
        # In place: observe() may be holding one of these buckets.
        for b in self._secs.values():
            moved = {remap[k]: v for k, v in b.items()}
            b.clear()
            b.update(moved)
        self.gen += 1

    def observe(self, rec):
        try:
            sec = int(rec["ts"])
            size = int(rec.get("length") or 0)
        except (KeyError, TypeError, ValueError):
            return
        key = self.key_of(rec)
        with self._lock:
            if sec < self.newest - self.retain:
                return
            b = self._secs.get(sec)
            if b is None:
                b = self._secs[sec] = {}
                if not self._order or sec > self._order[-1]:
                    self._order.append(sec)
                else:
                    # Packets arrive from several threads and adapters, and a
                    # .pcap can be out of order; seconds still sort.
                    bisect.insort(self._order, sec)
            i = self._intern(key)
            if i not in b and len(b) >= MAX_KEYS_PER_SEC:
                i = self._intern(self._lumped(key))
            c = b.get(i)
            if c is None:
                b[i] = [size, 1]
            else:
                c[0] += size
                c[1] += 1
            if sec > self.newest:
                self.newest = sec
                cut = sec - self.retain
                while self._order and self._order[0] < cut:
                    self._secs.pop(self._order.pop(0), None)

    def snapshot(self, since=None, kfrom=0, gen=None):
        """Seconds from `since` on, and the keys from index `kfrom` on.

        A `gen` other than the current one means the page's key indices are
        stale, so it gets everything.
        """
        with self._lock:
            if gen != self.gen:
                since, kfrom = None, 0
            kfrom = max(0, min(int(kfrom or 0), len(self._keys)))
            start = 0 if since is None else bisect.bisect_left(self._order, since)
            buckets = [[s, [[k, v[0], v[1]] for k, v in self._secs[s].items()]]
                       for s in self._order[start:]]
            return {"gen": self.gen, "full": since is None, "kfrom": kfrom,
                    "keys": [list(k) for k in self._keys[kfrom:]],
                    "buckets": buckets, "newest": self.newest,
                    "retain": self.retain}

    def clear(self):
        with self._lock:
            self._order.clear()
            self._secs.clear()
            self._keys.clear()
            self._index.clear()
            self.newest = 0
            self.gen += 1
