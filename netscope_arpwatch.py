"""
Tell a replaced device from an impersonated one, from ARP sightings.

A MAC change for an IP is ambiguous on its own: a router swap, a NIC swap or
a VM restart look the same, for a moment, as ARP cache poisoning. The
difference is what happens next. A replaced device is gone: its old MAC never
claims the address again. An impersonation is a fight: a poisoning tool keeps
re-claiming the address while the real device keeps claiming it back. So a
change is held (`hold` seconds) before it is believed:

  * the hold passes with the old MAC silent -> "replaced";
  * the old MAC claims the address back once, during the hold or within
    `flip_window` after a replacement -> "contested" (two devices claimed
    it). A Bonjour sleep proxy, a MAC-translating extender, a proxy-ARP
    hotspot or an overlapping router swap all do this, so it is recorded,
    not raised;
  * the address changes hands REPEATS (3) times within `hold` seconds, between
    any devices (old -> new -> old -> new) -> "impersonated", once per
    (iface, ip) until clear(). A third device turning up during the hold is
    one more change of hands, not an impersonation by itself.

Pure logic: no clock of its own (callers pass `now`) and no threads. One lock
guards the state, because observe() runs on the capture thread and tick() on
the alert beat. Nothing here blocks or does I/O.
"""
import threading
from collections import OrderedDict

MAX_ENTRIES = 4096      # tracked (iface, ip) pairs; the least recently seen go
MAX_SEEN = 8            # last-seen times kept per pair
REPEATS = 3             # changes of hands within `hold` that mean a fight


class ArpWatch:
    def __init__(self, hold=60.0, flip_window=3600.0):
        self.hold = hold
        self.flip_window = flip_window
        self._lock = threading.Lock()
        self._entries = OrderedDict()       # (iface, ip) -> entry dict

    def clear(self):
        with self._lock:
            self._entries.clear()

    def observe(self, iface, ip, mac, now):
        key = (iface, ip)
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                self._entries[key] = {"cur": mac, "pending": None,
                                      "prev": None, "seen": {mac: now},
                                      "last": mac, "hands": [],
                                      "flagged": False}
                while len(self._entries) > MAX_ENTRIES:
                    self._entries.popitem(last=False)
                return []
            self._entries.move_to_end(key)
            events = self._settle(key, e, now)
            e["seen"][mac] = now
            if mac != e["last"]:
                # The address changed hands. Only the last REPEATS times
                # matter: is the oldest of them within the hold?
                e["last"] = mac
                e["hands"] = (e["hands"] + [now])[-REPEATS:]
            self._trim(e)
            if e["flagged"]:
                return events
            hands = e["hands"]
            if len(hands) >= REPEATS and now - hands[0] <= self.hold:
                return events + [self._impersonated(key, e)]
            pending, prev, cur = e["pending"], e["prev"], e["cur"]
            if pending is not None:
                if mac == pending["mac"]:
                    return events
                if mac == cur:
                    # The old device claimed it back once: contested.
                    if pending.get("contested"):
                        return events
                    pending["contested"] = True
                    return events + [("contested", iface, ip, cur,
                                      pending["mac"])]
                # A third device: what is pending now. The change of hands
                # was counted above.
                e["pending"] = {"mac": mac, "at": now,
                                "contested": pending.get("contested", False)}
                return events
            if mac == cur:
                return events
            if prev is not None and mac == prev["mac"] and now < prev["until"]:
                # The replaced device is back: one reclaim, reported once.
                e["prev"] = None
                e["pending"] = {"mac": mac, "at": now, "contested": True}
                return events + [("contested", iface, ip, cur, mac)]
            e["pending"] = {"mac": mac, "at": now}
            return events

    def tick(self, now):
        events = []
        with self._lock:
            for key, e in self._entries.items():
                events += self._settle(key, e, now)
        return events

    # -- helpers (lock held) ------------------------------------------------

    def _settle(self, key, e, now):
        """Resolve a pending change whose hold is over."""
        p = e["pending"]
        if p is None or now - p["at"] < self.hold:
            return []
        old = e["cur"]
        e["pending"] = None
        if e["seen"].get(old, 0) > p["at"]:
            return []       # the old device kept claiming it: nothing changed
        e["cur"] = p["mac"]
        e["prev"] = {"mac": old, "until": now + self.flip_window}
        # Flagged: the impersonation said it all. Contested: that record
        # already named both devices; a second about the same pair is noise.
        if e["flagged"] or p.get("contested"):
            return []
        return [("replaced", key[0], key[1], old, p["mac"])]

    def _impersonated(self, key, e):
        e["flagged"] = True
        return ("impersonated", key[0], key[1], dict(e["seen"]))

    @staticmethod
    def _trim(e):
        seen = e["seen"]
        keep = {e["cur"], e["last"]}
        if e["pending"]:
            keep.add(e["pending"]["mac"])
        if e["prev"]:
            keep.add(e["prev"]["mac"])
        while len(seen) > MAX_SEEN:
            old = min((m for m in seen if m not in keep),
                      key=seen.get, default=None)
            if old is None:
                break
            del seen[old]
