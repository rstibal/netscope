"""
The "Needs you" store: alerts that wait for the user to decide.

A card stays open until it is acted on (trusted, blocked, dismissed or marked
expected), and open cards are kept in the history database so they survive a
restart. With no history (or history off) the cards live in memory for the
session.

Each card also remembers who its program talked to (`data["talk"]`), merged
over time, because the flow table forgets a connection soon after it ends.
"""

from __future__ import annotations

import copy
import threading
import time

STATES = ("trusted", "blocked", "dismissed", "expected")
TALK_KEYS = 200         # connections kept per card
PERSIST_EVERY = 60.0    # seconds between database writes of one card's talk


def merge_talk(saved, current):
    """
    Merge two {flow_key_str: {"host","in","out"}} maps. A flow keeps the larger
    figure of each (the table prunes, and a pruned flow reads smaller or goes
    missing). At most TALK_KEYS keys survive, the biggest by bytes.
    """
    out = {k: dict(v) for k, v in (saved or {}).items()}
    for k, v in (current or {}).items():
        old = out.get(k)
        if old is None:
            out[k] = {"host": v.get("host", ""), "in": v.get("in", 0),
                      "out": v.get("out", 0)}
        else:
            old["in"] = max(old.get("in", 0), v.get("in", 0))
            old["out"] = max(old.get("out", 0), v.get("out", 0))
            if v.get("host"):
                old["host"] = v["host"]
    if len(out) > TALK_KEYS:
        keep = sorted(out, key=lambda k: out[k].get("in", 0) + out[k].get("out", 0),
                      reverse=True)[:TALK_KEYS]
        out = {k: out[k] for k in keep}
    return out


def talk_by_host(talk):
    """[{"host","conns","in","out"}], biggest first."""
    by = {}
    for v in (talk or {}).values():
        row = by.setdefault(v.get("host", ""), {"host": v.get("host", ""),
                                                "conns": 0, "in": 0, "out": 0})
        row["conns"] += 1
        row["in"] += v.get("in", 0)
        row["out"] += v.get("out", 0)
    return sorted(by.values(), key=lambda r: r["in"] + r["out"], reverse=True)


def flows_for(snapshot, program):
    """
    The flows of `program` (case-insensitive) from FlowTable.snapshot(), as
    {str(flow_key): {"host","in","out"}}. The host is the flow's name, or else
    the remote address read from the key.
    """
    want = (program or "").lower()
    out = {}
    for key, f in (snapshot or {}).items():
        if (f.get("process") or "").lower() != want:
            continue
        host = f.get("rhost") or _remote_addr(key, f)
        out[str(key)] = {"host": host, "in": f.get("in", 0), "out": f.get("out", 0)}
    return out


def _remote_addr(key, f):
    """The end of the key that is not this machine's, when the flow says which."""
    try:
        _proto, _iface, a_ip, a_port, b_ip, b_port = key
    except (TypeError, ValueError):
        return ""
    lport = f.get("lport") or f.get("local_port")
    if lport is not None and a_port == lport and b_port != lport:
        return b_ip
    if lport is not None and b_port == lport and a_port != lport:
        return a_ip
    # No local port to go by: the lower port is usually the server's, so the
    # remote is the end with it; failing that, the second end.
    return a_ip if a_port and a_port < b_port else b_ip


class NeedsYou:
    """
    Callers are the judge worker and the beat threads. Never call add() or
    update_talk() from the capture thread: they may wait on the database.
    The lock guards memory only; disk writes happen outside it, serialised by
    their own lock, so open()/get() on the dashboard thread never wait on disk.
    """

    def __init__(self, history=None):
        self._history = history if history is not None and history.enabled else None
        self._lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._cards = {}            # id -> card, open and acted this session
        self._next = 1              # ids when there is no database
        self._next_local = -1       # ids for cards the database could not store
        self._pending = set()       # ids being inserted: hidden until they have a real one
        self._persisted = {}        # id -> `at` of the last talk write
        if self._history is not None:
            for c in self._history.needs_load():
                self._cards[c["id"]] = c

    def _persist(self, id):
        """Write the card's latest state. Never called with _lock held."""
        if self._history is None or id is None or id < 0:
            return
        with self._save_lock:
            with self._lock:
                c = self._cards.get(id)
                snap = self._copy(c) if c else None
            if snap is not None:
                self._history.needs_save(snap)

    @staticmethod
    def _copy(card):
        return copy.deepcopy(card)

    def add(self, kind, subject, data):
        """Add a card unless an open one has the same (kind, subject)."""
        with self._lock:
            for c in self._cards.values():
                if c["state"] == "open" and c["kind"] == kind and c["subject"] == subject:
                    return None
            card = {"id": None, "ts": time.time(), "kind": kind, "subject": subject,
                    "data": dict(data or {}), "state": "open", "acted": None}
            if self._history is None:
                card["id"] = self._next
                self._next += 1
                self._cards[card["id"]] = card
                return self._copy(card)
            # Reserved under the lock so a racing add of the same card dedups.
            card["id"] = self._next_local
            self._next_local -= 1
            tmp = card["id"]
            self._cards[tmp] = card
            self._pending.add(tmp)
            snap = self._copy(card)
            snap["id"] = None
        with self._save_lock:
            real = self._history.needs_save(snap)
        with self._lock:
            self._pending.discard(tmp)
            if real is not None:
                del self._cards[tmp]
                card["id"] = real
                self._cards[real] = card
            return self._copy(card)

    def open(self):
        with self._lock:
            cards = [c for i, c in self._cards.items()
                     if c["state"] == "open" and i not in self._pending]
            cards.sort(key=lambda c: c["id"], reverse=True)
            return [self._copy(c) for c in cards]

    def get(self, id):
        with self._lock:
            c = self._cards.get(id)
            return self._copy(c) if c and id not in self._pending else None

    def act(self, id, state):
        if state not in STATES:
            return None
        with self._lock:
            c = self._cards.get(id)
            if c is None or c["state"] != "open" or id in self._pending:
                return None
            c["state"] = state
            c["acted"] = time.time()
            self._persisted.pop(id, None)
            out = self._copy(c)
        self._persist(id)
        return out

    def update_talk(self, id, flows, at):
        """Merge flows into the card's talk. Not for the capture thread."""
        with self._lock:
            c = self._cards.get(id)
            if c is None or c["state"] != "open" or id in self._pending:
                return
            talk = merge_talk(c["data"].get("talk"), flows)
            h = self._history
            if h is not None:
                # A host excluded from history is not written to disk here
                # either: the name is the private part. Excluded later, it
                # comes out of what was saved before.
                talk = {k: v for k, v in talk.items()
                        if not h.excluded_host(v.get("host"))}
            c["data"]["talk"] = talk
            c["data"]["talk_at"] = at
            last = self._persisted.get(id)
            write = last is None or at - last >= PERSIST_EVERY
            if write:
                self._persisted[id] = at
        if write:
            self._persist(id)
