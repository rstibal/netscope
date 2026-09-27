# -*- coding: utf-8 -*-
"""
Persistent history — the part that survives closing the app.

Everything else in NetScope lives in memory and dies with the process. This
keeps hourly per-process rollups, first-seen records for every program and
host, and the alert log, so you can answer "what has this machine been doing
since Tuesday" and so "a program used the network for the first time" can mean
the first time *ever* rather than the first time since you launched the app.

Design constraint: the capture path must never wait on a disk write. Packets
accumulate in a plain dict under a short lock; a writer thread swaps the
accumulator out every few seconds and does the SQL. If the database is
unavailable the accumulator is simply discarded and capture carries on.
"""

from __future__ import annotations

import fnmatch
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

FLUSH_INTERVAL = 10.0          # seconds between disk writes
PRUNE_INTERVAL = 3600.0        # seconds between retention sweeps
DEFAULT_RETAIN_DAYS = 90
DEFAULT_ALERT_RETAIN_DAYS = 30

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS usage (
    day       TEXT    NOT NULL,
    hour      INTEGER NOT NULL,
    process   TEXT    NOT NULL,
    bytes_in  INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    packets   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, hour, process)
);
CREATE INDEX IF NOT EXISTS usage_day ON usage(day);

CREATE TABLE IF NOT EXISTS processes (
    name       TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    packets    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    host       TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    packets    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    severity TEXT NOT NULL,
    rule     TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT NOT NULL,
    process  TEXT,
    peer     TEXT
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS dhcp_leases (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    hostname   TEXT,
    server     TEXT,
    lease_secs INTEGER,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    ended   REAL,
    iface   TEXT,
    packets INTEGER NOT NULL DEFAULT 0,
    version TEXT
);
"""


def default_db_path():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        folder = os.path.join(base, "NetScope")
    else:
        folder = os.path.join(os.path.expanduser("~"), ".netscope")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError:
        folder = os.getcwd()
    return os.path.join(folder, "history.db")


# ---------------------------------------------------------------------------
# Small persistent settings, kept beside the history database
# ---------------------------------------------------------------------------


def settings_path():
    return os.path.join(os.path.dirname(default_db_path()), "settings.json")


def load_settings():
    try:
        import json
        with open(settings_path(), "r", encoding="utf-8") as fh:
            v = json.load(fh)
            return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def save_setting(key, value):
    """Remember a choice so it does not have to be made again every launch."""
    try:
        import json
        cur = load_settings()
        if cur.get(key) == value:
            return
        cur[key] = value
        folder = os.path.dirname(settings_path())
        os.makedirs(folder, exist_ok=True)
        tmp = settings_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, indent=1)
        os.replace(tmp, settings_path())
    except Exception:
        pass


def _day_hour(ts):
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d"), dt.hour


# ---------------------------------------------------------------------------
# Exclusions — programs and hosts the user asked not to have recorded
# ---------------------------------------------------------------------------

MAX_EXCLUDE = 100          # entries per list
MAX_PATTERN = 253          # the longest a DNS name can be


def clean_patterns(items):
    """Lower-cased, trimmed, de-duplicated, capped. Anything else is dropped."""
    out = []
    for x in items or []:
        if not isinstance(x, str):
            continue
        x = x.strip().lower()
        if x and len(x) <= MAX_PATTERN and x not in out:
            out.append(x)
    return out[:MAX_EXCLUDE]


def program_matches(pattern, name):
    """Exact name, or a * / ? wildcard: chrome.exe, chrome*."""
    name = (name or "").lower()
    return name == pattern or fnmatch.fnmatchcase(name, pattern)


def host_matches(pattern, host):
    """
    As program_matches, and a plain name also covers its subdomains, so
    example.com takes www.example.com with it — the way people mean a site.
    """
    host = (host or "").lower().rstrip(".")
    if host == pattern or fnmatch.fnmatchcase(host, pattern):
        return True
    return "*" not in pattern and "?" not in pattern and host.endswith("." + pattern)


class HistoryStore:
    def __init__(self, path=None, retain_days=DEFAULT_RETAIN_DAYS,
                 alert_retain_days=DEFAULT_ALERT_RETAIN_DAYS, enabled=True):
        self.path = path or default_db_path()
        self.retain_days = retain_days
        self.alert_retain_days = alert_retain_days
        self.enabled = enabled
        self.error = None
        self.session_id = None
        self.flushes = 0
        self.last_flush = 0.0

        self._acc = {}          # (day, hour, process) -> [in, out, packets]
        self._procs = {}        # name -> [first, last, in, out, packets]
        self._hosts = {}        # host -> [first, last, in, out, packets]
        self._pending_alerts = []
        self._pending_leases = []
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._db = None
        self._known_procs = set()
        self._known_hosts = set()
        self.was_empty = True
        self.exclude_programs = []
        self.exclude_hosts = []
        # Decisions per name, since record() runs for every packet and a
        # wildcard match per packet per pattern is not free. Rebuilt whenever
        # the lists change.
        self._ex_cache = {}

        if self.enabled:
            self._open()

    # -- lifecycle ----------------------------------------------------------

    def _open(self):
        try:
            self._db = sqlite3.connect(self.path, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            with self._db_lock:
                self._db.executescript(SCHEMA)
                self._db.commit()
                # Cache what we already know, so first-seen checks are a set
                # lookup on the hot path rather than a query per packet.
                self._known_procs = {r[0] for r in
                                     self._db.execute("SELECT name FROM processes")}
                self._known_hosts = {r[0] for r in
                                     self._db.execute("SELECT host FROM hosts")}
                # A fresh database has never seen anything, so every program
                # would look brand new. The first run is a baseline, not a
                # pile of alerts.
                self.was_empty = not self._known_procs and not self._known_hosts
        except Exception as exc:
            self.enabled = False
            self.error = f"{type(exc).__name__}: {exc}"
            self._db = None

    def start(self, iface=None, version=None):
        if not self.enabled:
            return
        try:
            with self._db_lock:
                cur = self._db.execute(
                    "INSERT INTO sessions(started, iface, version) VALUES (?,?,?)",
                    (time.time(), iface or "", version or ""))
                self.session_id = cur.lastrowid
                self._db.commit()
        except Exception:
            pass
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="history-writer")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if not self.enabled:
            return
        try:
            self.flush()
            with self._db_lock:
                if self.session_id:
                    self._db.execute("UPDATE sessions SET ended=? WHERE id=?",
                                     (time.time(), self.session_id))
                self._db.commit()
                self._db.close()
        except Exception:
            pass

    def _loop(self):
        last_prune = time.time()
        while not self._stop.wait(FLUSH_INTERVAL):
            try:
                self.flush()
                if time.time() - last_prune > PRUNE_INTERVAL:
                    self.prune()
                    last_prune = time.time()
            except Exception:
                pass

    # -- ingest (hot path — keep this cheap) --------------------------------

    def record(self, rec):
        if not self.enabled:
            return
        proc = rec.get("process") or "-"
        host = rec.get("rhost") or rec.get("remote") or ""
        size = rec.get("length", 0)
        ts = rec.get("ts", time.time())
        inbound = rec.get("dir") != "out"
        day, hour = _day_hour(ts)
        # An excluded program keeps only its name and first/last seen — the
        # new-program alert asks the database whether a program is new, so
        # dropping the name too would make it "new" every session. Its usage
        # goes, and so do the hosts it talked to. An excluded host is not
        # written at all: the name is the thing being kept private.
        proc_out = self.excluded_program(proc)
        host_out = proc_out or self.excluded_host(host)

        with self._lock:
            if not proc_out:
                slot = self._acc.get((day, hour, proc))
                if slot is None:
                    slot = self._acc[(day, hour, proc)] = [0, 0, 0]
                slot[0 if inbound else 1] += size
                slot[2] += 1

            for table, key, counts in ((self._procs, proc, not proc_out),
                                       (self._hosts, host if not host_out else "", True)):
                if not key:
                    continue
                row = table.get(key)
                if row is None:
                    row = table[key] = [ts, ts, 0, 0, 0]
                row[1] = ts
                if counts:
                    row[2 if inbound else 3] += size
                    row[4] += 1

    def record_alert(self, alert):
        if not self.enabled:
            return
        # A note-level alert about an excluded program or host is only a
        # record of activity ("chrome.exe connected to x, first time this
        # session") — the very thing excluded. Warnings and above are kept:
        # they are the security record, whoever they are about.
        if alert.get("severity", "info") == "info" and (
                self.excluded_program(alert.get("process"))
                or (alert.get("rule") == "new_host"
                    and self.excluded_host(alert.get("subject")))):
            return
        with self._lock:
            self._pending_alerts.append((
                alert.get("ts", time.time()), alert.get("severity", "info"),
                alert.get("rule", ""), alert.get("title", ""),
                alert.get("detail", ""), alert.get("process", ""),
                alert.get("peer", "")))

    def record_dhcp_lease(self, lease):
        """A completed lease (a DHCP ACK), queued for the next flush."""
        if not self.enabled:
            return
        with self._lock:
            self._pending_leases.append((
                lease.get("mac", ""), lease.get("ip", ""),
                lease.get("hostname", ""), lease.get("server", ""),
                lease.get("lease_secs"),
                lease.get("first_seen", time.time()),
                lease.get("last_seen", time.time())))

    # -- exclusions ---------------------------------------------------------

    def set_exclusions(self, programs=None, hosts=None):
        """
        Replace the lists. What is still waiting for the next flush and
        matches is dropped too — it would otherwise land on disk a few seconds
        after being excluded. What is already on disk stays until purge().
        """
        self.exclude_programs = clean_patterns(programs)
        self.exclude_hosts = clean_patterns(hosts)
        self._ex_cache = {}
        with self._lock:
            self._acc = {k: v for k, v in self._acc.items()
                         if not self.excluded_program(k[2])}
            for name, row in self._procs.items():
                if self.excluded_program(name):
                    row[2] = row[3] = row[4] = 0
            self._hosts = {k: v for k, v in self._hosts.items()
                           if not self.excluded_host(k)}

    def exclusions(self):
        return {"programs": list(self.exclude_programs),
                "hosts": list(self.exclude_hosts)}

    def excluded_program(self, name):
        if not self.exclude_programs or not name:
            return False
        key = ("p", name)
        hit = self._ex_cache.get(key)
        if hit is None:
            hit = any(program_matches(p, name) for p in self.exclude_programs)
            self._remember(key, hit)
        return hit

    def excluded_host(self, host):
        if not self.exclude_hosts or not host:
            return False
        key = ("h", host)
        hit = self._ex_cache.get(key)
        if hit is None:
            hit = any(host_matches(p, host) for p in self.exclude_hosts)
            self._remember(key, hit)
        return hit

    def _remember(self, key, hit):
        cache = self._ex_cache
        if len(cache) > 50000:          # a scan's worth of one-off IPs
            cache = self._ex_cache = {}
        cache[key] = hit

    def purge(self, kind, pattern):
        """
        Erase what is already recorded for one exclusion pattern. A program
        loses its usage and its note-level alerts; its name and first/last
        seen stay, for the same reason record() keeps them. A host loses its
        row and the note-level alerts that name it. Returns what went.

        The hosts an excluded program talked to in the past can't be told
        apart from anyone else's — the hosts table has no program column —
        so they stay; exclude the hosts too if that matters.
        """
        pattern = (clean_patterns([pattern]) or [None])[0]
        if not self.enabled or self._db is None or not pattern \
                or kind not in ("program", "host"):
            return {"usage": 0, "hosts": 0, "alerts": 0}
        match = program_matches if kind == "program" else host_matches
        gone = {"usage": 0, "hosts": 0, "alerts": 0}
        try:
            with self._db_lock:
                db = self._db
                if kind == "program":
                    names = [r[0] for r in db.execute("SELECT DISTINCT process FROM usage")
                             if match(pattern, r[0])]
                    for n in names:
                        gone["usage"] += db.execute(
                            "DELETE FROM usage WHERE process=?", (n,)).rowcount
                        db.execute("UPDATE processes SET bytes_in=0, bytes_out=0, "
                                   "packets=0 WHERE name=?", (n,))
                    ids = [r[0] for r in db.execute(
                        "SELECT id, process FROM alerts WHERE severity='info'")
                        if match(pattern, r[1])]
                else:
                    names = [r[0] for r in db.execute("SELECT host FROM hosts")
                             if match(pattern, r[0])]
                    for n in names:
                        gone["hosts"] += db.execute(
                            "DELETE FROM hosts WHERE host=?", (n,)).rowcount
                    ids = [r[0] for r in db.execute(
                        "SELECT id, detail FROM alerts WHERE severity='info' "
                        "AND rule='new_host'")
                        if any(match(pattern, w.strip(",.;:()'\""))
                               for w in (r[1] or "").split())]
                for i in ids:
                    gone["alerts"] += db.execute(
                        "DELETE FROM alerts WHERE id=?", (i,)).rowcount
                db.commit()
            if kind == "host":
                self._known_hosts = {h for h in self._known_hosts
                                     if not match(pattern, h)}
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        return gone

    # -- first-seen lookups -------------------------------------------------

    def known_process(self, name):
        return name in self._known_procs

    def known_host(self, host):
        # An excluded host is never written, so the database can't remember
        # it; one you named yourself isn't a first contact worth a warning.
        return host in self._known_hosts or self.excluded_host(host)

    def note_process(self, name):
        self._known_procs.add(name)

    def note_host(self, host):
        self._known_hosts.add(host)

    # -- flush --------------------------------------------------------------

    def flush(self):
        if not self.enabled or self._db is None:
            return
        with self._lock:
            acc, procs, hosts, alerts, leases = (
                self._acc, self._procs, self._hosts, self._pending_alerts,
                self._pending_leases)
            (self._acc, self._procs, self._hosts, self._pending_alerts,
             self._pending_leases) = {}, {}, {}, [], []
        if not (acc or procs or hosts or alerts or leases):
            return
        try:
            with self._db_lock:
                self._db.executemany(
                    "INSERT INTO usage(day,hour,process,bytes_in,bytes_out,packets) "
                    "VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(day,hour,process) DO UPDATE SET "
                    "bytes_in=bytes_in+excluded.bytes_in, "
                    "bytes_out=bytes_out+excluded.bytes_out, "
                    "packets=packets+excluded.packets",
                    [(d, h, p, v[0], v[1], v[2]) for (d, h, p), v in acc.items()])

                for table, col, data in (("processes", "name", procs),
                                         ("hosts", "host", hosts)):
                    self._db.executemany(
                        f"INSERT INTO {table}({col},first_seen,last_seen,"
                        f"bytes_in,bytes_out,packets) VALUES (?,?,?,?,?,?) "
                        f"ON CONFLICT({col}) DO UPDATE SET "
                        f"last_seen=max(last_seen,excluded.last_seen), "
                        f"first_seen=min(first_seen,excluded.first_seen), "
                        f"bytes_in=bytes_in+excluded.bytes_in, "
                        f"bytes_out=bytes_out+excluded.bytes_out, "
                        f"packets=packets+excluded.packets",
                        [(k, v[0], v[1], v[2], v[3], v[4]) for k, v in data.items()])

                if alerts:
                    self._db.executemany(
                        "INSERT INTO alerts(ts,severity,rule,title,detail,process,peer)"
                        " VALUES (?,?,?,?,?,?,?)", alerts)

                if leases:
                    self._db.executemany(
                        "INSERT INTO dhcp_leases(mac,ip,hostname,server,"
                        "lease_secs,first_seen,last_seen) VALUES (?,?,?,?,?,?,?) "
                        "ON CONFLICT(mac) DO UPDATE SET "
                        "ip=excluded.ip, "
                        "hostname=CASE WHEN excluded.hostname<>'' "
                        "THEN excluded.hostname ELSE dhcp_leases.hostname END, "
                        "server=excluded.server, "
                        "lease_secs=excluded.lease_secs, "
                        "last_seen=excluded.last_seen", leases)

                if self.session_id:
                    self._db.execute(
                        "UPDATE sessions SET packets=packets+? WHERE id=?",
                        (sum(v[2] for v in acc.values()), self.session_id))
                self._db.commit()
            self.flushes += 1
            self.last_flush = time.time()
            self._known_procs.update(procs)
            self._known_hosts.update(hosts)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def prune(self):
        if not self.enabled or self._db is None:
            return
        cutoff_day = (datetime.now() - timedelta(days=self.retain_days)).strftime("%Y-%m-%d")
        cutoff_ts = time.time() - self.alert_retain_days * 86400
        try:
            with self._db_lock:
                self._db.execute("DELETE FROM usage WHERE day < ?", (cutoff_day,))
                self._db.execute("DELETE FROM alerts WHERE ts < ?", (cutoff_ts,))
                self._db.execute("DELETE FROM sessions WHERE started < ?",
                                 (time.time() - self.retain_days * 86400,))
                self._db.commit()
        except Exception:
            pass

    # -- queries ------------------------------------------------------------

    def _q(self, sql, args=()):
        if not self.enabled or self._db is None:
            return []
        try:
            with self._db_lock:
                return [dict(r) for r in self._db.execute(sql, args)]
        except Exception:
            return []

    @staticmethod
    def _range_days(days):
        today = datetime.now().date()
        return [(today - timedelta(days=i)).strftime("%Y-%m-%d")
                for i in range(days - 1, -1, -1)]

    def daily(self, days=30):
        """Per-day totals, zero-filled so the chart has no missing columns."""
        wanted = self._range_days(days)
        rows = {r["day"]: r for r in self._q(
            "SELECT day, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
            "SUM(packets) AS packets FROM usage WHERE day >= ? GROUP BY day "
            "ORDER BY day", (wanted[0],))}
        return [rows.get(d, {"day": d, "bytes_in": 0, "bytes_out": 0, "packets": 0})
                for d in wanted]

    def hourly(self, day=None):
        day = day or datetime.now().strftime("%Y-%m-%d")
        rows = {r["hour"]: r for r in self._q(
            "SELECT hour, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
            "SUM(packets) AS packets FROM usage WHERE day = ? GROUP BY hour", (day,))}
        return [rows.get(h, {"hour": h, "bytes_in": 0, "bytes_out": 0, "packets": 0})
                for h in range(24)]

    def by_process(self, days=30, limit=15):
        since = self._range_days(days)[0]
        return self._q(
            "SELECT process AS name, SUM(bytes_in) AS bytes_in, "
            "SUM(bytes_out) AS bytes_out, SUM(packets) AS packets "
            "FROM usage WHERE day >= ? AND process <> '-' GROUP BY process "
            "ORDER BY (SUM(bytes_in)+SUM(bytes_out)) DESC LIMIT ?", (since, limit))

    def top_hosts(self, limit=15):
        return self._q(
            "SELECT host, first_seen, last_seen, bytes_in, bytes_out, packets "
            "FROM hosts ORDER BY (bytes_in+bytes_out) DESC LIMIT ?", (limit,))

    def new_hosts(self, days=7, limit=25):
        since = time.time() - days * 86400
        return self._q(
            "SELECT host, first_seen, last_seen, bytes_in, bytes_out, packets "
            "FROM hosts WHERE first_seen >= ? ORDER BY first_seen DESC LIMIT ?",
            (since, limit))

    def alert_history(self, days=30, limit=200):
        since = time.time() - days * 86400
        return self._q(
            "SELECT id, ts, severity, rule, title, detail, process, peer "
            "FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?", (since, limit))

    def dhcp_leases(self, limit=100):
        return self._q(
            "SELECT mac, ip, hostname, server, lease_secs, first_seen, last_seen "
            "FROM dhcp_leases ORDER BY last_seen DESC LIMIT ?", (limit,))

    def sessions(self, limit=20):
        return self._q(
            "SELECT id, started, ended, iface, packets, version FROM sessions "
            "ORDER BY started DESC LIMIT ?", (limit,))

    def summary(self):
        if not self.enabled:
            return {"enabled": False, "error": self.error}
        first = self._q("SELECT MIN(day) AS d FROM usage")
        totals = self._q("SELECT SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
                         "SUM(packets) AS packets FROM usage")
        counts = self._q("SELECT (SELECT COUNT(*) FROM processes) AS processes, "
                         "(SELECT COUNT(*) FROM hosts) AS hosts, "
                         "(SELECT COUNT(*) FROM alerts) AS alerts, "
                         "(SELECT COUNT(*) FROM sessions) AS sessions")
        # WAL mode keeps recent writes in a sidecar file until checkpoint, so
        # reporting only the main file understates what is on disk.
        size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                size += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        t = totals[0] if totals else {}
        return {
            "enabled": True,
            "path": self.path,
            "size": size,
            "since": (first[0]["d"] if first else None),
            "bytes_in": t.get("bytes_in") or 0,
            "bytes_out": t.get("bytes_out") or 0,
            "packets": t.get("packets") or 0,
            "retain_days": self.retain_days,
            "alert_retain_days": self.alert_retain_days,
            "flushes": self.flushes,
            "error": self.error,
            **(counts[0] if counts else {}),
        }

    def wipe(self):
        if not self.enabled or self._db is None:
            return
        with self._lock:
            (self._acc, self._procs, self._hosts, self._pending_alerts,
             self._pending_leases) = {}, {}, {}, [], []
        try:
            with self._db_lock:
                for t in ("usage", "processes", "hosts", "alerts",
                          "dhcp_leases", "sessions"):
                    self._db.execute(f"DELETE FROM {t}")
                self._db.commit()
                self._db.execute("VACUUM")
            self._known_procs.clear()
            self._known_hosts.clear()
            self.session_id = None
        except Exception:
            pass
