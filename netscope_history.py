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
from datetime import datetime, timedelta

from netscope_l2 import is_group_ip

FLUSH_INTERVAL = 10.0          # seconds between disk writes
PRUNE_INTERVAL = 3600.0        # seconds between retention sweeps
DEFAULT_RETAIN_DAYS = 90
DEFAULT_ALERT_RETAIN_DAYS = 30
# How long the check-in rule learns before it warns. It starts the first time
# NetScope sees a check-in, which on an existing database is the first run of
# 1.26.0: everything already on a schedule then is learned, not reported. A
# day, because an hourly check-in needs five hours to be recognised at all.
CHECKIN_BASELINE = 86400.0
# Distinct (hour, program, host) rows held between flushes. Past it, further
# hosts for that hour are folded into one "(other)" row, so a scan of a /16
# can't grow the batch without bound; the program's own totals stay exact.
MAX_PENDING_PAIRS = 20000
OTHER_HOSTS = "(other)"
# Alerts kept in memory if the database keeps refusing writes, so a full disk
# can't also fill the machine's memory.
MAX_PENDING_ALERTS = 5000
# The database layout. 2 (1.40.0) added coverage and reset the usage recorded
# before it, which had no record of which adapters were being captured. 3
# (1.41.0) put the adapter in the usage keys, so History can show one. 4
# (1.42.0) dropped coverage again: on a machine that is often shut down,
# how much of the day NetScope ran was never going to read 100%.
SCHEMA_VERSION = 4

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS usage (
    day       TEXT    NOT NULL,
    hour      INTEGER NOT NULL,
    process   TEXT    NOT NULL,
    iface     TEXT    NOT NULL DEFAULT '',
    bytes_in  INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    packets   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, hour, process, iface)
);
CREATE INDEX IF NOT EXISTS usage_day ON usage(day);

-- Which host each program talked to, per hour. usage and hosts are separate
-- tallies with no way to join them; this is what says why a program moved
-- N MB, and when. Recorded from 1.32.0 on, so older traffic has none.
CREATE TABLE IF NOT EXISTS usage_pairs (
    day       TEXT    NOT NULL,
    hour      INTEGER NOT NULL,
    process   TEXT    NOT NULL,
    host      TEXT    NOT NULL,
    iface     TEXT    NOT NULL DEFAULT '',
    bytes_in  INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    packets   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, hour, process, host, iface)
);
CREATE INDEX IF NOT EXISTS usage_pairs_host ON usage_pairs(host);
CREATE INDEX IF NOT EXISTS usage_pairs_day ON usage_pairs(day);

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
    peer     TEXT,
    subject  TEXT
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);

-- Program-and-host pairs seen contacting each other on a schedule, so the
-- check-in alert only reports a pair once, ever.
-- The files each program name was seen running from, so blocking it from an
-- alert still works after a restart when it is no longer running.
CREATE TABLE IF NOT EXISTS program_paths (
    name      TEXT NOT NULL,
    path      TEXT NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (name, path)
);

CREATE TABLE IF NOT EXISTS checkins (
    program    TEXT NOT NULL,
    host       TEXT NOT NULL,
    period     INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    PRIMARY KEY (program, host)
);

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


_settings_lock = threading.Lock()


def save_setting(key, value):
    """Remember a choice so it does not have to be made again every launch."""
    try:
        import json
        # Read-modify-write: two requests changing different settings at once
        # would otherwise each write back a file missing the other's change.
        with _settings_lock:
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


_dh_cache = (None, None)


def _day_hour(ts):
    # Called for every packet, and a second holds many of them.
    global _dh_cache
    sec = int(ts)
    if _dh_cache[0] == sec:
        return _dh_cache[1]
    dt = datetime.fromtimestamp(sec)
    out = (dt.strftime("%Y-%m-%d"), dt.hour)
    _dh_cache = (sec, out)
    return out


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


def schema_statements():
    """
    SCHEMA's CREATE statements one by one, without its PRAGMAs (which can't
    run inside a transaction) or comments (one has a semicolon in it), so a
    migration can rebuild tables in the same transaction as the rest.
    """
    body = "\n".join(l for l in SCHEMA.splitlines() if not l.strip().startswith("--"))
    return [x.strip() for x in body.split(";")
            if x.strip() and not x.strip().upper().startswith("PRAGMA")]


class HistoryStore:
    def __init__(self, path=None, retain_days=DEFAULT_RETAIN_DAYS,
                 alert_retain_days=DEFAULT_ALERT_RETAIN_DAYS, enabled=True):
        self.path = path or default_db_path()
        # ":memory:" is what demo mode uses: a working History tab for the
        # session, and nothing invented ever reaching the real database.
        self.in_memory = self.path == ":memory:"
        self.retain_days = retain_days
        self.alert_retain_days = alert_retain_days
        self.enabled = enabled
        self.error = None
        self.session_id = None
        self.flushes = 0
        self.last_flush = 0.0

        self._acc = {}          # (day, hour, process, iface) -> [in, out, packets]
        self._pairs = {}        # (day, hour, process, host, iface) -> [in, out, packets]
        self._procs = {}        # name -> [first, last, in, out, packets]
        self._hosts = {}        # host -> [first, last, in, out, packets]
        self._pending_alerts = []
        self._pending_leases = []
        # Where the pre-1.40 database was copied before its usage was reset,
        # for this run only, so the History tab can say so once.
        self.reset_backup = None
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._db = None
        self._known_procs = set()
        self._known_hosts = set()
        self._known_checkins = set()
        self._checkin_since = None
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
                # `subject` (what a mute is keyed on) arrived in 1.25.1; a
                # database from before has the table without it. Old rows stay
                # without one, so they can't be muted from the log.
                cols = {r[1] for r in self._db.execute("PRAGMA table_info(alerts)")}
                if "subject" not in cols:
                    self._db.execute("ALTER TABLE alerts ADD COLUMN subject TEXT")
                self._db.commit()
                self._migrate()
                # Cache what we already know, so first-seen checks are a set
                # lookup on the hot path rather than a query per packet.
                self._known_procs = {r[0] for r in
                                     self._db.execute("SELECT name FROM processes")}
                self._known_hosts = {r[0] for r in
                                     self._db.execute("SELECT host FROM hosts")}
                self._known_checkins = {(r[0], r[1]) for r in self._db.execute(
                    "SELECT program, host FROM checkins")}
                self._checkin_since = self._db.execute(
                    "SELECT MIN(first_seen) FROM checkins").fetchone()[0]
                # A fresh database has never seen anything, so every program
                # would look brand new. The first run is a baseline, not a
                # pile of alerts.
                self.was_empty = not self._known_procs and not self._known_hosts
        except Exception as exc:
            self.enabled = False
            self.error = f"{type(exc).__name__}: {exc}"
            self._db = None

    def _migrate(self):
        """
        Bring an older database up to SCHEMA_VERSION. Called with _db_lock held.

        To 2: usage from before 1.40 is erased. It was recorded with no note
        of which adapters were being captured, so a day with the dropdown on
        one adapter looked like a quiet day, and there is no way to tell them
        apart afterwards. The file is copied first (history.db.before-1.40).
        Known programs and hosts, check-ins, alerts, leases and paths stay, so
        nothing is "new" again and the alert log, the security record, is
        intact. The all-time byte counters on programs and hosts go to zero.
        """
        v = self._db.execute("PRAGMA user_version").fetchone()[0]
        if v >= SCHEMA_VERSION:
            return
        had = self._db.execute("SELECT EXISTS(SELECT 1 FROM usage) "
                               "OR EXISTS(SELECT 1 FROM sessions)").fetchone()[0]
        backup = None
        if v < 2 and had and not self.in_memory:
            backup = self.path + ".before-1.40"
            if not os.path.exists(backup):
                dst = sqlite3.connect(backup)
                try:
                    self._db.backup(dst)
                finally:
                    dst.close()
        # Every step below in one transaction: executescript() commits as it
        # goes, so a failure between renaming the old tables and copying them
        # left new, empty ones beside them. The next open saw the new shape,
        # never copied, and the old usage was stranded in usage_old for good.
        self._db.commit()
        self._db.execute("BEGIN")
        try:
            self._migrate_steps(v, had)
            self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        self.reset_backup = backup

    def _migrate_steps(self, v, had):
        if v < 2 and had:
            for t in ("usage", "usage_pairs", "sessions"):
                self._db.execute(f"DELETE FROM {t}")
            for t in ("processes", "hosts"):
                self._db.execute(f"UPDATE {t} SET bytes_in=0, bytes_out=0, packets=0")
        # To 3: the adapter joins the usage keys. SQLite can't change a
        # primary key in place, so the two tables are rebuilt; rows from
        # before carry no adapter ('') and count under "All adapters" only.
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(usage)")}
        if "iface" not in cols:
            for t in ("usage", "usage_pairs"):
                self._db.execute(f"ALTER TABLE {t} RENAME TO {t}_old")
            for stmt in schema_statements():
                self._db.execute(stmt)
            self._db.execute(
                "INSERT INTO usage(day,hour,process,iface,bytes_in,bytes_out,packets) "
                "SELECT day,hour,process,'',bytes_in,bytes_out,packets FROM usage_old")
            self._db.execute(
                "INSERT INTO usage_pairs(day,hour,process,host,iface,bytes_in,bytes_out,"
                "packets) SELECT day,hour,process,host,'',bytes_in,bytes_out,packets "
                "FROM usage_pairs_old")
            for t in ("usage", "usage_pairs"):
                self._db.execute(f"DROP TABLE {t}_old")
            for stmt in schema_statements():    # the indexes went with the old tables
                self._db.execute(stmt)
        # To 4: the record of how long NetScope ran (1.40-1.41) goes.
        self._db.execute("DROP TABLE IF EXISTS coverage")
        self._db.execute("DROP TABLE IF EXISTS meta")

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
        # Multicast and broadcast are one packet to everyone listening, not
        # traffic with a host. The program's usage still counts it.
        if is_group_ip(rec.get("dst")):
            host = ""
        size = rec.get("length", 0)
        ts = rec.get("ts", time.time())
        iface = rec.get("iface") or ""
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
                slot = self._acc.get((day, hour, proc, iface))
                if slot is None:
                    slot = self._acc[(day, hour, proc, iface)] = [0, 0, 0]
                slot[0 if inbound else 1] += size
                slot[2] += 1
                if host and not host_out:
                    pk = (day, hour, proc, host, iface)
                    ps = self._pairs.get(pk)
                    if ps is None:
                        if len(self._pairs) >= MAX_PENDING_PAIRS:
                            pk = (day, hour, proc, OTHER_HOSTS, iface)
                        ps = self._pairs.setdefault(pk, [0, 0, 0])
                    ps[0 if inbound else 1] += size
                    ps[2] += 1

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
                alert.get("peer", ""), alert.get("subject") or None))

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
            self._pairs = {k: v for k, v in self._pairs.items()
                           if not self.excluded_program(k[2])
                           and not self.excluded_host(k[3])}
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

        By host is read from the per-host breakdown (usage_pairs), so a
        purged program's traffic leaves its hosts' totals too. The hosts it
        contacted stay known (first seen), so they don't count as new.
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
                        db.execute("DELETE FROM usage_pairs WHERE process=?", (n,))
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
                    for n in [r[0] for r in db.execute(
                            "SELECT DISTINCT host FROM usage_pairs")
                            if match(pattern, r[0])]:
                        db.execute("DELETE FROM usage_pairs WHERE host=?", (n,))
                    ids = [r[0] for r in db.execute(
                        "SELECT id, detail FROM alerts WHERE severity='info' "
                        "AND rule='new_host'")
                        if any(match(pattern, w.strip(",.;:()'\""))
                               for w in (r[1] or "").split())]
                for i in ids:
                    gone["alerts"] += db.execute(
                        "DELETE FROM alerts WHERE id=?", (i,)).rowcount
                col = "program" if kind == "program" else "host"
                for (p, h) in list(self._known_checkins):
                    if match(pattern, p if kind == "program" else h):
                        db.execute(f"DELETE FROM checkins WHERE {col}=?",
                                   (p if kind == "program" else h,))
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

    def process_first_seen(self, name):
        """When a program first used the network, or None if never recorded."""
        r = self._q("SELECT first_seen FROM processes WHERE name=?", (name,))
        return r[0]["first_seen"] if r else None

    def known_checkin(self, program, host):
        # An excluded host isn't stored, so it can't be remembered; like
        # known_host(), one you named yourself isn't news.
        return (program, host) in self._known_checkins or self.excluded_host(host)

    def checkin_baselining(self):
        """True while the check-in rule is still learning this machine."""
        return (self._checkin_since is None or
                time.time() < self._checkin_since + CHECKIN_BASELINE)

    def note_checkin(self, program, host, period):
        """Remember a scheduled pair. Written at once: they are rare."""
        self._known_checkins.add((program, host))
        now = time.time()
        if self._checkin_since is None:
            self._checkin_since = now
        if (not self.enabled or self._db is None or self.excluded_host(host)
                or self.excluded_program(program)):
            return
        try:
            with self._db_lock:
                self._db.execute(
                    "INSERT INTO checkins(program,host,period,first_seen,last_seen) "
                    "VALUES (?,?,?,?,?) ON CONFLICT(program,host) DO UPDATE SET "
                    "period=excluded.period, last_seen=excluded.last_seen",
                    (program, host, int(period), now, now))
                self._db.commit()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def note_host(self, host):
        self._known_hosts.add(host)

    def note_path(self, name, path):
        """Remember a program's file. Written at once: a pair is new rarely."""
        if not self.enabled or self._db is None or not name or not path:
            return
        try:
            with self._db_lock:
                self._db.execute(
                    "INSERT INTO program_paths(name, path, last_seen) VALUES (?,?,?) "
                    "ON CONFLICT(name, path) DO UPDATE SET last_seen=excluded.last_seen",
                    (str(name).lower(), str(path), time.time()))
                self._db.commit()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def known_paths(self, name):
        return {r["path"] for r in self._q(
            "SELECT path FROM program_paths WHERE name=?", (str(name or "").lower(),))}

    # -- flush --------------------------------------------------------------

    def flush(self):
        if not self.enabled or self._db is None:
            return
        with self._lock:
            acc, procs, hosts, alerts, leases, pairs = (
                self._acc, self._procs, self._hosts, self._pending_alerts,
                self._pending_leases, self._pairs)
            (self._acc, self._procs, self._hosts, self._pending_alerts,
             self._pending_leases, self._pairs) = {}, {}, {}, [], [], {}
        if not (acc or procs or hosts or alerts or leases or pairs):
            return
        try:
            with self._db_lock:
                self._db.executemany(
                    "INSERT INTO usage(day,hour,process,iface,bytes_in,bytes_out,packets) "
                    "VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(day,hour,process,iface) DO UPDATE SET "
                    "bytes_in=bytes_in+excluded.bytes_in, "
                    "bytes_out=bytes_out+excluded.bytes_out, "
                    "packets=packets+excluded.packets",
                    [(d, h, p, i, v[0], v[1], v[2]) for (d, h, p, i), v in acc.items()])

                if pairs:
                    self._db.executemany(
                        "INSERT INTO usage_pairs(day,hour,process,host,iface,bytes_in,"
                        "bytes_out,packets) VALUES (?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(day,hour,process,host,iface) DO UPDATE SET "
                        "bytes_in=bytes_in+excluded.bytes_in, "
                        "bytes_out=bytes_out+excluded.bytes_out, "
                        "packets=packets+excluded.packets",
                        [(d, h, p, ho, i, v[0], v[1], v[2])
                         for (d, h, p, ho, i), v in pairs.items()])

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
                        "INSERT INTO alerts(ts,severity,rule,title,detail,process,"
                        "peer,subject) VALUES (?,?,?,?,?,?,?,?)", alerts)

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
            # Nothing from this batch reached the disk, and a half-applied
            # transaction would be committed by whatever writes next. Undo it
            # and put the batch back for the next flush.
            try:
                with self._db_lock:
                    self._db.rollback()
            except Exception:
                pass
            self._requeue(acc, procs, hosts, alerts, leases, pairs)

    def _requeue(self, acc, procs, hosts, alerts, leases, pairs=()):
        with self._lock:
            for k, v in dict(pairs).items():
                slot = self._pairs.setdefault(k, [0, 0, 0])
                for i in range(3):
                    slot[i] += v[i]
            for k, v in acc.items():
                slot = self._acc.setdefault(k, [0, 0, 0])
                for i in range(3):
                    slot[i] += v[i]
            for table, data in ((self._procs, procs), (self._hosts, hosts)):
                for k, v in data.items():
                    row = table.get(k)
                    if row is None:
                        table[k] = v
                    else:
                        row[0] = min(row[0], v[0])
                        row[1] = max(row[1], v[1])
                        for i in (2, 3, 4):
                            row[i] += v[i]
            self._pending_alerts[:0] = alerts
            self._pending_leases[:0] = leases
            extra = len(self._pending_alerts) - MAX_PENDING_ALERTS
            if extra > 0:
                del self._pending_alerts[:extra]
            extra = len(self._pending_leases) - MAX_PENDING_ALERTS
            if extra > 0:
                del self._pending_leases[:extra]

    def prune(self):
        if not self.enabled or self._db is None:
            return
        cutoff_day = (datetime.now() - timedelta(days=self.retain_days)).strftime("%Y-%m-%d")
        cutoff_ts = time.time() - self.alert_retain_days * 86400
        try:
            with self._db_lock:
                self._db.execute("DELETE FROM usage WHERE day < ?", (cutoff_day,))
                self._db.execute("DELETE FROM usage_pairs WHERE day < ?", (cutoff_day,))
                self._db.execute("DELETE FROM alerts WHERE ts < ?", (cutoff_ts,))
                self._db.execute("DELETE FROM sessions WHERE started < ?",
                                 (time.time() - self.retain_days * 86400,))
                self._db.execute("DELETE FROM program_paths WHERE last_seen < ?",
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

    @staticmethod
    def _on(iface, col="iface"):
        """(" AND col = ?", [iface]) for one adapter; nothing for all of them."""
        return (f" AND {col} = ?", [iface]) if iface else ("", [])

    def daily(self, days=30, iface=""):
        """Per-day totals, zero-filled so the chart has no missing columns."""
        wanted = self._range_days(days)
        w, a = self._on(iface)
        rows = {r["day"]: r for r in self._q(
            "SELECT day, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
            "SUM(packets) AS packets FROM usage WHERE day >= ?" + w + " GROUP BY day "
            "ORDER BY day", [wanted[0]] + a)}
        return [dict(rows.get(d) or {"day": d, "bytes_in": 0, "bytes_out": 0, "packets": 0})
                for d in wanted]

    def by_process(self, days=30, limit=15, iface=""):
        since = self._range_days(days)[0]
        w, a = self._on(iface)
        rows = self._q(
            "SELECT process AS name, SUM(bytes_in) AS bytes_in, "
            "SUM(bytes_out) AS bytes_out, SUM(packets) AS packets "
            "FROM usage WHERE day >= ? AND process <> '-'" + w + " GROUP BY process "
            "ORDER BY (SUM(bytes_in)+SUM(bytes_out)) DESC LIMIT ?", [since] + a + [limit])
        return self._with_trend(rows, "name", "usage", "process", days, iface)

    def _with_trend(self, rows, key, table, col, days, iface=""):
        """
        Each row's bytes per day across the range, as `trend`, one number per
        day of _range_days(days). A total alone can't say whether 40 GB was
        steady use or one download; the page draws this beside the bar.
        """
        names = [r[key] for r in rows]
        if not names:
            return rows
        wanted = self._range_days(days)
        pos = {d: i for i, d in enumerate(wanted)}
        w, a = self._on(iface)
        marks = ",".join("?" * len(names))
        per = {n: [0] * len(wanted) for n in names}
        for r in self._q(
                f"SELECT {col} AS n, day, SUM(bytes_in+bytes_out) AS b FROM {table} "
                f"WHERE day >= ? AND {col} IN ({marks})" + w + f" GROUP BY {col}, day",
                [wanted[0]] + names + a):
            i = pos.get(r["day"])
            if i is not None and r["n"] in per:
                per[r["n"]][i] = r["b"] or 0
        for r in rows:
            r["trend"] = per.get(r[key], [])
        return rows

    def day_detail(self, day, iface="", limit=8):
        """
        One day of the daily chart, opened: its 24 hours, and the programs and
        hosts that made it. What a tall bar is made of, without guessing.
        """
        w, a = self._on(iface)
        hours = {r["hour"]: r for r in self._q(
            "SELECT hour, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out "
            "FROM usage WHERE day = ?" + w + " GROUP BY hour", [day] + a)}
        programs = self._q(
            "SELECT process AS name, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
            "SUM(packets) AS packets FROM usage WHERE day = ? AND process <> '-'" + w +
            " GROUP BY process ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT ?",
            [day] + a + [limit])
        hosts = self._q(
            "SELECT host, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
            "SUM(packets) AS packets FROM usage_pairs WHERE day = ?" + w +
            " GROUP BY host ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT ?",
            [day] + a + [limit])
        return {"day": day, "iface": iface,
                "hours": [{"hour": h, "bytes_in": (hours.get(h) or {}).get("bytes_in") or 0,
                           "bytes_out": (hours.get(h) or {}).get("bytes_out") or 0}
                          for h in range(24)],
                "programs": programs, "hosts": hosts}

    def pairs_since(self):
        """First day with a per-host breakdown, or None if none is recorded."""
        r = self._q("SELECT MIN(day) AS d FROM usage_pairs")
        return r[0]["d"] if r and r[0]["d"] else None

    def detail(self, kind, name, days=30, limit=8, iface=""):
        """
        Why a program or host has the bytes it has. A program: the hosts it
        talked to, its last 72 hours hour by hour, and its busiest hours with
        the main host in each. A host: the programs that contacted it.
        `unlisted` is a program's traffic in the period with no host recorded
        (before 1.32.0, or past `limit`), so the parts add up to the whole.
        """
        since = self._range_days(days)[0]
        w, a = self._on(iface)
        out = {"kind": kind, "name": name, "days": days, "iface": iface,
               "pairs_since": self.pairs_since(), "rows": [], "unlisted": 0,
               "total": 0, "hours": [], "busiest": []}
        if kind == "program":
            tot = self._q("SELECT SUM(bytes_in+bytes_out) AS t FROM usage "
                          "WHERE day >= ? AND process = ?" + w, [since, name] + a)
            out["total"] = (tot[0]["t"] or 0) if tot else 0
            out["rows"] = self._q(
                "SELECT host AS name, SUM(bytes_in) AS bytes_in, "
                "SUM(bytes_out) AS bytes_out, SUM(packets) AS packets "
                "FROM usage_pairs WHERE day >= ? AND process = ?" + w + " GROUP BY host "
                "ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT ?", [since, name] + a + [limit])
            now = datetime.now().replace(minute=0, second=0, microsecond=0)
            slots = [now - timedelta(hours=i) for i in range(71, -1, -1)]
            have = {(r["day"], r["hour"]): r for r in self._q(
                "SELECT day, hour, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out "
                "FROM usage WHERE process = ? AND day >= ?" + w + " GROUP BY day, hour",
                [name, slots[0].strftime("%Y-%m-%d")] + a)}
            for t in slots:
                r = have.get((t.strftime("%Y-%m-%d"), t.hour))
                out["hours"].append({"day": t.strftime("%Y-%m-%d"), "hour": t.hour,
                                     "bytes_in": r["bytes_in"] if r else 0,
                                     "bytes_out": r["bytes_out"] if r else 0})
            busy = self._q(
                "SELECT day, hour, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out "
                "FROM usage WHERE day >= ? AND process = ?" + w + " GROUP BY day, hour "
                "ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT 5", [since, name] + a)
            for b in busy:
                top = self._q(
                    "SELECT host FROM usage_pairs WHERE day = ? AND hour = ? AND "
                    "process = ?" + w + " GROUP BY host "
                    "ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT 1",
                    [b["day"], b["hour"], name] + a)
                b["host"] = top[0]["host"] if top else ""
            out["busiest"] = busy
            listed = sum(r["bytes_in"] + r["bytes_out"] for r in out["rows"])
            out["unlisted"] = max(0, out["total"] - listed)
        else:
            tot = self._q("SELECT SUM(bytes_in+bytes_out) AS t FROM usage_pairs "
                          "WHERE day >= ? AND host = ?" + w, [since, name] + a)
            out["total"] = (tot[0]["t"] or 0) if tot else 0
            out["rows"] = self._q(
                "SELECT process AS name, SUM(bytes_in) AS bytes_in, "
                "SUM(bytes_out) AS bytes_out, SUM(packets) AS packets "
                "FROM usage_pairs WHERE day >= ? AND host = ?" + w + " GROUP BY process "
                "ORDER BY SUM(bytes_in+bytes_out) DESC LIMIT ?", [since, name] + a + [limit])
        return out

    def by_host(self, days=30, limit=15, iface=""):
        """Hosts by traffic in the range, from the per-hour breakdown."""
        since = self._range_days(days)[0]
        w, a = self._on(iface, "p.iface")
        rows = self._q(
            "SELECT p.host AS host, SUM(p.bytes_in) AS bytes_in, "
            "SUM(p.bytes_out) AS bytes_out, SUM(p.packets) AS packets, "
            "h.first_seen AS first_seen FROM usage_pairs p "
            "LEFT JOIN hosts h ON h.host = p.host WHERE p.day >= ?" + w +
            " GROUP BY p.host ORDER BY SUM(p.bytes_in+p.bytes_out) DESC LIMIT ?",
            [since] + a + [limit])
        return self._with_trend(rows, "host", "usage_pairs", "host", days, iface)

    def new_hosts(self, days=7, limit=25, iface=""):
        """
        Hosts first contacted in the range, with their traffic in it. For one
        adapter, only hosts that had traffic on it.
        """
        since_day = self._range_days(days)[0]
        since = datetime.strptime(since_day, "%Y-%m-%d").timestamp()
        w, a = self._on(iface, "p.iface")
        return self._q(
            "SELECT h.host AS host, h.first_seen AS first_seen, "
            "COALESCE(SUM(p.bytes_in), 0) AS bytes_in, "
            "COALESCE(SUM(p.bytes_out), 0) AS bytes_out FROM hosts h "
            "LEFT JOIN usage_pairs p ON p.host = h.host AND p.day >= ?" + w +
            " WHERE h.first_seen >= ? GROUP BY h.host" +
            (" HAVING COUNT(p.host) > 0" if iface else "") +
            " ORDER BY h.first_seen DESC LIMIT ?", [since_day] + a + [since, limit])

    def ifaces(self):
        """Every adapter History has usage for, busiest first."""
        rows = self._q(
            "SELECT iface, SUM(bytes_in+bytes_out) AS n FROM usage WHERE iface <> '' "
            "GROUP BY iface ORDER BY n DESC, iface")
        return [r["iface"] for r in rows]

    def range_totals(self, days=30, iface=""):
        """What the range adds up to, read from the same rows as its charts."""
        since = self._range_days(days)[0]
        w, a = self._on(iface)
        t = self._q("SELECT SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, "
                    "SUM(packets) AS packets, COUNT(DISTINCT CASE WHEN process <> '-' "
                    "THEN process END) AS programs FROM usage WHERE day >= ?" + w,
                    [since] + a)
        n = self._q("SELECT COUNT(DISTINCT host) AS hosts FROM usage_pairs "
                    "WHERE day >= ? AND host <> ?" + w, [since, OTHER_HOSTS] + a)
        t = t[0] if t else {}
        return {"bytes_in": t.get("bytes_in") or 0, "bytes_out": t.get("bytes_out") or 0,
                "packets": t.get("packets") or 0, "programs": t.get("programs") or 0,
                "hosts": (n[0]["hosts"] if n else 0) or 0}

    def alert_log(self, before=None, after=None, limit=100):
        """
        Logged alerts, newest first, as (rows, more). `before` pages back from
        an id; `after` returns only ids newer than one the caller already has.
        Ids, not timestamps: two alerts can share a timestamp, and a page
        boundary between them would drop one.
        """
        where, args = [], []
        if before is not None:
            where.append("id < ?")
            args.append(int(before))
        if after is not None:
            where.append("id > ?")
            args.append(int(after))
        rows = self._q(
            "SELECT id, ts, severity, rule, title, detail, process, peer, subject "
            "FROM alerts" + (" WHERE " + " AND ".join(where) if where else "") +
            " ORDER BY id DESC LIMIT ?", args + [int(limit) + 1])
        return rows[:limit], len(rows) > limit

    def totals(self):
        """
        Totals per program and per host over everything kept (the retention
        period), for export: the same rows the History tab reads, with when
        each was first and last seen.
        """
        return self._q(
            "SELECT * FROM ("
            "SELECT 'program' AS kind, u.process AS name, pr.first_seen, pr.last_seen, "
            "SUM(u.bytes_in) AS bytes_in, SUM(u.bytes_out) AS bytes_out, "
            "SUM(u.packets) AS packets FROM usage u "
            "LEFT JOIN processes pr ON pr.name = u.process "
            "WHERE u.process <> '-' GROUP BY u.process "
            "UNION ALL SELECT 'host' AS kind, p.host AS name, h.first_seen, h.last_seen, "
            "SUM(p.bytes_in), SUM(p.bytes_out), SUM(p.packets) FROM usage_pairs p "
            "LEFT JOIN hosts h ON h.host = p.host GROUP BY p.host"
            ") ORDER BY kind DESC, (bytes_in + bytes_out) DESC")

    def all_alerts(self):
        """Every logged alert, oldest first, for export."""
        return self._q("SELECT id, ts, severity, rule, title, detail, process, peer, "
                       "subject FROM alerts ORDER BY id")

    def alert_counts(self, days=None):
        """{"total", "high", "warn", "info", "newest"} over `days`, or all kept."""
        since = 0 if days is None else time.time() - days * 86400
        out = {"total": 0, "high": 0, "warn": 0, "info": 0}
        for r in self._q("SELECT severity, COUNT(*) AS n FROM alerts WHERE ts >= ? "
                         "GROUP BY severity", (since,)):
            out[r["severity"]] = r["n"]
            out["total"] += r["n"]
        top = self._q("SELECT MAX(id) AS m FROM alerts")
        out["newest"] = (top[0]["m"] if top else None) or 0
        return out

    def dhcp_leases(self, limit=100):
        return self._q(
            "SELECT mac, ip, hostname, server, lease_secs, first_seen, last_seen "
            "FROM dhcp_leases ORDER BY last_seen DESC LIMIT ?", (limit,))

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
            "path": ("in memory only — demo traffic is never written to disk"
                     if self.in_memory else self.path),
            "size": size,
            "since": (first[0]["d"] if first else None),
            "bytes_in": t.get("bytes_in") or 0,
            "bytes_out": t.get("bytes_out") or 0,
            "packets": t.get("packets") or 0,
            "retain_days": self.retain_days,
            "alert_retain_days": self.alert_retain_days,
            "flushes": self.flushes,
            "error": self.error,
            "reset_backup": self.reset_backup,
            **(counts[0] if counts else {}),
        }

    def wipe(self):
        if not self.enabled or self._db is None:
            return
        with self._lock:
            (self._acc, self._procs, self._hosts, self._pending_alerts,
             self._pending_leases, self._pairs) = {}, {}, {}, [], [], {}
        try:
            with self._db_lock:
                for t in ("usage", "usage_pairs", "processes", "hosts", "alerts",
                          "dhcp_leases", "sessions", "checkins", "program_paths"):
                    self._db.execute(f"DELETE FROM {t}")
                self._db.commit()
                self._db.execute("VACUUM")
            self._known_procs.clear()
            self._known_hosts.clear()
            self._known_checkins.clear()
            self._checkin_since = None
            self.session_id = None
        except Exception:
            pass
