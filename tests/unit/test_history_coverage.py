"""
History since 1.40/1.41/1.42: every figure follows the chosen range, usage
is kept per adapter so History can show one, usage from before 1.40 (with no
record of what was captured) is reset once, after copying the file, and the
1.40-1.41 record of how long NetScope ran is gone.
"""
import os, sqlite3, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_history as H

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def q(h, sql):
    with h._db_lock:
        return [tuple(r) for r in h._db.execute(sql)]

def pkt(proc, host, n=100, ts=None, out=True, iface="Ethernet"):
    return {"process": proc, "rhost": host, "remote": "203.0.113.9", "length": n,
            "dir": "out" if out else "in", "ts": ts or time.time(), "iface": iface}

# The usage tables as they were before 1.41: no adapter in the key.
OLD_USAGE = """
CREATE TABLE usage (day TEXT NOT NULL, hour INTEGER NOT NULL, process TEXT NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, hour, process));
CREATE INDEX usage_day ON usage(day);
CREATE TABLE usage_pairs (day TEXT NOT NULL, hour INTEGER NOT NULL, process TEXT NOT NULL,
    host TEXT NOT NULL, bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, hour, process, host));
"""

def old_db(version):
    path = os.path.join(tempfile.mkdtemp(prefix="ns-cov-"), "history.db")
    old = sqlite3.connect(path)
    old.executescript(OLD_USAGE)
    old.executescript(H.SCHEMA)          # every other table, as it is now
    today = time.strftime("%Y-%m-%d")
    old.execute("INSERT INTO usage VALUES (?, 9, 'chrome.exe', 500, 50, 5)", (today,))
    old.execute("INSERT INTO usage_pairs VALUES (?, 9, 'chrome.exe', 'a.example', 500, 50, 5)", (today,))
    old.execute("INSERT INTO processes VALUES ('chrome.exe', 1, 2, 500, 50, 5)")
    old.execute("INSERT INTO hosts VALUES ('a.example', 1, 2, 500, 50, 5)")
    old.execute("INSERT INTO sessions(started, iface, packets) VALUES (1, 'Wi-Fi', 5)")
    old.execute("INSERT INTO alerts(ts, severity, rule, title, detail) VALUES (1, 'warn', 'x', 't', 'd')")
    old.execute("INSERT INTO checkins VALUES ('chrome.exe', 'a.example', 60, 1, 2)")
    old.execute(f"PRAGMA user_version={version}")
    old.commit(); old.close()
    return path

# -- the one-time reset of a database from before 1.40 ------------------------------
path = old_db(0)
h = H.HistoryStore(path=path)
check("an older database is copied before anything is erased",
      h.reset_backup == path + ".before-1.40" and os.path.exists(h.reset_backup), h.reset_backup)
bk = sqlite3.connect(h.reset_backup)
check("...and the copy has the old usage in it",
      bk.execute("SELECT COUNT(*) FROM usage").fetchone()[0] == 1)
bk.close()
check("usage, the per-host breakdown and sessions are reset",
      q(h, "SELECT (SELECT COUNT(*) FROM usage), (SELECT COUNT(*) FROM usage_pairs), "
           "(SELECT COUNT(*) FROM sessions)") == [(0, 0, 0)])
check("known programs and hosts stay known, so nothing is new again",
      h.known_process("chrome.exe") and h.known_host("a.example") and not h.was_empty)
check("...with their all-time byte counts zeroed",
      q(h, "SELECT bytes_in, bytes_out FROM processes") == [(0, 0)])
check("the alert log and check-ins are kept",
      q(h, "SELECT (SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM checkins)") == [(1, 1)])
check("the summary says so, for the tab", h.summary()["reset_backup"] == h.reset_backup)
check("the usage tables now key on the adapter",
      "iface" in {r[1] for r in q(h, "PRAGMA table_info(usage)")}
      and "iface" in {r[1] for r in q(h, "PRAGMA table_info(usage_pairs)")})
check("...and keep their day index", ("usage_day",) in q(h, "SELECT name FROM sqlite_master WHERE type='index'"))
h.record(pkt("chrome.exe", "a.example")); h.flush(); h.stop()

h = H.HistoryStore(path=path)
check("the reset happens once: reopening keeps new usage",
      h.reset_backup is None and q(h, "SELECT iface FROM usage") == [("Ethernet",)])
h.stop()

# -- from 1.40 to 1.41: nothing erased, the rows just gain an adapter column -------
path = old_db(2)
h = H.HistoryStore(path=path)
check("a 1.40 database is not reset or copied",
      h.reset_backup is None and not os.path.exists(path + ".before-1.40"))
check("...its rows are kept, with no adapter",
      q(h, "SELECT process, iface, bytes_in FROM usage") == [("chrome.exe", "", 500)]
      and q(h, "SELECT host, iface FROM usage_pairs") == [("a.example", "")])
check("...counted under every adapter, but no single one",
      h.range_totals(7)["bytes_in"] == 500 and h.range_totals(7, "Ethernet")["bytes_in"] == 0)
check("...and the version is current", q(h, "PRAGMA user_version") == [(H.SCHEMA_VERSION,)])
h.stop()

# -- a migration that fails part-way changes nothing ----------------------------------
path = old_db(2)
raw = sqlite3.connect(path)
raw.execute("CREATE TABLE usage_pairs_old (x)")      # the second rename will fail
raw.commit(); raw.close()
h = H.HistoryStore(path=path)
check("a failed migration is reported", not h.enabled or h.error, h.error)
h.stop()
raw = sqlite3.connect(path)
check("...and rolled back: the old usage is where it was, version unchanged",
      raw.execute("SELECT process, bytes_in FROM usage").fetchall() == [("chrome.exe", 500)]
      and "iface" not in {r[1] for r in raw.execute("PRAGMA table_info(usage)")}
      and raw.execute("PRAGMA user_version").fetchone()[0] == 2)
raw.execute("DROP TABLE usage_pairs_old"); raw.commit(); raw.close()
h = H.HistoryStore(path=path)
check("...so the next open migrates it in full",
      q(h, "SELECT process, iface, bytes_in FROM usage") == [("chrome.exe", "", 500)], h.error)
h.stop()

fresh = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-cov-"), "h.db"))
check("a new database needs no reset and no copy",
      fresh.reset_backup is None and q(fresh, "PRAGMA user_version") == [(H.SCHEMA_VERSION,)])

# -- from 1.41 to 1.42: the coverage record goes, usage stays ------------------------
path = os.path.join(tempfile.mkdtemp(prefix="ns-cov-"), "history.db")
h = H.HistoryStore(path=path)
h.record(pkt("chrome.exe", "a.example")); h.flush(); h.stop()
old = sqlite3.connect(path)
old.executescript("""
CREATE TABLE coverage (day TEXT, hour INTEGER, iface TEXT, state TEXT, seconds REAL,
    PRIMARY KEY (day, hour, iface, state));
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
INSERT INTO coverage VALUES ('2026-10-30', 9, '*', 'running', 3600);
INSERT INTO meta VALUES ('coverage_start', '1.8e9');
PRAGMA user_version=3;""")
old.commit(); old.close()
h = H.HistoryStore(path=path)
tables = {r[0] for r in q(h, "SELECT name FROM sqlite_master WHERE type='table'")}
check("a 1.41 database loses its coverage tables",
      not ({"coverage", "meta"} & tables) and q(h, "PRAGMA user_version") == [(H.SCHEMA_VERSION,)], tables)
check("...and keeps its usage", h.range_totals(7)["bytes_out"] == 100 and h.reset_backup is None)
check("a day carries only what moved", set(h.daily(7)[-1]) == {"day", "bytes_in", "bytes_out", "packets"},
      h.daily(7)[-1])
h.stop()

h = fresh

# -- one range for everything -------------------------------------------------------
old_ts = time.time() - 40 * 86400
h.record(pkt("old.exe", "old.example", 9000, ts=old_ts))
h.record(pkt("new.exe", "new.example", 300))
h.record(pkt("-", "new.example", 200))
h.flush()
week = [r["host"] for r in h.by_host(7)]
check("By host follows the range", week == ["new.example"], week)
check("...and the longer range reaches further back",
      "old.example" in [r["host"] for r in h.by_host(90)], h.by_host(90))
t = h.range_totals(7)
procs = sum(r["bytes_in"] + r["bytes_out"] for r in h.by_process(7))
check("totals are the range's, and agree with By program plus unattributed",
      t["bytes_in"] + t["bytes_out"] == procs + 200 and t["programs"] == 1 and t["hosts"] == 1, t)
check("By host includes unattributed traffic",
      h.by_host(7)[0]["bytes_out"] == 500, h.by_host(7))

# -- one adapter --------------------------------------------------------------------------
for _ in range(3):
    h.record(pkt("vrserver.exe", "10.0.0.5", 50000, iface="VR"))
h.record(pkt("new.exe", "new.example", 100, iface="VR"))
h.flush()
check("every adapter with usage is listed, busiest first",
      h.ifaces() == ["VR", "Ethernet"], h.ifaces())
check("All adapters adds them up",
      h.range_totals(7)["bytes_out"] == 500 + 150000 + 100, h.range_totals(7))
check("one adapter's totals are its own",
      h.range_totals(7, "VR")["bytes_out"] == 150100 and h.range_totals(7, "Ethernet")["bytes_out"] == 500)
check("...and so are its programs and hosts",
      [r["name"] for r in h.by_process(7, iface="VR")] == ["vrserver.exe", "new.exe"]
      and [r["host"] for r in h.by_host(7, iface="Ethernet")] == ["new.example"])
check("...and its days", h.daily(7, "VR")[-1]["bytes_out"] == 150100)
d = h.detail("program", "new.exe", 7, iface="VR")
check("a program's detail follows the adapter",
      d["total"] == 100 and [r["name"] for r in d["rows"]] == ["new.example"], d)
check("...and covers every adapter without one",
      h.detail("program", "new.exe", 7)["total"] == 400)
check("first contacts on one adapter are hosts it carried",
      [r["host"] for r in h.new_hosts(7, iface="VR")] == ["10.0.0.5", "new.example"]
      or sorted(r["host"] for r in h.new_hosts(7, iface="VR")) == ["10.0.0.5", "new.example"],
      h.new_hosts(7, iface="VR"))
check("...and none from an adapter that carried nothing", h.new_hosts(7, iface="Wi-Fi") == [])

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
