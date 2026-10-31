"""
History 1.40: what was being captured is recorded per hour, every figure
follows the chosen range, and usage from before (with no such record) is
reset once, after copying the file.
"""
import os, sqlite3, sys, tempfile, time, types
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

def pkt(proc, host, n=100, ts=None, out=True):
    return {"process": proc, "rhost": host, "remote": "203.0.113.9", "length": n,
            "dir": "out" if out else "in", "ts": ts or time.time()}

# -- the one-time reset of an older database ---------------------------------------
folder = tempfile.mkdtemp(prefix="ns-cov-")
path = os.path.join(folder, "history.db")
old = sqlite3.connect(path)
old.executescript(H.SCHEMA)
old.execute("INSERT INTO usage VALUES ('2026-10-01', 9, 'chrome.exe', 500, 50, 5)")
old.execute("INSERT INTO usage_pairs VALUES ('2026-10-01', 9, 'chrome.exe', 'a.example', 500, 50, 5)")
old.execute("INSERT INTO processes VALUES ('chrome.exe', 1, 2, 500, 50, 5)")
old.execute("INSERT INTO hosts VALUES ('a.example', 1, 2, 500, 50, 5)")
old.execute("INSERT INTO sessions(started, iface, packets) VALUES (1, 'Wi-Fi', 5)")
old.execute("INSERT INTO alerts(ts, severity, rule, title, detail) VALUES (1, 'warn', 'x', 't', 'd')")
old.execute("INSERT INTO checkins VALUES ('chrome.exe', 'a.example', 60, 1, 2)")
old.commit(); old.close()

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
h.record(pkt("chrome.exe", "a.example")); h.flush(); h.stop()

h = H.HistoryStore(path=path)
check("it happens once: reopening keeps new usage",
      h.reset_backup is None and q(h, "SELECT COUNT(*) FROM usage") == [(1,)])
h.stop()

fresh = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-cov-"), "h.db"))
check("a new database needs no reset and no copy",
      fresh.reset_backup is None and q(fresh, "PRAGMA user_version") == [(H.SCHEMA_VERSION,)])

# -- coverage ------------------------------------------------------------------------
h = fresh
state = {"src": (["Ethernet"], ["Wi-Fi"], ["VR"])}
h.coverage_source = lambda: state["src"]
t0 = time.time() - 30
h.tick_coverage(now=t0)                     # the first tick only starts the clock
h.tick_coverage(now=t0 + 10)
h.tick_coverage(now=t0 + 10 + 3600)         # woke from sleep: capped, not an hour
state["src"] = None                         # capture stopped
h.tick_coverage(now=t0 + 10 + 3610)
h.flush()
ad = {a["iface"]: a for a in h.adapters(7)}
check("captured, missed and ignored adapters are each recorded",
      ad.get("Ethernet", {}).get("captured") and ad.get("Wi-Fi", {}).get("missed")
      and ad.get("VR", {}).get("ignored"), ad)
check("a long gap counts at most one tick",
      ad["Ethernet"]["captured"] == round(10 + H.MAX_TICK), ad["Ethernet"])
check("nothing is credited while capture is stopped",
      q(h, "SELECT SUM(seconds) FROM coverage WHERE iface='*'") == [(10 + H.MAX_TICK,)])
today = h.daily(7)[-1]
check("the day says how long it ran, and which adapter was missed",
      today["ran"] > 0 and "Wi-Fi" in today["missed"] and today["expected"] >= today["ran"], today)
check("days before coverage began expect nothing", h.daily(7)[0]["expected"] == 0, h.daily(7)[0])

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

# -- what the app feeds it ------------------------------------------------------------
sys.argv = [sys.argv[0]]
import netscope as N
eng = types.SimpleNamespace(
    running=True, ifaces=["Ethernet"], ignored=["VR"],
    interfaces=lambda refresh=True: [
        {"name": "Ethernet", "ip": "192.168.1.2"}, {"name": "Wi-Fi", "ip": "192.168.1.3"},
        {"name": "VR", "ip": "10.0.0.2"}, {"name": "Bluetooth", "ip": ""},
        {"name": "Loopback", "ip": "127.0.0.1"}])
app = types.SimpleNamespace(source=None)
check("live capture reports captured, missed and ignored",
      N.coverage_now(eng, app) == (["Ethernet"], ["Wi-Fi"], ["VR"]), N.coverage_now(eng, app))
app.source = "saved.pcap"
check("an imported file is not coverage", N.coverage_now(eng, app) is None)
app.source = None; eng.running = False
check("nor is a stopped capture", N.coverage_now(eng, app) is None)

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
