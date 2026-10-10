import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import shutil, tempfile, time
from datetime import datetime
import netscope_history as H

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns-hp-")
def store(name):
    return H.HistoryStore(path=os.path.join(tmp, name + ".db"))
def pkt(proc, host, n=1000, d="out", ts=None):
    return {"process": proc, "rhost": host, "remote": "1.2.3.4", "length": n,
            "dir": d, "ts": ts or time.time()}
def q(h, sql, args=()):
    return [tuple(r) for r in h._db.execute(sql, args)]

# ---- recorded per hour, program and host, and summed across flushes
h = store("rec")
h.record(pkt("mystery.exe", "cdn.example", 4000, "in"))
h.record(pkt("mystery.exe", "cdn.example", 500, "out"))
h.record(pkt("mystery.exe", "api.example", 100, "out"))
h.record(pkt("chrome.exe", "cdn.example", 900, "in"))
h.flush()
h.record(pkt("mystery.exe", "cdn.example", 1000, "in"))
h.flush()
check("one row per hour/program/host",
      q(h, "SELECT COUNT(*) FROM usage_pairs") == [(3,)])
check("bytes add up across flushes",
      q(h, "SELECT bytes_in, bytes_out, packets FROM usage_pairs "
           "WHERE process='mystery.exe' AND host='cdn.example'") == [(5000, 500, 3)])

# ---- the detail answers "why" and "when", and adds up to the program's total
d = h.detail("program", "mystery.exe", 7)
check("hosts are ranked biggest first",
      [r["name"] for r in d["rows"]] == ["cdn.example", "api.example"], d["rows"])
check("the parts add up to the program's total in usage",
      sum(r["bytes_in"] + r["bytes_out"] for r in d["rows"]) + d["unlisted"] == d["total"]
      and d["total"] == 5600 and d["unlisted"] == 0, (d["total"], d["unlisted"]))
check("72 hourly slots, the current hour last and carrying the bytes",
      len(d["hours"]) == 72
      and d["hours"][-1]["bytes_in"] + d["hours"][-1]["bytes_out"] == 5600, d["hours"][-1])
check("the busiest hour names its main host",
      d["busiest"] and d["busiest"][0]["host"] == "cdn.example", d["busiest"])
check("pairs_since reports the first recorded day",
      d["pairs_since"] == datetime.now().strftime("%Y-%m-%d"))
dh = h.detail("host", "cdn.example", 7)
check("a host lists the programs that contacted it",
      [r["name"] for r in dh["rows"]] == ["mystery.exe", "chrome.exe"], dh["rows"])

# ---- traffic from before pairs existed shows as unlisted, not as nothing
h.record(pkt("old.exe", "x.example", 700))
h.flush()
h._db.execute("DELETE FROM usage_pairs WHERE process='old.exe'")
h._db.commit()
d = h.detail("program", "old.exe", 7)
check("usage with no pair rows is reported as not broken down",
      d["rows"] == [] and d["unlisted"] == 700 == d["total"], d)

# ---- unattributed traffic and blank hosts get no pair row
h = store("blank")
h.record(pkt("-", "somewhere.example"))
h.record({"process": "a.exe", "length": 10, "dir": "out", "ts": time.time()})
h.flush()
check("a program of '-' and a blank host are not paired",
      q(h, "SELECT COUNT(*) FROM usage_pairs") == [(0,)])

# ---- the pending batch is bounded
H.MAX_PENDING_PAIRS = 5
h = store("cap")
for i in range(20):
    h.record(pkt("scan.exe", "h%d.example" % i, 100))
check("a scan folds into one (other) row past the cap",
      len(h._pairs) == 6 and any(k[3] == H.OTHER_HOSTS for k in h._pairs), len(h._pairs))
h.flush()
check("...and the program's own total stays exact",
      q(h, "SELECT SUM(bytes_out) FROM usage WHERE process='scan.exe'") == [(2000,)]
      and q(h, "SELECT SUM(bytes_out) FROM usage_pairs") == [(2000,)])
H.MAX_PENDING_PAIRS = 20000

# ---- exclusions
h = store("ex")
h.set_exclusions(["secret.exe"], ["bank.example"])
h.record(pkt("secret.exe", "anywhere.com"))
h.record(pkt("chrome.exe", "www.bank.example"))
h.record(pkt("chrome.exe", "news.com"))
h.flush()
check("an excluded program or host is never paired",
      q(h, "SELECT process, host FROM usage_pairs") == [("chrome.exe", "news.com")])
h.record(pkt("late.exe", "late.example"))
h.set_exclusions(["late.exe"], ["bank.example"])
h.flush()
check("excluding drops unflushed pairs too",
      q(h, "SELECT COUNT(*) FROM usage_pairs WHERE process='late.exe'") == [(0,)])

# ---- purge, retention, wipe
h = store("gone")
h.record(pkt("a.exe", "one.example"))
h.record(pkt("a.exe", "two.example"))
h.record(pkt("b.exe", "one.example"))
h.flush()
h.purge("program", "a.exe")
check("purging a program erases its per-host breakdown",
      q(h, "SELECT process FROM usage_pairs") == [("b.exe",)])
h.purge("host", "one.example")
check("purging a host erases it from every program's breakdown",
      q(h, "SELECT COUNT(*) FROM usage_pairs") == [(0,)])

h.record(pkt("old.exe", "old.example"))
h.flush()
h._db.execute("UPDATE usage_pairs SET day='2000-01-01'")
h._db.commit()
h.prune()
check("retention prunes old pairs", q(h, "SELECT COUNT(*) FROM usage_pairs") == [(0,)])

h.record(pkt("w.exe", "w.example"))
h.flush()
h.record(pkt("w.exe", "w2.example"))
h.wipe()
h.flush()
check("wipe clears them, pending ones included",
      q(h, "SELECT COUNT(*) FROM usage_pairs") == [(0,)])

# ---- a failed flush keeps the pairs for the next one
h = store("retry")
h.record(pkt("r.exe", "r.example", 300))
real = h._db
class Boom:
    def __getattr__(self, n):
        if n == "executemany":
            raise RuntimeError("disk full")
        return getattr(real, n)
h._db = Boom()
h.flush()
h._db = real
h.flush()
check("a failed flush is retried, pairs included",
      q(h, "SELECT bytes_out FROM usage_pairs WHERE process='r.exe'") == [(300,)])

shutil.rmtree(tmp, ignore_errors=True)
print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
