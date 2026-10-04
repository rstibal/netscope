import os, sys, shutil, tempfile, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_history as H

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns-hf-")
h = H.HistoryStore(path=os.path.join(tmp, "h.db"))

def pkt(proc, host, n, ts):
    return {"process": proc, "rhost": host, "remote": "1.2.3.4", "length": n,
            "dir": "out", "ts": ts}

def total(proc):
    r = h._db.execute("SELECT COALESCE(SUM(bytes_out),0), COALESCE(SUM(packets),0) "
                      "FROM usage WHERE process=?", (proc,)).fetchone()
    return tuple(r)

now = time.time()
for i in range(10):
    h.record(pkt("a.exe", "example.com", 100, now))
h.record_alert({"severity": "warn", "rule": "x", "title": "t", "detail": "d",
                "subject": "s", "ts": now})

# ---- a write that fails loses nothing --------------------------------------
class Boom:
    """Stands in for the connection: usage writes succeed, then the hosts
    write fails, so the transaction is left half-applied."""
    def __init__(self, real): self.real, self.n = real, 0
    def executemany(self, sql, rows):
        if "INTO hosts" in sql:
            raise RuntimeError("disk full")
        return self.real.executemany(sql, rows)
    def __getattr__(self, name): return getattr(self.real, name)

real = h._db
h._db = Boom(real)
h.flush()
h._db = real
check("failure is reported", "disk full" in (h.error or ""), h.error)
check("half-applied write was rolled back", total("a.exe") == (0, 0), total("a.exe"))
check("the batch is waiting to be retried", len(h._pending_alerts) == 1 and h._hosts)

h.error = None
h.record(pkt("a.exe", "example.com", 100, now))   # traffic during the outage
h.flush()
check("retry writes everything once", total("a.exe") == (1100, 11), total("a.exe"))
check("the alert arrived exactly once",
      real.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1)
row = real.execute("SELECT bytes_out, packets FROM hosts WHERE host='example.com'").fetchone()
check("host totals are complete", tuple(row) == (1100, 11), tuple(row) if row else None)

# ---- a persistent failure can't grow the alert queue without bound ---------
h2 = H.HistoryStore(path=os.path.join(tmp, "h2.db"))
r2 = h2._db
h2._db = Boom(r2)
for i in range(H.MAX_PENDING_ALERTS + 500):
    h2.record_alert({"severity": "warn", "rule": "x", "title": str(i),
                     "detail": "d", "ts": now})
    if i % 1000 == 0:
        h2.record(pkt("b.exe", "h.example", 1, now)); h2.flush()
h2.flush()
check("pending alerts stay capped", len(h2._pending_alerts) <= H.MAX_PENDING_ALERTS,
      len(h2._pending_alerts))
check("the newest alerts are the ones kept",
      h2._pending_alerts[-1][3] == str(H.MAX_PENDING_ALERTS + 499))

# ---- the per-second day/hour cache follows the clock ------------------------
a = H._day_hour(1_700_000_000.2)
b = H._day_hour(1_700_000_000.9)
c = H._day_hour(1_700_000_000.0 + 3 * 3600)
check("same second, same answer", a == b)
check("a later hour is not served from the cache", c[1] == (a[1] + 3) % 24)

# ---- settings saved from two threads both survive --------------------------
os.environ["LOCALAPPDATA"] = tmp; os.environ["HOME"] = tmp
os.environ["USERPROFILE"] = tmp
def save(i):
    for j in range(15): H.save_setting("k%d_%d" % (i, j), j)
ts = [threading.Thread(target=save, args=(i,)) for i in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
check("concurrent settings writes all land", len(H.load_settings()) == 60,
      len(H.load_settings()))

h.stop(); h2._db = r2; h2.stop()
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(1 if fails else 0)
