import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import shutil, sqlite3, tempfile, time
import netscope_history as H

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns-alog-")
stores = []
def store(name):
    h = H.HistoryStore(path=os.path.join(tmp, name + ".db"))
    stores.append(h)
    return h

def alert(i, sev="warn", subject="x.example", ts=None):
    return {"ts": ts or time.time(), "severity": sev, "rule": "new_host",
            "title": "t%d" % i, "detail": "d%d" % i, "process": "p.exe",
            "peer": "1.2.3.4", "subject": subject}

# ---- a database from before 1.25.1 gains the column, keeping its rows
path = os.path.join(tmp, "old.db")
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
  severity TEXT NOT NULL, rule TEXT NOT NULL, title TEXT NOT NULL,
  detail TEXT NOT NULL, process TEXT, peer TEXT);
INSERT INTO alerts(ts,severity,rule,title,detail,process,peer)
  VALUES (strftime('%s','now'),'high','cleartext_creds','old','old one','ftp.exe','5.6.7.8');
""")
db.commit(); db.close()
h = H.HistoryStore(path=path); stores.append(h)
check("an old database opens", h.enabled, h.error)
cols = [r[1] for r in h._db.execute("PRAGMA table_info(alerts)")]
check("...and gains a subject column", "subject" in cols, cols)
rows, more = h.alert_log()
check("...its old alerts still read, with no subject",
      len(rows) == 1 and rows[0]["title"] == "old" and rows[0]["subject"] is None, rows)
h.record_alert(alert(1)); h.flush()
rows, _ = h.alert_log()
check("...and new ones record their subject", rows[0]["subject"] == "x.example", rows)
h2 = H.HistoryStore(path=path); stores.append(h2)
check("opening it again doesn't try to add the column twice", h2.enabled, h2.error)

# ---- paging
h = store("paging")
for i in range(250):
    h.record_alert(alert(i, sev="high" if i % 50 == 0 else "warn"))
h.flush()
rows, more = h.alert_log(limit=100)
check("newest first, a page at a time",
      len(rows) == 100 and more and rows[0]["title"] == "t249" and rows[-1]["title"] == "t150")
rows2, more2 = h.alert_log(before=rows[-1]["id"], limit=100)
rows3, more3 = h.alert_log(before=rows2[-1]["id"], limit=100)
check("before= pages back without gaps or repeats",
      [r["title"] for r in rows2][:1] == ["t149"] and len(rows3) == 50 and not more3
      and len({r["id"] for r in rows + rows2 + rows3}) == 250)
newest = rows[0]["id"]
h.record_alert(alert(250)); h.record_alert(alert(251)); h.flush()
new, m = h.alert_log(after=newest)
check("after= returns only what is newer", [r["title"] for r in new] == ["t251", "t250"] and not m, new)
c = h.alert_counts()
check("counts by severity, and the newest id",
      c["total"] == 252 and c["high"] == 5 and c["warn"] == 247 and c["newest"] == new[0]["id"], c)
old = time.time() - 10 * 86400
h.record_alert(alert(999, ts=old)); h.flush()
check("counts can be limited to recent days",
      h.alert_counts(days=7)["total"] == 252 and h.alert_counts()["total"] == 253)

# ---- a store with history off
off = H.HistoryStore(path=os.path.join(tmp, "off.db"), enabled=False)
check("with history off the log is empty, not an error",
      off.alert_log() == ([], False) and off.alert_counts()["total"] == 0)

for x in stores:
    try: x._db.close()
    except Exception: pass
shutil.rmtree(tmp, ignore_errors=True)
print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
