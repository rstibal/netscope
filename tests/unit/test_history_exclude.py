import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import shutil, tempfile, time
import netscope_history as H
import netscope_alerts as A

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns-hx-")

def store(name):
    return H.HistoryStore(path=os.path.join(tmp, name + ".db"))

def pkt(proc, host, n=1000, d="out"):
    return {"process": proc, "rhost": host, "remote": "1.2.3.4", "length": n,
            "dir": d, "ts": time.time()}

def q(h, sql, args=()):
    return [tuple(r) for r in h._db.execute(sql, args)]

# ---- matching
check("program: exact, any case", H.program_matches("chrome.exe", "Chrome.EXE"))
check("program: wildcard", H.program_matches("chrome*", "chrome.exe"))
check("program: no partial match without a wildcard",
      not H.program_matches("chrome", "chrome.exe"))
check("host: a plain name covers its subdomains",
      H.host_matches("example.com", "www.example.com"))
check("...but not a name that merely ends the same way",
      not H.host_matches("example.com", "badexample.com"))
check("host: wildcard", H.host_matches("10.0.0.*", "10.0.0.7"))
check("host: a trailing dot is ignored", H.host_matches("example.com", "example.com."))
check("patterns are cleaned: trimmed, lower-cased, de-duplicated, non-strings dropped",
      H.clean_patterns([" Chrome.exe ", "chrome.exe", "", None, 5, "x"*300]) == ["chrome.exe"])

# ---- recording
h = store("rec")
h.set_exclusions(["secret.exe"], ["bank.example"])
h.record(pkt("secret.exe", "anywhere.com"))
h.record(pkt("chrome.exe", "www.bank.example"))
h.record(pkt("chrome.exe", "news.com"))
h.flush()
check("an excluded program's usage is not written",
      q(h, "SELECT COUNT(*) FROM usage WHERE process='secret.exe'") == [(0,)])
check("...but its name is, with no counters",
      q(h, "SELECT bytes_in+bytes_out, packets FROM processes WHERE name='secret.exe'") == [(0, 0)])
check("...so the new-program alert still knows it next session",
      store("rec").known_process("secret.exe"))
check("the hosts an excluded program talks to are not written",
      q(h, "SELECT COUNT(*) FROM hosts WHERE host='anywhere.com'") == [(0,)])
check("an excluded host is not written at all",
      q(h, "SELECT COUNT(*) FROM hosts WHERE host LIKE '%bank.example'") == [(0,)])
check("...while the program's own usage still counts that traffic",
      q(h, "SELECT SUM(packets) FROM usage WHERE process='chrome.exe'") == [(2,)])
check("other hosts are recorded as before",
      q(h, "SELECT packets FROM hosts WHERE host='news.com'") == [(1,)])
check("an excluded host counts as known, so it never warns as a first contact",
      h.known_host("login.bank.example") and not h.known_host("elsewhere.org"))

# ---- adding an exclusion drops what hasn't been flushed yet
h = store("pending")
h.record(pkt("late.exe", "late.example"))
h.set_exclusions(["late.exe"], [])
h.flush()
check("unflushed usage for a newly excluded program never reaches disk",
      q(h, "SELECT COUNT(*) FROM usage WHERE process='late.exe'") == [(0,)])
# Its pending hosts can't be dropped with it: a host row doesn't say which
# program it came from — the same limit purge() has for older hosts.

# ---- the alert log
h = store("alerts")
h.set_exclusions(["secret.exe"], ["bank.example"])
for a in ({"severity": "info", "rule": "new_process", "process": "secret.exe"},
          {"severity": "info", "rule": "new_host", "process": "chrome.exe",
           "subject": "www.bank.example"},
          {"severity": "warn", "rule": "new_process", "process": "secret.exe"},
          {"severity": "high", "rule": "cleartext_creds", "process": "chrome.exe",
           "subject": "www.bank.example"},
          {"severity": "info", "rule": "new_host", "process": "chrome.exe",
           "subject": "news.com"}):
    h.record_alert({"ts": time.time(), "title": "t", "detail": "d", **a})
h.flush()
got = sorted(q(h, "SELECT severity, rule FROM alerts"))
check("note-level alerts about excluded subjects are not logged; warnings and others are",
      got == [("high", "cleartext_creds"), ("info", "new_host"), ("warn", "new_process")], got)

# ---- with the alert engine: an excluded program is still new exactly once
h = store("engine")
h.was_empty = False
h.set_exclusions(["secret.exe"], [])
e = A.AlertEngine(history=h); e.warmup_until = 0; e.baselining = False
h.record(pkt("secret.exe", "x.com"))       # as the capture path does
e._change_rules(pkt("secret.exe", "x.com"))
check("the first sighting of an excluded program still warns",
      any(a["rule"] == "new_process" and a["severity"] == "warn" for a in e.list()))
h.flush()
e2 = A.AlertEngine(history=store("engine")); e2.warmup_until = time.time() + 999
e2.baselining = False
e2._change_rules(pkt("secret.exe", "x.com"))
check("...and not again next session",
      not any(a["severity"] == "warn" for a in e2.list()), e2.list())

# ---- purge
h = store("purge")
h.record(pkt("old.exe", "old.example"))
h.record(pkt("chrome.exe", "cdn.old.example"))
h.record(pkt("chrome.exe", "keep.example"))
h.record_alert({"ts": time.time(), "severity": "info", "rule": "new_host",
                "process": "chrome.exe", "subject": "cdn.old.example",
                "title": "t", "detail": "chrome.exe connected to cdn.old.example, first time"})
h.record_alert({"ts": time.time(), "severity": "info", "rule": "new_process",
                "process": "old.exe", "title": "t", "detail": "old.exe used the network"})
h.flush()
g = h.purge("program", "OLD.exe")
check("purging a program deletes its usage", g["usage"] == 1 and
      q(h, "SELECT COUNT(*) FROM usage WHERE process='old.exe'") == [(0,)], g)
check("...zeroes its counters but keeps its name",
      q(h, "SELECT packets FROM processes WHERE name='old.exe'") == [(0,)])
check("...and deletes its note-level alerts", g["alerts"] == 1, g)
check("...leaving the hosts it talked to, which can't be told apart",
      q(h, "SELECT COUNT(*) FROM hosts WHERE host='old.example'") == [(1,)])
g = h.purge("host", "old.example")
check("purging a host deletes it and its subdomains",
      g["hosts"] == 2 and q(h, "SELECT host FROM hosts") == [("keep.example",)], g)
check("...and the note-level alerts that name it", g["alerts"] == 1, g)
check("purge ignores an unknown kind or an empty pattern",
      h.purge("thing", "x") == h.purge("host", "  ") == {"usage": 0, "hosts": 0, "alerts": 0})

# ---- wiping history keeps the exclusions
h.set_exclusions(["a.exe"], ["b.example"])
h.wipe()
check("Erase all history doesn't forget what not to record",
      h.exclusions() == {"programs": ["a.exe"], "hosts": ["b.example"]})

for x in list(locals().values()):
    if isinstance(x, H.HistoryStore) and x._db is not None:
        try: x._db.close()
        except Exception: pass
shutil.rmtree(tmp, ignore_errors=True)
print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
