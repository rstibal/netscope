import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, ROOT)
import json, random, re, shutil, subprocess, tempfile, time
import netscope_timeline as T
import netscope_history as H
import netscope_alerts as A

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def every(period, n=12, start=1000, burst=1, jitter=0):
    out = []
    for i in range(n):
        t = start + i * period + (random.randint(-jitter, jitter) if jitter else 0)
        out += [t + j for j in range(burst)]
    return sorted(set(out))

# ---- the test itself
random.seed(3)
check("a steady 30 s check-in is regular", T.regular_interval(every(30)) == 30)
check("...with a second of jitter too", T.regular_interval(every(60, jitter=1)) in (59, 60, 61))
check("fewer than five bursts is not enough", T.regular_interval(every(30, n=4)) == 0)
check("a constant stream is not a check-in", T.regular_interval(list(range(1000, 1600))) == 0)
check("bursts long against the gap don't count",
      T.regular_interval(every(12, burst=6)) == 0)
irregular = sorted({1000 + sum(random.randint(10, 300) for _ in range(i)) for i in range(20)})
check("uneven gaps are not regular", T.regular_interval(irregular) == 0)
check("under 5 s apart is traffic, not a schedule", T.regular_interval(every(4)) == 0)

# ---- the same answers as the dashboard's Timeline
node = shutil.which("node")
if not node:
    print("SKIP  JavaScript parity (node not found)")
else:
    src = open(os.path.join(ROOT, "netscope_ui.py"), encoding="utf-8").read()
    fn = re.search(r"function tlRegular\(secs\)\{.*?\n\}", src, re.S).group(0)
    cases = [every(30), every(60, jitter=1), every(30, n=4), list(range(1000, 1300)),
             every(12, burst=6), irregular, every(4), every(45, n=80, jitter=2),
             every(20, burst=3), every(300, n=6, jitter=20)]
    for _ in range(60):
        p = random.choice([7, 15, 20, 45, 60, 120, 600])
        cases.append(every(p, n=random.randint(3, 40), burst=random.randint(1, 4),
                           jitter=random.randint(0, max(1, p // 6))))
    js = fn + "\nconst cases = " + json.dumps(cases) + ";\nconsole.log(JSON.stringify(cases.map(tlRegular)));"
    tmp = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
    tmp.write(js); tmp.close()
    try:
        got = json.loads(subprocess.run([node, tmp.name], capture_output=True, text=True,
                                        timeout=30).stdout)
    finally:
        os.unlink(tmp.name)
    want = [T.regular_interval(c) for c in cases]
    diff = [(i, a, b) for i, (a, b) in enumerate(zip(got, want)) if a != b]
    check("the alert and the Timeline's box agree on %d cases" % len(cases), not diff, diff[:5])

# ---- pairs out of the Timeline
def pkt(ts, proc, host, ip="1.2.3.4", n=100):
    return {"ts": ts, "process": proc, "rhost": host, "remote": ip, "src": "10.0.0.2",
            "dst": ip, "sport": 50000, "dport": 443, "dir": "out", "proto": "TLS",
            "length": n, "iface": "eth0"}
NOW = int(time.time())
def timeline():
    t = T.Timeline()
    for s in range(NOW - 3000, NOW):
        t.observe(pkt(s + .2, "Busy.exe", "api.example.com"))       # never idle
        if (NOW - s) % 45 == 0:
            t.observe(pkt(s + .3, "Busy.exe", "dl.example.com"))     # a check-in inside it
            t.observe(pkt(s + .4, "(no socket)", "dl.example.com"))
        if (NOW - s) % 30 == 0:
            t.observe(pkt(s + .5, "(broadcast)", "", ip="255.255.255.255"))
            t.observe(pkt(s + .6, "Agent.exe", "", ip="203.0.113.9"))   # no name: the address
    return t
pairs = timeline().pair_activity()
check("pair_activity splits a program by host",
      ("Busy.exe", "api.example.com") in pairs and ("Busy.exe", "dl.example.com") in pairs, list(pairs))
check("...uses the address when there is no name", ("Agent.exe", "203.0.113.9") in pairs)
check("...and one second is counted once per pair",
      len(pairs[("Busy.exe", "api.example.com")]) == 3000)

# ---- the rule, without history
e = A.AlertEngine()
got = e.check_checkins(timeline())
names = sorted((a["process"], a["subject"], a["severity"]) for a in got)
check("without history, each scheduled pair is a note",
      names == [("Agent.exe", "203.0.113.9", "info"), ("Busy.exe", "dl.example.com", "info")], names)
check("...labelled with who, where and how often",
      any(a["detail"].startswith("Busy.exe contacts dl.example.com every ~45s (") for a in got),
      [a["detail"] for a in got])
check("traffic with no program behind it is never reported",
      not any(a["process"].startswith("(") for a in got))
check("a pair is reported once, not every pass", e.check_checkins(timeline()) == [])
e2 = A.AlertEngine(); e2.rules["checkin"] = False
check("the rule can be switched off", e2.check_checkins(timeline()) == [])
e3 = A.AlertEngine(); e3.mute("checkin", "dl.example.com")
check("a muted host stays quiet", [a["subject"] for a in e3.check_checkins(timeline())] == ["203.0.113.9"])

# ---- with history
tmp = tempfile.mkdtemp(prefix="ns-ci-")
stores = []
def store(name):
    h = H.HistoryStore(path=os.path.join(tmp, name + ".db")); stores.append(h); return h

h = store("a"); h.was_empty = False
e = A.AlertEngine(history=h)
check("the first day only learns", e.check_checkins(timeline()) == [] and
      h.known_checkin("Busy.exe", "dl.example.com"))
h2 = store("a")
check("...and what it learned is remembered next time",
      h2.known_checkin("Busy.exe", "dl.example.com") and h2.checkin_baselining())

h = store("b"); h.was_empty = False
h._checkin_since = time.time() - 2 * 86400          # learned for two days already
with h._db_lock:
    h._db.execute("INSERT INTO processes VALUES ('Busy.exe', ?, ?, 0, 0, 0)",
                  (time.time() - 30 * 86400, time.time()))
    h._db.commit()
e = A.AlertEngine(history=h)
got = {a["process"]: a for a in e.check_checkins(timeline())}
check("after that, a known program's new check-in is a note",
      got.get("Busy.exe", {}).get("severity") == "info", got)
check("...and a program new this week checking in is a warning",
      got.get("Agent.exe", {}).get("severity") == "warn" and
      got["Agent.exe"]["title"] == "New program checking in on a schedule" and
      "new on this machine this week" in got["Agent.exe"]["detail"], got.get("Agent.exe"))
e2 = A.AlertEngine(history=store("b"))
check("a pair already reported never fires again, even in a new session",
      e2.check_checkins(timeline()) == [])

h = store("c"); h.was_empty = False
h._checkin_since = time.time() - 2 * 86400
h.set_exclusions([], ["dl.example.com"])
e = A.AlertEngine(history=h)
got = [a["subject"] for a in e.check_checkins(timeline())]
check("an excluded host counts as known, and isn't stored",
      got == ["203.0.113.9"] and
      h._q("SELECT COUNT(*) AS n FROM checkins WHERE host='dl.example.com'")[0]["n"] == 0, got)

h = store("d"); h.note_checkin("X.exe", "x.example", 60)
h.wipe()
check("Erase all history forgets check-ins and starts learning again",
      not h.known_checkin("X.exe", "x.example") and h.checkin_baselining() and
      h._q("SELECT COUNT(*) AS n FROM checkins")[0]["n"] == 0)
h = store("e"); h.note_checkin("X.exe", "x.example", 60); h.note_checkin("Y.exe", "y.example", 60)
h.purge("host", "x.example")
check("purging a host deletes its check-ins",
      [r["host"] for r in h._q("SELECT host FROM checkins")] == ["y.example"])

for x in stores:
    try: x._db.close()
    except Exception: pass
shutil.rmtree(tmp, ignore_errors=True)
print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
