import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_alerts as A

def engine():
    e = A.AlertEngine()
    e._dns_read = A._now()          # stop it re-reading the real machine
    return e

def titles(e):
    return [a["title"] for a in e.list()]

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

N = A.SCAN_PORT_THRESHOLD

# ---- 1. Inbound: one peer touching N distinct local ports in the window fires.
e = engine()
now = A._now()
for i in range(N):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 1000 + i, "ts": now})
check("inbound burst of N distinct ports -> fires",
      titles(e) == ["Possible port scan from 45.33.12.9"], str(titles(e)))

# ---- 2. Inbound: fewer than N distinct ports stays quiet.
e = engine()
for i in range(N - 1):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 1000 + i, "ts": now})
check("inbound, N-1 distinct ports -> silent", e.list() == [], str(titles(e)))

# ---- 3. Same port hammered repeatedly is not a scan (no distinct growth).
e = engine()
for _ in range(50):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 443, "ts": now})
check("one port hammered -> silent", e.list() == [], str(titles(e)))

# ---- 4. Outbound: one process fanning out to N distinct host/port pairs fires.
e = engine()
for i in range(N):
    e._scan_rule({"dir": "out", "process": "sketchy.exe",
                  "remote": f"10.0.0.{i}", "dport": 445, "ts": now})
check("outbound fan-out of N distinct pairs -> fires",
      titles(e) == ["sketchy.exe is contacting many hosts/ports at once"], str(titles(e)))

# ---- 5. Outbound: normal traffic to one host/port is silent regardless of volume.
e = engine()
for _ in range(50):
    e._scan_rule({"dir": "out", "process": "chrome.exe",
                  "remote": "93.184.216.34", "dport": 443, "ts": now})
check("repeated single destination -> silent", e.list() == [], str(titles(e)))

# ---- 6. A burst spread out past the window never accumulates enough distinct hits.
e = engine()
for i in range(N):
    e._scan_rule({"dir": "in", "remote": "1.2.3.4", "dport": 2000 + i,
                  "ts": now + i * (A.SCAN_WINDOW_SECS + 1)})
check("burst spread past the window -> silent", e.list() == [], str(titles(e)))

# ---- 7. Firing clears the window so the next packet doesn't double-fire immediately.
e = engine()
for i in range(N):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 1000 + i, "ts": now})
e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 1000, "ts": now})
check("one alert per burst, not one per follow-on packet", len(e.list()) == 1, str(titles(e)))

# ---- 8. Rule can be disabled.
e = engine()
e.rules["port_scan"] = False
for i in range(N):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 1000 + i, "ts": now})
check("disabled rule -> silent", e.list() == [], str(titles(e)))

# ---- 9. Missing dport/peer never crashes.
e = engine()
e._scan_rule({"dir": "in", "remote": "45.33.12.9", "ts": now})
e._scan_rule({"dir": "out", "process": "x.exe", "dport": 80, "ts": now})
e._scan_rule({"dir": "in", "dport": 80, "ts": now})
check("missing fields -> no crash, silent", e.list() == [], str(titles(e)))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
