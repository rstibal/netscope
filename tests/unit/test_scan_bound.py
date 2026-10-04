import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_alerts as A

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def syn(peer, dport, ts):
    return {"dir": "in", "remote": peer, "sport": 40000, "dport": dport, "ts": ts,
            "transport": "tcp", "decoded": {"tcp": {"flags": "S"}}}

def engine():
    e = A.AlertEngine(); e._dns_read = A._now(); return e

# ---- one-off scanners over time don't pile up ------------------------------
e = engine()
t = 1000.0
for i in range(A.SCAN_PEERS_MAX * 3):
    e._scan_rule(syn("198.51.%d.%d" % (i // 250, i % 250), 22, t))
    t += 1.0                                  # each knocks once, then is gone
check("tracked peers stay bounded", len(e._scan_inbound) <= A.SCAN_PEERS_MAX,
      len(e._scan_inbound))

# ---- a real scan is still caught while the table is busy -------------------
e = engine()
t = 1000.0
for i in range(A.SCAN_PEERS_MAX - 5):
    e._scan_rule(syn("198.51.%d.%d" % (i // 250, i % 250), 22, t))
t += 100.0                                    # that crowd has aged out
for p in range(A.SCAN_PORT_THRESHOLD):
    e._scan_rule(syn("203.0.113.9", 1000 + p, t + p * 0.1))
check("a scan is detected when the table was full of stale peers",
      any(a["rule"] == "port_scan" for a in e.list()))

# ---- a scan from a tracked host is detected even at the cap ----------------
e = engine()
for p in range(3):
    e._scan_rule(syn("203.0.113.9", 2000 + p, 5000.0))
for i in range(A.SCAN_PEERS_MAX):                      # fill with live peers
    e._scan_rule(syn("198.51.%d.%d" % (i // 250, i % 250), 22, 5000.5))
for p in range(3, A.SCAN_PORT_THRESHOLD + 1):
    e._scan_rule(syn("203.0.113.9", 2000 + p, 5001.0))
check("an already-tracked scanner still fires at the cap",
      any(a["rule"] == "port_scan" for a in e.list()))

sys.exit(1 if fails else 0)
