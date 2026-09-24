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


def tcp(direction, remote, dport, ts, flags="S", sport=40000, process=None):
    """A TCP record shaped the way CaptureEngine._build() makes one."""
    rec = {"dir": direction, "remote": remote, "sport": sport, "dport": dport,
           "ts": ts, "transport": "tcp",
           "decoded": {"tcp": {"flags": flags}}}
    if process:
        rec["process"] = process
    return rec

def udp(direction, remote, sport, dport, ts, process=None):
    rec = {"dir": direction, "remote": remote, "sport": sport, "dport": dport,
           "ts": ts, "transport": "udp", "decoded": {}}
    if process:
        rec["process"] = process
    return rec


# ---- 1. Inbound: one peer sending SYNs to N distinct local ports fires.
e = engine()
now = A._now()
for i in range(N):
    e._scan_rule(tcp("in", "45.33.12.9", 1000 + i, now))
check("inbound SYN burst to N distinct ports -> fires",
      titles(e) == ["Possible port scan from 45.33.12.9"], str(titles(e)))

# ---- 2. Inbound: fewer than N distinct ports stays quiet.
e = engine()
for i in range(N - 1):
    e._scan_rule(tcp("in", "45.33.12.9", 1000 + i, now))
check("inbound, N-1 distinct ports -> silent", e.list() == [], str(titles(e)))

# ---- 3. Same port hammered repeatedly is not a scan (no distinct growth).
e = engine()
for _ in range(50):
    e._scan_rule(tcp("in", "45.33.12.9", 443, now))
check("one port hammered -> silent", e.list() == [], str(titles(e)))

# ---- 4. Outbound: one process SYNing N distinct host/port pairs fires.
e = engine()
for i in range(N):
    e._scan_rule(tcp("out", f"10.0.0.{i}", 445, now, process="sketchy.exe"))
check("outbound fan-out of N distinct pairs -> fires",
      titles(e) == ["sketchy.exe is contacting many hosts/ports at once"], str(titles(e)))

# ---- 5. Outbound: normal traffic to one host/port is silent regardless of volume.
e = engine()
for _ in range(50):
    e._scan_rule(tcp("out", "93.184.216.34", 22, now, process="ssh.exe"))
check("repeated single destination -> silent", e.list() == [], str(titles(e)))

# ---- 6. A burst spread out past the window never accumulates enough distinct hits.
e = engine()
for i in range(N):
    e._scan_rule(tcp("in", "1.2.3.4", 2000 + i, now + i * (A.SCAN_WINDOW_SECS + 1)))
check("burst spread past the window -> silent", e.list() == [], str(titles(e)))

# ---- 7. Firing clears the window so the next packet doesn't double-fire immediately.
e = engine()
for i in range(N):
    e._scan_rule(tcp("in", "45.33.12.9", 1000 + i, now))
e._scan_rule(tcp("in", "45.33.12.9", 1000, now))
check("one alert per burst, not one per follow-on packet", len(e.list()) == 1, str(titles(e)))

# ---- 8. Rule can be disabled.
e = engine()
e.rules["port_scan"] = False
for i in range(N):
    e._scan_rule(tcp("in", "45.33.12.9", 1000 + i, now))
check("disabled rule -> silent", e.list() == [], str(titles(e)))

# ---- 9. Missing dport/peer/transport never crashes.
e = engine()
e._scan_rule({"dir": "in", "remote": "45.33.12.9", "ts": now, "transport": "tcp"})
e._scan_rule({"dir": "out", "process": "x.exe", "dport": 80, "ts": now})
e._scan_rule({"dir": "in", "dport": 80, "ts": now, "transport": "udp"})
e._scan_rule({"dir": "in", "remote": "45.33.12.9", "dport": 80, "ts": now})
check("missing fields -> no crash, silent", e.list() == [], str(titles(e)))

# ---- Ordinary traffic that used to look like a scan -------------------------
#
# The rule once counted every packet, so replies to this machine's own
# traffic — each arriving on a fresh ephemeral port — read as probes.

# ---- 10. A dozen DNS lookups: the replies land on random local ports.
e = engine()
for i in range(20):
    port = 50000 + i * 37
    e._scan_rule(udp("out", "192.168.1.1", port, 53, now + i * 0.5, process="svchost.exe"))
    e._scan_rule(udp("in", "192.168.1.1", 53, port, now + i * 0.5 + 0.02))
check("DNS replies on ephemeral ports -> silent", e.list() == [], str(titles(e)))

# ---- 11. Replies to our TCP connections (SYN-ACK, data) are not probes.
e = engine()
for i in range(20):
    e._scan_rule(tcp("in", "151.101.1.140", 50000 + i, now, flags="SA", sport=443))
    e._scan_rule(tcp("in", "151.101.1.140", 50000 + i, now, flags="PA", sport=443))
check("SYN-ACKs and data to many local ports -> silent", e.list() == [], str(titles(e)))

# ---- 12. One page load: a browser opening connections to many web hosts.
e = engine()
for i in range(40):
    e._scan_rule(tcp("out", f"151.101.{i}.1", 443 if i % 2 else 80, now + i * 0.1,
                     process="chrome.exe"))
    e._scan_rule(udp("out", f"142.250.{i}.1", 50000 + i, 443, now + i * 0.1,
                     process="chrome.exe"))    # QUIC
check("browser fan-out on web ports -> silent", e.list() == [], str(titles(e)))

# ---- 13. Unsolicited UDP to many local ports is still a scan.
e = engine()
for i in range(N):
    e._scan_rule(udp("in", "45.33.12.9", 40000, 100 + i, now))
check("unsolicited inbound UDP to N ports -> fires",
      titles(e) == ["Possible port scan from 45.33.12.9"], str(titles(e)))

# ---- 14. A reply only counts as one while it is recent.
e = engine()
e._scan_rule(udp("out", "45.33.12.9", 7000, 53, now, process="x.exe"))
for i in range(N):
    e._scan_rule(udp("in", "45.33.12.9", 53, 7000 if i == 0 else 7000 + i,
                     now + A.UDP_REPLY_TTL + 1))
check("an old outbound datagram no longer excuses inbound UDP",
      titles(e) == ["Possible port scan from 45.33.12.9"], str(titles(e)))

# ---- 15. Outbound UDP is remembered even while the rule is off.
e = engine()
e.rules["port_scan"] = False
for i in range(N):
    e._scan_rule(udp("out", "192.168.1.1", 50000 + i, 53, now, process="svchost.exe"))
e.rules["port_scan"] = True
for i in range(N):
    e._scan_rule(udp("in", "192.168.1.1", 53, 50000 + i, now + 0.1))
check("replies to datagrams sent while the rule was off -> silent",
      e.list() == [], str(titles(e)))

# ---- 16. The reply table stays bounded.
e = engine()
for i in range(A.UDP_SENT_MAX * 2):
    e._note_udp_sent(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", 5000, now)
check("remembered UDP endpoints stay bounded",
      len(e._udp_sent) <= A.UDP_SENT_MAX, str(len(e._udp_sent)))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
