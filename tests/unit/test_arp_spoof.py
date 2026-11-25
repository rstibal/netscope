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

def rec(iface, ip, mac, op=2, ts=1000.0):
    return {"iface": iface, "ts": ts, "decoded": {"arp": {"op": op, "sender_ip": ip,
                                                "sender_mac": mac,
                                                "target_ip": "192.168.1.1"}}}

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

# ---- 1. First sighting of an IP is the baseline, not an alert.
e = engine()
e._arp_rule(rec("Ethernet", "192.168.1.50", "aa:bb:cc:11:22:33"))
check("first sighting -> silent", e.list() == [], str(titles(e)))

# ---- 2. The same MAC claiming the same IP again stays silent.
e._arp_rule(rec("Ethernet", "192.168.1.50", "aa:bb:cc:11:22:33"))
check("repeat of the same binding -> silent", e.list() == [], str(titles(e)))

# ---- 3. A different MAC claiming an already-seen IP is held, then believed:
# a device that was swapped stays swapped (ArpWatch's hold, 60 s).
e._arp_rule(rec("Ethernet", "192.168.1.50", "de:ad:be:ef:00:01", ts=1001.0))
e.tick(1030.0)
check("changed MAC for a known IP -> nothing during the hold",
      e.list() == [], str(titles(e)))
e.tick(1001.0 + 61)
check("...then 'A device was replaced'",
      titles(e) == ["A device was replaced"], str(titles(e)))

# ---- 4. The same IP on a different adapter is a separate baseline, not a spoof.
e = engine()
e._arp_rule(rec("Ethernet", "192.168.1.50", "aa:bb:cc:11:22:33"))
e._arp_rule(rec("VPN", "192.168.1.50", "11:11:11:11:11:11"))
check("same IP on a different adapter -> silent", e.list() == [], str(titles(e)))

# ---- 5. An ARP probe (sender IP 0.0.0.0) is ignored.
e = engine()
e._arp_rule(rec("Ethernet", "0.0.0.0", "aa:bb:cc:11:22:33"))
check("ARP probe (0.0.0.0) -> silent", e.list() == [], str(titles(e)))

# ---- 6. Missing decoded.arp never crashes.
e = engine()
e._arp_rule({"iface": "Ethernet"})
e._arp_rule({})
check("no arp payload -> no crash, silent", e.list() == [], str(titles(e)))

# ---- 7. Rule can be disabled.
e = engine()
e.rules["arp_spoof"] = False
e._arp_rule(rec("Ethernet", "192.168.1.50", "aa:bb:cc:11:22:33"))
e._arp_rule(rec("Ethernet", "192.168.1.50", "de:ad:be:ef:00:01"))
check("disabled rule -> silent", e.list() == [], str(titles(e)))

# ---- 8. Two MACs alternating on one IP is an impersonation: one alert, not
# one per flip (plus the record of the first reclaim).
e = engine()
for i, mac in enumerate(["aa:bb:cc:11:22:33", "de:ad:be:ef:00:01"] * 3):
    e._arp_rule(rec("Ethernet", "192.168.1.50", mac, ts=1000.0 + i))
e.tick(1010.0)
alerts = [a for a in e.list() if a["title"].startswith("Another device")]
check("alternation on one IP -> one 'Another device is claiming' alert",
      len(alerts) == 1 and alerts[0]["title"] == "Another device is claiming 192.168.1.50"
      and alerts[0]["count"] == 1, str(e.list()))

# ---- 9. One reclaim is only a record: two devices claimed it.
e = engine()
for i, mac in enumerate(["aa:bb:cc:11:22:33", "de:ad:be:ef:00:01", "aa:bb:cc:11:22:33"]):
    e._arp_rule(rec("Ethernet", "192.168.1.50", mac, ts=1000.0 + i))
e.tick(1010.0)
check("one flip back -> 'Two devices claimed', warn",
      titles(e) == ["Two devices claimed 192.168.1.50"]
      and e.list()[0]["severity"] == "warn", str(e.list()))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
