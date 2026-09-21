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

def rec(iface, ip, mac, op=2):
    return {"iface": iface, "decoded": {"arp": {"op": op, "sender_ip": ip,
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

# ---- 3. A different MAC claiming an already-seen IP fires.
e._arp_rule(rec("Ethernet", "192.168.1.50", "de:ad:be:ef:00:01"))
check("changed MAC for a known IP -> fires",
      titles(e) == ["ARP binding changed"], str(titles(e)))

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

# ---- 8. Repeated flips on the same IP aggregate into one alert, not one per flip.
e = engine()
e._arp_rule(rec("Ethernet", "192.168.1.50", "aa:bb:cc:11:22:33"))
e._arp_rule(rec("Ethernet", "192.168.1.50", "de:ad:be:ef:00:01"))
e._arp_rule(rec("Ethernet", "192.168.1.50", "de:ad:be:ef:00:02"))
alerts = e.list()
check("repeated flips on one IP -> one alert entry, count grows",
      len(alerts) == 1 and alerts[0]["count"] == 2, str(alerts))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
