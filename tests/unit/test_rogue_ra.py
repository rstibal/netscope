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

def rec(iface, router, rdnss=None):
    ra = {"router": router, "router_lifetime": 1800, "managed": False,
          "other_config": False, "prefixes": [], "rdnss": rdnss or [],
          "source_link_layer": "aa:bb:cc:11:22:33"}
    return {"iface": iface, "decoded": {"ra": ra}}

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

# ---- 1. First router seen on an adapter is the baseline, not an alert.
e = engine()
e._ra_rule(rec("Ethernet", "fe80::1"))
check("first router -> silent", e.list() == [], str(titles(e)))

# ---- 2. The same router advertising again stays silent.
e._ra_rule(rec("Ethernet", "fe80::1"))
check("repeat of the same router -> silent", e.list() == [], str(titles(e)))

# ---- 3. A second, different router on the same adapter fires.
e._ra_rule(rec("Ethernet", "fe80::2"))
check("second router on the same adapter -> fires",
      titles(e) == ["Unexpected IPv6 router"], str(titles(e)))

# ---- 4. The alert names the RDNSS servers when the rogue router pushes them.
e = engine()
e._ra_rule(rec("Ethernet", "fe80::1"))
e._ra_rule(rec("Ethernet", "fe80::2", rdnss=[{"server": "fe80::2", "lifetime": 300}]))
detail = e.list()[0]["detail"] if e.list() else ""
check("RDNSS server named in the alert detail", "fe80::2" in detail, detail)

# ---- 5. The same router IP on a different adapter is a separate baseline.
e = engine()
e._ra_rule(rec("Ethernet", "fe80::1"))
e._ra_rule(rec("VPN", "fe80::1"))
check("same router IP on a different adapter -> silent", e.list() == [], str(titles(e)))

# ---- 6. Missing decoded.ra never crashes.
e = engine()
e._ra_rule({"iface": "Ethernet"})
e._ra_rule({})
check("no ra payload -> no crash, silent", e.list() == [], str(titles(e)))

# ---- 7. Rule can be disabled.
e = engine()
e.rules["rogue_ra"] = False
e._ra_rule(rec("Ethernet", "fe80::1"))
e._ra_rule(rec("Ethernet", "fe80::2"))
check("disabled rule -> silent", e.list() == [], str(titles(e)))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
