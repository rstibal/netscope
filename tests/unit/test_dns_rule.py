import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys; import netscope_alerts as A

def rec(server, iface, proc="svchost.exe"):
    return {"proto": "DNS", "dir": "out", "remote": server, "iface": iface,
            "process": proc, "length": 80}

def engine(configured=None, by_iface=None):
    e = A.AlertEngine()
    e._dns_read = A._now()          # stop it re-reading the real machine
    e.dns_configured = configured
    e.dns_by_iface = by_iface or {}
    return e

def titles(e):
    return [a["title"] for a in e.list()]

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

# ---- 1. Rob's case: dual-homed, each adapter has its own configured resolver.
e = engine({"192.168.1.1", "10.0.0.38"},
           {"Wi-Fi": {"192.168.1.1"}, "Ethernet": {"10.0.0.38"}})
for _ in range(200): e._dns_rule(rec("192.168.1.1", "Wi-Fi"))
for _ in range(40):  e._dns_rule(rec("10.0.0.38", "Ethernet"))
check("dual-homed, both configured -> silent", e.list() == [], str(titles(e)))

# ---- 2. Same but no OS answer: statistics per interface must also stay quiet.
e = engine(None)
for _ in range(200): e._dns_rule(rec("192.168.1.1", "Wi-Fi"))
for _ in range(40):  e._dns_rule(rec("10.0.0.38", "Ethernet"))
check("dual-homed, no OS answer -> silent (per-iface stats)", e.list() == [], str(titles(e)))

# ---- 3. The old rule fired here. Prove the old logic would have.
old = {}
for _ in range(200): old["192.168.1.1"] = old.get("192.168.1.1", 0) + 1
for _ in range(40):  old["10.0.0.38"] = old.get("10.0.0.38", 0) + 1
primary = max(old, key=old.get)
check("old global rule WOULD have fired (regression guard)",
      len(old) >= 2 and old[primary] >= 20 and old["10.0.0.38"] > 3)

# ---- 4. Genuine finding: a server nothing on the box is configured to use.
e = engine({"192.168.1.1"}, {"Wi-Fi": {"192.168.1.1"}})
for _ in range(200): e._dns_rule(rec("192.168.1.1", "Wi-Fi"))
for _ in range(10):  e._dns_rule(rec("45.33.12.9", "Wi-Fi", "sketchy.exe"))
check("unconfigured resolver -> fires", titles(e) == ["DNS to an unconfigured resolver"], str(titles(e)))
if e.list():
    d = e.list()[0]["detail"]
    check("message names iface + configured set", "on Wi-Fi" in d and "192.168.1.1" in d, d)

# ---- 5. A configured secondary, however rare, is not an alert.
e = engine({"8.8.8.8", "8.8.4.4"}, {"Wi-Fi": {"8.8.8.8", "8.8.4.4"}})
for _ in range(300): e._dns_rule(rec("8.8.8.8", "Wi-Fi"))
for _ in range(25):  e._dns_rule(rec("8.8.4.4", "Wi-Fi"))
check("configured secondary -> silent", e.list() == [], str(titles(e)))

# ---- 6. One stray packet is not a pattern.
e = engine({"192.168.1.1"})
for _ in range(50): e._dns_rule(rec("192.168.1.1", "Wi-Fi"))
e._dns_rule(rec("1.2.3.4", "Wi-Fi"))
e._dns_rule(rec("1.2.3.4", "Wi-Fi"))
check("2 strays -> silent", e.list() == [], str(titles(e)))
e._dns_rule(rec("1.2.3.4", "Wi-Fi"))
check("3rd stray -> fires", len(e.list()) == 1, str(titles(e)))

# ---- 7. Fallback statistics still catch a real change on one interface.
e = engine(None)
for _ in range(50): e._dns_rule(rec("192.168.1.1", "Wi-Fi"))
for _ in range(5):  e._dns_rule(rec("45.33.12.9", "Wi-Fi"))
check("fallback stats still fire on one iface", titles(e) == ["DNS to an unexpected resolver"], str(titles(e)))

# ---- 8. Same server on two interfaces alerts separately, not merged.
e = engine({"192.168.1.1"})
for i in ("Wi-Fi", "Ethernet"):
    for _ in range(30): e._dns_rule(rec("192.168.1.1", i))
    for _ in range(5):  e._dns_rule(rec("9.9.9.9", i))
check("per-interface alert keys", len(e.list()) == 2, str(len(e.list())))

# ---- 9. Inbound and non-DNS ignored; no crash on a missing iface.
e = engine({"192.168.1.1"})
e._dns_rule({"proto": "DNS", "dir": "in", "remote": "6.6.6.6", "iface": "Wi-Fi"})
e._dns_rule({"proto": "TLS", "dir": "out", "remote": "6.6.6.6", "iface": "Wi-Fi"})
for _ in range(5): e._dns_rule({"proto": "DNS", "dir": "out", "remote": "6.6.6.6"})
check("inbound/non-DNS ignored, blank iface safe", len(e.list()) == 1, str(titles(e)))

# ---- 10. POSIX resolv.conf reader.
import tempfile, os as _os, unittest.mock as mock
with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
    fh.write("# comment\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nsearch lan\n")
    path = fh.name
real_open = open
with mock.patch.object(A.os, "name", "posix"):
    with mock.patch("builtins.open", lambda p, *a, **k: real_open(path if p == "/etc/resolv.conf" else p, *a, **k)):
        got, by = A.configured_resolvers()
check("resolv.conf parsed", got == {"127.0.0.53", "192.168.1.1"}, str(got))
_os.unlink(path)

# ---- IPv6 resolvers -----------------------------------------------------------
#
# The OS query used to ask for IPv4 servers only, so on a dual-stack network
# every query to a configured IPv6 resolver was judged "unconfigured".

# ---- The PowerShell answer: one row per adapter *per family*, merged.
ps = [
    {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["192.168.1.1"]},
    {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["FE80:0:0:0::1%12", "2001:DB8::53"]},
    {"InterfaceAlias": "Loopback", "ServerAddresses": []},
]
every, by = A._parse_resolvers(ps)
check("both families are read and normalised",
      every == {"192.168.1.1", "fe80::1", "2001:db8::53"}, str(every))
check("an adapter's v4 and v6 rows merge rather than overwrite",
      by.get("Wi-Fi") == {"192.168.1.1", "fe80::1", "2001:db8::53"}, str(by))
check("a single adapter (not an array) still parses",
      A._parse_resolvers({"InterfaceAlias": "E", "ServerAddresses": "10.0.0.1"})[0]
      == {"10.0.0.1"})
check("no resolvers at all -> (None, None)", A._parse_resolvers([]) == (None, None))

# ---- A configured IPv6 resolver is not an alert, however it is spelled.
e = engine(every, by)
for _ in range(20): e._dns_rule(rec("fe80::1", "Wi-Fi"))
for _ in range(20): e._dns_rule(rec("2001:db8::53", "Wi-Fi"))
check("DNS to configured IPv6 resolvers -> silent", e.list() == [], str(titles(e)))

# ---- An unconfigured IPv6 resolver still is.
for _ in range(5): e._dns_rule(rec("2606:4700:4700::1111", "Wi-Fi"))
check("DNS to an unconfigured IPv6 resolver -> fires",
      titles(e) == ["DNS to an unconfigured resolver"], str(titles(e)))

check("normalise_ip leaves a non-address alone",
      A.normalise_ip("not-an-ip") == "not-an-ip" and A.normalise_ip(None) == "")

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
