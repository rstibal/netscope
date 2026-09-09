import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, json, unittest.mock as mock
import netscope_alerts as A

class R:
    def __init__(self, out): self.stdout = out; self.returncode = 0

def run_with(out):
    with mock.patch.object(A.os, "name", "nt"):
        with mock.patch.object(A.subprocess, "run", return_value=R(out)):
            return A.configured_resolvers()

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

# Two adapters — the shape Rob's machine would return.
out = json.dumps([
    {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["192.168.1.1"]},
    {"InterfaceAlias": "Ethernet", "ServerAddresses": ["10.0.0.38", "10.0.0.1"]},
    {"InterfaceAlias": "Loopback", "ServerAddresses": []},
])
got, by = run_with(out)
check("multi-adapter parsed", got == {"192.168.1.1", "10.0.0.38", "10.0.0.1"}, str(got))
check("per-iface map", by.get("Ethernet") == {"10.0.0.38", "10.0.0.1"}, str(by))
check("adapter with no resolver skipped", "Loopback" not in by, str(list(by)))

# PowerShell collapses a single object out of ConvertTo-Json.
got, by = run_with(json.dumps({"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["1.1.1.1"]}))
check("single object (not array)", got == {"1.1.1.1"}, str(got))

# One server can come back as a bare string rather than a list.
got, by = run_with(json.dumps([{"InterfaceAlias": "Wi-Fi", "ServerAddresses": "1.1.1.1"}]))
check("bare string server", got == {"1.1.1.1"}, str(got))

# Junk / empty / failure must yield (None, None) so the rule falls back.
for label, out in [("empty stdout", ""), ("null", "null"), ("garbage", "not json"),
                   ("no servers anywhere", json.dumps([{"InterfaceAlias":"X","ServerAddresses":[]}]))]:
    got, by = run_with(out)
    check(f"{label} -> (None, None)", got is None and by is None, str(got))

with mock.patch.object(A.os, "name", "nt"):
    with mock.patch.object(A.subprocess, "run", side_effect=OSError("no powershell")):
        got, by = A.configured_resolvers()
check("powershell missing -> (None, None)", got is None, str(got))

# refresh_dns_config must never raise and must keep the old value on failure.
e = A.AlertEngine(); e.dns_configured = {"192.168.1.1"}
with mock.patch.object(A, "configured_resolvers", side_effect=RuntimeError("boom")):
    e.refresh_dns_config()
check("refresh survives an exception, keeps prior value", e.dns_configured == {"192.168.1.1"}, str(e.dns_configured))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
