import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_block as B

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def refuses(fn, *a, **k):
    try:
        fn(*a, **k)
    except B.BlockError as e:
        return str(e)
    return None


class Fw:
    """A firewall that records the commands it is given."""
    def __init__(self):
        self.rules, self.cmds, self.fail_on = set(), [], None
        self.listed = ""            # what the PowerShell query reports
    def __call__(self, cmd):
        self.cmds.append(cmd)
        if cmd[0] == "powershell":
            return 0, self.listed
        name = next((a[5:] for a in cmd if a.startswith("name=")), "")
        if "add" in cmd:
            if self.fail_on and name.endswith(self.fail_on):
                return 1, "access denied"
            self.rules.add(name); return 0, "Ok."
        if "delete" in cmd:
            ok = name in self.rules
            self.rules.discard(name); return (0 if ok else 1), ""
        return (0 if name in self.rules else 1), ""


A = os.path.abspath
CHROME, SVCHOST, OWN = A("/opt/app/chrome.exe"), A("/win/svchost.exe"), A("/opt/ns/netscope.exe")


def make(fw=None, enabled=True, available=True, exe=CHROME):
    st = {"blocking_enabled": enabled}
    fw = fw or Fw()
    b = B.Blocker(lambda: st, st.__setitem__, run=fw, available=lambda: available,
                  local_ips=lambda: {"192.168.1.5"}, own_exes=[OWN],
                  program_path=lambda pid: {1: exe, 2: SVCHOST, 3: OWN}.get(pid, ""))
    return b, fw, st


# -- a host block -----------------------------------------------------------
b, fw, st = make()
e = b.block_host("203.0.113.9")
check("a host block makes an out and an in rule", len(fw.rules) == 2
      and all(n.startswith("NetScope-block-") for n in fw.rules), fw.rules)
add = [c for c in fw.cmds if "add" in c][0]
check("the rule blocks that remote address on every profile",
      "action=block" in add and "remoteip=203.0.113.9" in add and "profile=any" in add, add)
check("it is recorded in the settings", [x["id"] for x in st["blocks"]] == [e["id"]])
check("a second block of the same host is refused", refuses(b.block_host, "203.0.113.9") == "Already blocked.")

# -- with a port: outbound only ----------------------------------------------
b2, fw2, _ = make()
b2.block_host("203.0.113.9", 8443, "udp")
cmd = [c for c in fw2.cmds if "add" in c][0]
check("a port-scoped block is one outbound rule", len(fw2.rules) == 1 and "dir=out" in cmd, cmd)
check("...with the protocol and remote port", "protocol=UDP" in cmd and "remoteport=8443" in cmd, cmd)
check("a different port on the same host is its own block", b2.block_host("203.0.113.9", 22) and b2.count() == 2)

# -- addresses that must not be blocked -------------------------------------
for bad, why in (("not-an-ip", "text"), ("127.0.0.1", "loopback"), ("0.0.0.0", "wildcard"),
                 ("224.0.0.251", "multicast"), ("::1", "v6 loopback"), ("192.168.1.5", "own address"),
                 ("::ffff:192.168.1.5", "own address, mapped")):
    check("refuses " + why, refuses(b.block_host, bad) is not None)
check("a bad port is refused", refuses(b.block_host, "198.51.100.1", 70000) is not None)
check("scoped zone ids are stripped", b.block_host("fe80::1%eth0")["target"] == "fe80::1")

# -- programs ----------------------------------------------------------------
b, fw, st = make()
e = b.block_program(pid=1)
check("a program is blocked by the path the server looked up", "program=" + CHROME in
      [c for c in fw.cmds if "add" in c][0] and e["name"] == "chrome.exe")
check("only outbound", len(fw.rules) == 1 and next(iter(fw.rules)).endswith("-out"))
check("svchost is refused", "Windows" in (refuses(b.block_program, pid=2) or ""))
check("NetScope itself is refused", "NetScope" in (refuses(b.block_program, pid=3) or ""))
check("a pid with no path is refused", refuses(b.block_program, pid=99) is not None)

# -- a program known only by name (the timeline) ----------------------------
def named(path):
    st = {"blocking_enabled": True}; fw = Fw()
    return B.Blocker(lambda: st, st.__setitem__, run=fw, available=lambda: True,
                     own_exes=[OWN], name_path=lambda n: path if n == "chrome.exe" else ""), fw
b, fw = named(CHROME)
e = b.block_program(name="chrome.exe")
check("a name resolves to the path the server found", e["target"] == CHROME)
check("a name nothing resolves to is refused, saying why",
      "several" in (refuses(named(CHROME)[0].block_program, name="other.exe") or ""))
check("a resolved svchost is still refused", refuses(named(SVCHOST)[0].block_program, name="chrome.exe") is not None)

# -- gating ------------------------------------------------------------------
b, fw, st = make(enabled=False)
check("off by default means refused", "switched off" in (refuses(b.block_host, "203.0.113.9") or ""))
check("and no command ran", not fw.cmds)
b.set_enabled(True)
check("switching it on allows it", b.block_host("203.0.113.9") is not None)
b, fw, st = make(available=False)
check("without Windows/admin it is refused", "administrator" in (refuses(b.block_host, "203.0.113.9") or ""))

# -- a failed second rule rolls back the first ------------------------------
fw = Fw(); fw.fail_on = "-in"
b, fw, st = make(fw)
msg = refuses(b.block_host, "203.0.113.9")
check("a refused rule is reported", msg and "access denied" in msg, msg)
check("the half that did get made is removed", not fw.rules, fw.rules)
check("and nothing is recorded", not st.get("blocks"))

# -- unblocking -------------------------------------------------------------
b, fw, st = make()
e = b.block_host("203.0.113.9")
check("unblock removes the rules and the record", b.unblock(e["id"]) and not fw.rules and not st["blocks"])
check("unblocking something already gone is not an error", b.unblock(e["id"]) is None)
check("an id that is not one is refused", refuses(b.unblock, "x; calc") is not None)
st["blocking_enabled"] = False
e = None
b2, fw2, st2 = make()
e = b2.block_host("203.0.113.9"); st2["blocking_enabled"] = False
check("unblocking works even with blocking switched off", b2.unblock(e["id"]) is not None)

# -- listing: verified against the firewall ---------------------------------
b, fw, st = make()
e = b.block_host("203.0.113.9")
check("a block present in the firewall is active", b.listing()[0]["state"] == "active")
fw.rules.clear(); b._verified = (0.0, {})
check("a rule deleted outside NetScope reads missing, not blocked", b.listing()[0]["state"] == "missing")
fw.listed = "NetScope-block-deadbeef-out\nNetScope-block-deadbeef-in\nSome other rule\n"
b._orphans = (0.0, [])
l = b.listing()
check("a rule with no record is listed as unknown", [x["id"] for x in l if x["state"] == "unknown"] == ["deadbeef"], l)
fw.rules.update(["NetScope-block-deadbeef-out", "NetScope-block-deadbeef-in"])
check("and can be removed by id", b.unblock("deadbeef") is None and not fw.rules)
b, fw, st = make()
b.block_host("203.0.113.9")
b._available = lambda: False
check("a record that can't be checked says unverified, not blocked",
      [x["state"] for x in b.listing()] == ["unverified"])

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
