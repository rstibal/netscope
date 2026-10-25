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
        self.rules, self.cmds, self.fail_set = {}, [], False
    def __call__(self, cmd):
        self.cmds.append(cmd)
        name = next((a[5:] for a in cmd if a.startswith("name=")), "")
        if "add" in cmd:
            self.rules[name] = cmd; return 0, "Ok."
        if "set" in cmd:
            if self.fail_set or name not in self.rules:
                return 1, "no"
            self.rules[name] = self.rules[name] + [cmd[-1]]; return 0, "Ok."
        if "delete" in cmd:
            ok = name in self.rules
            self.rules.pop(name, None); return (0 if ok else 1), ""
        return (0 if name in self.rules else 1), ""


A = os.path.abspath
CHROME, GAME = A("/opt/app/chrome.exe"), A("/opt/app/game.exe")


def make(name_ips=None, drop=None):
    st = {"blocking_enabled": True}
    fw = Fw()
    b = B.Blocker(lambda: st, st.__setitem__, run=fw, available=lambda: True,
                  local_ips=lambda: {"192.168.1.5"},
                  program_path=lambda pid: {1: CHROME, 2: GAME}.get(pid, ""),
                  name_ips=name_ips, drop=drop or (lambda e: 0), background=False)
    return b, fw, st

adds = lambda fw: [c for c in fw.cmds if "add" in c]


# -- direction and ports ------------------------------------------------------
b, fw, st = make()
b.block_host("203.0.113.9", dir="in")
check("a host can be blocked inbound only: one -in rule", list(fw.rules) and
      all(n.endswith("-in") for n in fw.rules) and "dir=in" in adds(fw)[0], list(fw.rules))
b.block_host("203.0.113.9")
check("...which is a different block from both ways", b.count() == 2)
check("the same inbound block twice is refused",
      refuses(b.block_host, "203.0.113.9", dir="in") == "Already blocked.")

b, fw, st = make()
e = b.block_host("203.0.113.9", lport=3389, proto="tcp")
cmd = adds(fw)[0]
check("a host to one local port is inbound only", e["dir"] == "in" and len(fw.rules) == 1
      and "dir=in" in cmd, cmd)
check("...with the local port and protocol", "localport=3389" in cmd and "protocol=TCP" in cmd
      and not any(a.startswith("remoteport") for a in cmd), cmd)
check("a remote and a local port together are refused",
      refuses(b.block_host, "203.0.113.9", port=443, lport=3389) is not None)
check("a bad local port is refused", refuses(b.block_host, "203.0.113.9", lport=0) is None
      and refuses(b.block_host, "198.51.100.2", lport="99999") is not None)

b, fw, st = make()
e = b.block_program(pid=2, dir="in")
cmd = adds(fw)[0]
check("a program can be blocked inbound only", e["dir"] == "in" and "dir=in" in cmd
      and "program=" + GAME in cmd and list(fw.rules)[0].endswith("-in"), cmd)
e2 = b.block_program(pid=2)
check("...and outbound, still the default, is its own block", e2["dir"] == "out" and b.count() == 2)
e3 = b.block_program(pid=2, lport=27015, proto="udp")
cmd = adds(fw)[-1]
check("a program on one local port is inbound to that port",
      e3["dir"] == "in" and "localport=27015" in cmd and "protocol=UDP" in cmd, cmd)

# -- entries from before 1.35 have no dir ---------------------------------------
old = [{"id": "aaaaaaaa", "kind": "host", "target": "203.0.113.1"},
       {"id": "bbbbbbbb", "kind": "host", "target": "203.0.113.1", "port": 443, "proto": "TCP"},
       {"id": "cccccccc", "kind": "program", "target": CHROME, "name": "chrome.exe"}]
check("an old host block reads as both ways", B.direction(old[0]) == "both"
      and len(B.Blocker.rule_names(old[0])) == 2)
check("an old host:port block reads as outbound", B.direction(old[1]) == "out")
check("an old program block reads as outbound", B.direction(old[2]) == "out"
      and B.Blocker.rule_names(old[2]) == ["NetScope-block-cccccccc-out"])
b, fw, st = make()
st["blocks"] = list(old)
check("a new both-ways block of an old one's host is a duplicate",
      refuses(b.block_host, "203.0.113.1") == "Already blocked.")
check("...as is an outbound block of an old program block",
      refuses(b.block_program, pid=1) == "Already blocked.")
check("...but inbound for that program is new", b.block_program(pid=1, dir="in")["dir"] == "in")

# -- by name ------------------------------------------------------------------
ips = {"tracker.example.com": ["198.51.100.7", "2001:db8::7", "127.0.0.1", "192.168.1.5"]}
b, fw, st = make(name_ips=lambda n: ips.get(n, []))
e = b.block_name("Tracker.Example.com.")
check("a name block is stored lower-case without the dot", e["target"] == "tracker.example.com")
check("it holds the name's usable addresses (not loopback or this machine)",
      e["ips"] == ["198.51.100.7", "2001:db8::7"], e["ips"])
check("both ways, one remoteip list", len(fw.rules) == 2 and
      all("remoteip=198.51.100.7,2001:db8::7" in c for c in adds(fw)), adds(fw))
check("a name with no known address is refused, saying why",
      "hasn't seen an address" in (refuses(b.block_name, "nothing.example.com") or ""))
check("an address is refused as a name", refuses(b.block_name, "203.0.113.9") is not None)
check("junk is refused as a name", refuses(b.block_name, "a b; calc") is not None)
check("the same name twice is refused", refuses(b.block_name, "tracker.example.com") == "Already blocked.")

# A CDN name behind a CNAME, the way www names usually answer.
before = len(fw.cmds)
b.note_dns([{"name": "tracker.example.com.", "type": "CNAME", "data": "edge.cdn.example.net."},
            {"name": "edge.cdn.example.net.", "type": "A", "data": "203.0.113.50"},
            {"name": "unrelated.example.org.", "type": "A", "data": "203.0.113.99"}])
sets = [c for c in fw.cmds[before:] if "set" in c]
check("a new address from a captured answer, through a CNAME, is added to both rules",
      len(sets) == 2 and all(c[-1] == "remoteip=198.51.100.7,2001:db8::7,203.0.113.50" for c in sets), sets)
check("...and remembered", st["blocks"][0]["ips"][-1] == "203.0.113.50")
check("an unrelated name's address is not", "203.0.113.99" not in st["blocks"][0]["ips"])
before = len(fw.cmds)
b.note_dns([{"name": "tracker.example.com", "type": "A", "data": "198.51.100.7"}])
check("an address it already has changes nothing", len(fw.cmds) == before)
b.note_dns([{"name": "tracker.example.com", "type": "A", "data": "192.168.1.5"}])
check("nor does this machine's own address", len(fw.cmds) == before)

fw.fail_set = True
b.note_dns([{"name": "tracker.example.com", "type": "A", "data": "203.0.113.51"}])
check("an address the firewall refused is not recorded as blocked",
      "203.0.113.51" not in st["blocks"][0]["ips"])
fw.fail_set = False

b2, fw2, st2 = make(name_ips=lambda n: ["198.51.100.1"])
b2.block_name("cdn.example.com")
b2.note_dns([{"name": "cdn.example.com", "type": "A", "data": "10.9.%d.%d" % (i // 250, i % 250 + 1)}
             for i in range(B.MAX_NAME_IPS + 5)])
e = st2["blocks"][0]
check("a name stops growing at the cap", len(e["ips"]) == B.MAX_NAME_IPS, len(e["ips"]))
check("...and says it reached it", e.get("capped") is True)

b.unblock(st["blocks"][0]["id"])
before = len(fw.cmds)
b.note_dns([{"name": "tracker.example.com", "type": "A", "data": "203.0.113.60"}])
check("once unblocked, its answers are ignored", len(fw.cmds) == before)

# The thread version gets there too.
st3 = {"blocking_enabled": True}; fw3 = Fw()
b3 = B.Blocker(lambda: st3, st3.__setitem__, run=fw3, available=lambda: True,
               name_ips=lambda n: ["198.51.100.1"], drop=lambda e: 0)
b3.block_name("x.example.com")
b3.note_dns([{"name": "x.example.com", "type": "AAAA", "data": "2001:db8::9"}])
import time
for _ in range(50):
    if "2001:db8::9" in st3["blocks"][0]["ips"]: break
    time.sleep(0.05)
check("in the background, too", "2001:db8::9" in st3["blocks"][0]["ips"])

# -- ending open connections --------------------------------------------------
def c(pid, lport, rip, rport, status="ESTABLISHED"):
    return {"pid": pid, "status": status, "lip": "192.168.1.5", "lport": lport,
            "rip": rip, "rport": rport}
CONNS = [c(1, 51000, "203.0.113.9", 443), c(1, 51001, "203.0.113.9", 80),
         c(2, 0, "", 0, "LISTEN") | {"lport": 27015}, c(2, 27015, "203.0.113.9", 60000),
         c(2, 52000, "198.51.100.7", 443), c(1, 51002, "203.0.113.9", 443, "TIME_WAIT")]
exe = {1: CHROME, 2: GAME}.get
pick = lambda e: sorted((x["pid"], x["lport"]) for x in B.connections_to_drop(e, CONNS, exe))
check("a host block ends every open connection with it", pick({"kind": "host", "target": "203.0.113.9"})
      == [(1, 51000), (1, 51001), (2, 27015)])
check("...a host:port block only those to that port",
      pick({"kind": "host", "target": "203.0.113.9", "port": 443, "proto": "TCP"}) == [(1, 51000)])
check("...a UDP-scoped block none (Windows can only end TCP)",
      pick({"kind": "host", "target": "203.0.113.9", "port": 443, "proto": "UDP"}) == [])
check("an inbound-only host block only the ones it made to a listening port",
      pick({"kind": "host", "target": "203.0.113.9", "dir": "in"}) == [(2, 27015)])
check("an outbound program block leaves what connected to its server",
      pick({"kind": "program", "target": GAME, "dir": "out"}) == [(2, 52000)])
check("an inbound program block only that",
      pick({"kind": "program", "target": GAME, "dir": "in"}) == [(2, 27015)])
check("a name block ends connections to any of its addresses",
      pick({"kind": "name", "target": "t", "ips": ["198.51.100.7"], "dir": "both"}) == [(2, 52000)])

got = []
b, fw, st = make(drop=lambda e: got.append(e["target"]) or 3)
e = b.block_host("203.0.113.9")
check("a block ends what is open and says how many", got == ["203.0.113.9"] and e["dropped"] == 3)
check("the count isn't stored with the block", "dropped" not in st["blocks"][0])
b, fw, st = make(drop=lambda e: 1 / 0)
check("a failure ending them doesn't undo the block", b.block_host("203.0.113.9")["dropped"] == 0
      and b.count() == 1)

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
