"""
Six ways the dashboard reported something that wasn't so (found 1.33.4).

Each was seen on a real machine running PIA's VPN beside Chrome and Steam:

1. The VPN's encrypted outer copy of every tunnelled packet counted in the
   live totals and the Programs list, so the totals were about double and
   pia-openvpn.exe was the "top program". The History already left it out.
2. Several programs bind UDP 5353 (mDNS) at once. The socket table kept one
   owner per port, whichever came last, so mDNS was credited at random.
3. A plain-HTTP Host header ("10.0.0.70:7678") became the host's name, port
   and all, and a lowercase "host:" header was missed.
4. The check-in rule took multicast groups (224.0.0.251, ff02::c) for hosts
   being contacted on a schedule.
5. Chrome-based apps send a 1-byte TCP keepalive every 45 s on an idle
   connection, which the check-in test read as a schedule.
6. Multicast announcements (a router's SSDP to ff02::c) counted as traffic
   with that host, putting the router near the top of the host totals.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N
import netscope_alerts as A
import netscope_history as H
import netscope_timeline as T
from netscope_l2 import is_group_ip


def rec(**kw):
    r = {"ts": 1000.0, "seq": 0, "src": "10.0.0.2", "dst": "203.0.113.5",
         "remote": "203.0.113.5", "sport": 50000, "dport": 443, "proto": "TCP",
         "transport": "tcp", "length": 100, "payload_len": 46, "process": "app.exe",
         "pid": 1, "dir": "out", "rhost": "", "info": "", "iface": "Wi-Fi"}
    r.update(kw)
    return r


# ---- is_group_ip ---------------------------------------------------------------
check("group addresses recognised",
      all(is_group_ip(a) for a in ("224.0.0.251", "239.255.255.250", "255.255.255.255",
                                   "192.168.0.255", "ff02::fb", "FF02::C", "ff02::1:3%12")))
check("unicast addresses are not groups",
      not any(is_group_ip(a) for a in ("192.168.0.1", "8.8.8.8", "fe80::1", "2001:db8::1",
                                       "", None, "github.com")))

# The page's Timeline applies the same test (isGroupIP in netscope_ui.py).
import json, re, shutil, subprocess, tempfile
node = shutil.which("node")
if not node:
    print("SKIP  isGroupIP parity (node not found)")
else:
    ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    src = open(os.path.join(ROOT, "netscope_ui.py"), encoding="utf-8").read()
    fn = re.search(r"function isGroupIP\(a\)\{.*?\n\}", src, re.S).group(0)
    cases = ["224.0.0.251", "239.255.255.250", "223.255.255.1", "240.0.0.1",
             "255.255.255.255", "192.168.0.255", "192.168.0.1", "ff02::fb", "FF02::C",
             "ff02::1:3%12", "fe80::1", "2001:db8::1", "", "github.com", "1.2.3"]
    js = fn + "\nconsole.log(JSON.stringify(" + json.dumps(cases) + ".map(isGroupIP)));"
    tmp = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
    tmp.write(js); tmp.close()
    try:
        got = json.loads(subprocess.run([node, tmp.name], capture_output=True, text=True,
                                        timeout=30).stdout)
    finally:
        os.unlink(tmp.name)
    want = [is_group_ip(c) for c in cases]
    check("page and server agree on what is multicast/broadcast", got == want,
          [(c, g, w) for c, g, w in zip(cases, got, want) if g != w])

# ---- 1. VPN outer copy stays out of the live totals ----------------------------
s = N.PacketStore()
s.add(rec(length=1000, process="chrome.exe"), b"")
s.add(rec(length=1100, process="pia-openvpn.exe", remote="198.51.100.7",
          dst="198.51.100.7", tunnel_outer=True), b"")
st = s.stats()
names = [p["name"] for p in st["processes"]]
check("outer copy not in total bytes", st["total_out"] == 1000, st["total_out"])
check("outer copy not in the Programs list", names == ["chrome.exe"], names)
check("outer copy not in the host totals",
      [h["host"] for h in st["hosts"]] == ["203.0.113.5"], st["hosts"])
check("...but counted, so the page can say it left it out",
      st.get("tunnel_bytes") == 1100, st.get("tunnel_bytes"))
check("...and the packet itself is still in the table", st["total_packets"] == 2)

# ---- 2. Shared ports are not credited to one program at random ---------------
r = N.ProcessResolver()
r.available = True
r._local_ips = {"10.0.0.2"}

class C:
    def __init__(self, port, pid, kind):
        self.laddr = type("A", (), {"port": port})()
        self.pid = pid
        self.type = kind

import socket
conns = [C(5353, 11, socket.SOCK_DGRAM), C(5353, 12, socket.SOCK_DGRAM),
         C(50000, 13, socket.SOCK_STREAM), C(137, 4, socket.SOCK_DGRAM),
         C(1900, 20, socket.SOCK_DGRAM), C(1900, 21, socket.SOCK_DGRAM)]
names_by_pid = {11: "chrome.exe", 12: "svchost.exe", 13: "curl.exe", 4: "System",
                20: "svchost.exe", 21: "svchost.exe"}
real_conns, real_name = N.psutil.net_connections, r.name_for_pid
N.psutil.net_connections = lambda kind="inet": conns
r.name_for_pid = lambda pid: names_by_pid.get(pid, f"pid {pid}")
try:
    r.refresh()
    r._local_ips = {"10.0.0.2"}        # refresh() read this machine's real ones
    name, pid, d = r.lookup(5353, 5353, "udp", "10.0.0.2", "224.0.0.251")
    check("a port two programs share is labelled, not guessed",
          (name, pid) == ("(shared port)", None), (name, pid))
    name, pid, d = r.lookup(50000, 443, "tcp", "10.0.0.2", "203.0.113.5")
    check("an ordinary port still names its program", name == "curl.exe", name)
    name, pid, d = r.lookup(1900, 1900, "udp", "10.0.0.2", "239.255.255.250")
    check("two instances of the same program are still that program",
          name == "svchost.exe", name)
finally:
    N.psutil.net_connections = real_conns
check("(shared port) is counted as unattributed", "(shared port)" in N.UNOWNED)

# ---- 3. Host header names ------------------------------------------------------
check("port stripped from a Host header", N.host_from_header("example.com:8080") == "example.com")
check("an address is not a name", N.host_from_header("10.0.0.70:7678") == "")
check("bracketed IPv6 is not a name", N.host_from_header("[fe80::1]:80") == "")
check("plain name kept, lower-cased", N.host_from_header("Example.COM") == "example.com")
check("blank stays blank", N.host_from_header("") == "" and N.host_from_header(None) == "")
check("header lookup ignores case",
      N.header(dict([("host", "a.example")]), "Host") == "a.example")

# ---- 4 & 5. Timeline pairs: no multicast, no keepalive-only seconds -------------
t = T.Timeline()
for i in range(8):
    base = 10000 + i * 45
    # Chrome keepalive: 1-byte probe out, bare ACK in, every 45 s.
    t.observe(rec(ts=base, process="chrome.exe", rhost="mtalk.google.com",
                  length=41, payload_len=1))
    t.observe(rec(ts=base, process="chrome.exe", rhost="mtalk.google.com",
                  dir="in", length=52, payload_len=0))
    # A real check-in: data each time.
    t.observe(rec(ts=base + 3, process="agent.exe", rhost="c2.example",
                  length=300, payload_len=246))
    # mDNS to the group, every 45 s too.
    t.observe(rec(ts=base + 5, process="svchost.exe", remote="224.0.0.251",
                  dst="224.0.0.251", proto="MDNS", transport="udp",
                  length=80, payload_len=40, sport=5353, dport=5353))
    # The router's SSDP announcement, received on the group.
    t.observe(rec(ts=base + 7, process="svchost.exe", remote="fe80::1",
                  src="fe80::1", dst="ff02::c", dir="in", transport="udp",
                  proto="UDP", length=400, payload_len=340, sport=1900, dport=1900))
pairs = t.pair_activity()
check("keepalive-only seconds don't count as activity",
      not pairs.get(("chrome.exe", "mtalk.google.com")), pairs.get(("chrome.exe", "mtalk.google.com")))
check("a check-in that carries data still does",
      T.regular_interval(pairs.get(("agent.exe", "c2.example"), [])) == 45)
check("traffic to a multicast group is not a pair",
      ("svchost.exe", "224.0.0.251") not in pairs, list(pairs))
check("an announcement received on a group is not a pair either",
      ("svchost.exe", "fe80::1") not in pairs, list(pairs))
snap = t.snapshot()
check("each second says how many packets carried data",
      all(len(item) == 4 for _, items in snap["buckets"] for item in items))

e = A.AlertEngine()
e._dns_read = A._now()
fired = e.check_checkins(t)
check("the check-in alert fires only for the real one",
      [a["detail"].split(" contacts ")[0] for a in fired] == ["agent.exe"],
      [a["detail"] for a in fired])

# ---- 6. Multicast is not traffic with a host -----------------------------------
s = N.PacketStore()
s.add(rec(process="svchost.exe", remote="fe80::1", src="fe80::1", dst="ff02::c",
          dir="in", length=400), b"")
s.add(rec(process="chrome.exe", remote="224.0.0.251", dst="224.0.0.251", length=80), b"")
s.add(rec(process="chrome.exe", length=1000), b"")
st = s.stats()
check("live host totals leave multicast out",
      [h["host"] for h in st["hosts"]] == ["203.0.113.5"], [h["host"] for h in st["hosts"]])
check("...while the programs still count it",
      {p["name"] for p in st["processes"]} == {"svchost.exe", "chrome.exe"})

h = H.HistoryStore(path=":memory:")
h.record(rec(process="svchost.exe", remote="fe80::1", src="fe80::1", dst="ff02::c",
             dir="in", length=400))
h.record(rec(process="chrome.exe", remote="224.0.0.251", dst="224.0.0.251", length=80))
h.record(rec(process="chrome.exe", length=1000))
check("history hosts leave multicast out", sorted(h._hosts) == ["203.0.113.5"], sorted(h._hosts))
check("history pairs leave multicast out",
      sorted(k[3] for k in h._pairs) == ["203.0.113.5"], sorted(h._pairs))
check("history program usage still counts it",
      sum(v[0] + v[1] for v in h._acc.values()) == 1480)

e = A.AlertEngine()
e._dns_read = A._now()
e.warmup_until = 0
e.rules["new_host"] = True
e._change_rules(rec(process="chrome.exe", remote="224.0.0.251", dst="224.0.0.251"))
check("multicast is never a 'first contact with a host'",
      not [a for a in e.list() if a["rule"] == "new_host"], [a["title"] for a in e.list()])

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
