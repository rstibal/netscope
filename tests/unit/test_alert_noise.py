"""
Alerts that fired a lot and told you nothing.

From a real day's alert log (1.33.3):
- "pid 3376 has never used the network on this machine before" -- the name
  lookup had failed, so the subject was a recycled number nobody can act on,
  and it went into the history as a "program" for good.
- "OneDrive.exe used the network for the first time this session" -- a note
  for every known program after each restart. With history attached the
  database already says it is known; the note only buried the warnings.
- "pia-openvpn.exe has moved over 500 MB this session" -- the VPN client is
  credited with the encrypted outer copy of everything tunnelled, so it
  always crosses the threshold.
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


class FakeHistory:
    enabled, was_empty = True, False
    def __init__(self, known=(), hosts=()):
        self.known, self.hosts, self.noted = set(known), set(hosts), []
    def known_process(self, p): return p in self.known
    def note_process(self, p): self.noted.append(p); self.known.add(p)
    def known_host(self, h): return h in self.hosts
    def note_host(self, h): self.hosts.add(h)
    def record_alert(self, a): pass


def engine(history=None):
    e = A.AlertEngine(history=history)
    e._dns_read = A._now()
    e.warmup_until = 0
    return e


def titles(e):
    return [a["title"] for a in e.list()]


# ---- 1. An unnamed pid is not a program --------------------------------------
h = FakeHistory()
e = engine(h)
e._change_rules({"process": "pid 3376", "remote": "203.0.113.5", "length": 60})
check("an unnamed pid raises no new-program alert", e.list() == [], titles(e))
check("...and is not written to history as a program", h.noted == [], h.noted)
e._change_rules({"process": "(shared port)", "remote": "224.0.0.251", "length": 60})
check("a placeholder label is not a new program", e.list() == [], titles(e))
e._change_rules({"process": "vrmonitor.exe", "remote": "203.0.113.5", "length": 60})
check("once the name resolves, the real program still alerts",
      titles(e) == ["New program on the network"], titles(e))

# ---- 2. With history, a known program is silent ------------------------------
e = engine(FakeHistory(known={"OneDrive.exe"}))
e._change_rules({"process": "OneDrive.exe", "remote": "52.168.117.175", "length": 60})
check("known program, first packet this session -> no note", e.list() == [], titles(e))

e = engine(FakeHistory(known={"chrome.exe"}, hosts={"github.com"}))
e.rules["new_host"] = True
e._change_rules({"process": "chrome.exe", "rhost": "github.com", "dir": "out", "length": 60})
check("known host, first contact this session -> no note", e.list() == [], titles(e))
e._change_rules({"process": "chrome.exe", "rhost": "new.example", "dir": "out", "length": 60})
check("a genuinely new host still warns", titles(e) == ["First contact with a host"], titles(e))

# ---- 3. Without history, this session is all there is to go on ---------------
e = engine(None)
e._change_rules({"process": "curl.exe", "remote": "203.0.113.5", "length": 60})
check("no history -> first-this-session note still fires",
      titles(e) == ["Program started using the network"], titles(e))

# ---- 4. The VPN's outer copy does not count toward the threshold --------------
e = engine(None)
e.threshold_mb = 1
big = 600 * 1024
for _ in range(3):
    e._change_rules({"process": "pia-openvpn.exe", "remote": "198.51.100.7",
                     "length": big, "tunnel_outer": True})
check("tunnel outer copy never crosses the threshold",
      "Bandwidth threshold crossed" not in titles(e), titles(e))
for _ in range(3):
    e._change_rules({"process": "steam.exe", "remote": "198.51.100.8", "length": big})
check("ordinary traffic still crosses it",
      "Bandwidth threshold crossed" in titles(e), titles(e))

# ---- 5. CaptureEngine marks the outer copy before the alerts see it ----------
seen = []
class Spy:
    def inspect(self, rec, payload): seen.append(dict(rec))

eng = N.CaptureEngine(N.PacketStore(), N.ProcessResolver(), alerts=Spy())
eng.tunnel._is.update({"PIA": True, "Ethernet": False})
def built_rec(**kw):
    r = {"ts": 1.0, "seq": 0, "src": "10.0.0.2", "dst": "198.51.100.7",
         "remote": "198.51.100.7", "local": "10.0.0.2", "sport": 50000,
         "info": "", "rhost": "", "pid": None}
    r.update(kw)
    return r
built = iter([
    built_rec(proto="TCP", transport="tcp", dir="out", dport=443, process="chrome.exe", length=100),
    built_rec(proto="UDP", transport="udp", dir="out", dport=1194, process="pia-openvpn.exe", length=140),
])
eng._build = lambda pkt: (next(built), b"", b"")
eng._on_packet(None, "PIA")
eng._on_packet(None, "Ethernet")
check("inner packet on the tunnel adapter is not marked",
      not seen[0].get("tunnel_outer"), seen[0])
check("outer packet on the physical adapter is marked",
      seen[1].get("tunnel_outer") is True, seen[1])

# ---- 6. Erasing history starts a new baseline, not a flood of "new program"
import tempfile
import netscope_history as H
h = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(), "h.db"))
e = engine(h)
e.baselining = False
h.note_process("chrome.exe")
e._change_rules({"process": "chrome.exe", "remote": "203.0.113.5", "length": 60})
h.wipe()
e.history_wiped()
for proc in ("chrome.exe", "steam.exe", "OneDrive.exe"):
    e._change_rules({"process": proc, "remote": "203.0.113.5", "length": 60})
check("after Erase all history, programs are recorded quietly", e.list() == [], titles(e))
check("...including ones this run had already seen",
      h.known_process("chrome.exe") and h.known_process("steam.exe"))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
