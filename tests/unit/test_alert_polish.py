"""
Alert wording: FTP or POP3 by port, host names over bare addresses, and the
bandwidth threshold counted per hour rather than per session.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_alerts as A

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def engine():
    e = A.AlertEngine(A.DesktopNotifier(enabled=False))
    e.warmup_until = 0
    return e

def rec(**kw):
    r = {"process": "client.exe", "remote": "203.0.113.77", "rhost": "", "sport": 50000,
         "dport": 21, "dir": "out", "length": 80}
    r.update(kw)
    return r

# -- FTP or POP3 ------------------------------------------------------------------
e = engine()
e._transport_rules(rec(dport=21), b"USER rob\r\n")
t = [a["title"] for a in e.list()]
check("USER on port 21 is FTP", "Unencrypted FTP username" in t, t)
e = engine()
e._transport_rules(rec(dport=110), b"PASS hunter2\r\n")
t = [a["title"] for a in e.list()]
check("PASS on port 110 is POP3", "Unencrypted POP3 password" in t, t)
check("...not FTP/POP3", not any("FTP/POP3" in x for x in t), t)
e = engine()
e._transport_rules(rec(dport=143), b"a1 LOGIN rob hunter2\r\n")
check("IMAP stays IMAP", "Unencrypted IMAP credentials" in [a["title"] for a in e.list()])

# -- names over bare addresses ------------------------------------------------------
e = engine()
e._transport_rules(rec(dport=21, rhost="legacy-ftp.example.com"), b"USER rob\r\n")
d = [a["detail"] for a in e.list()]
check("a known name leads, the address in brackets",
      all("legacy-ftp.example.com (203.0.113.77)" in x for x in d) and d, d)
e._transport_rules(rec(dport=21, rhost=""), b"USER rob\r\n")
check("the same peer before its name was known isn't a second alert",
      len(e.list()) == len(d), [a["detail"] for a in e.list()])
e = engine()
e._transport_rules(rec(dport=21), b"USER rob\r\n")
check("with no name, the address alone",
      all("to 203.0.113.77 " in a["detail"] for a in e.list()), [a["detail"] for a in e.list()])
check("peer_label with a name equal to the address shows it once",
      A.peer_label({"remote": "203.0.113.77", "rhost": "203.0.113.77"}) == "203.0.113.77")

# -- per hour ------------------------------------------------------------------------
e = engine()
e.threshold_mb = 1
MB = 1024 * 1024
t0 = 1_800_000_000.0
def move(mb, at, proc="steam.exe"):
    e._change_rules({"process": proc, "remote": "198.51.100.8", "length": int(mb * MB), "ts": at})
crossed = lambda: [a for a in e.list() if a["title"] == "Bandwidth threshold crossed"]
for i in range(4):
    move(0.4, t0 + i * 1200)          # every 20 minutes: 1.2 MB within 40 of them
check("1.2 MB inside one hour crosses 1 MB/hour, once", len(crossed()) == 1, crossed())
check("the alert says per hour", "in the last hour" in crossed()[0]["detail"], crossed()[0]["detail"])

e = engine(); e.threshold_mb = 1
for i in range(6):
    move(0.3, t0 + i * 1800)          # 0.6 MB per hour at most
check("a slow trickle over a long session never fires, unlike a per-session count",
      crossed() == [], crossed())
check("the hour's count is only the last hour", e.hourly_bytes("steam.exe") <= int(0.6 * MB) + 1,
      e.hourly_bytes("steam.exe"))

e = engine(); e.threshold_mb = 1
move(1.2, t0)
check("crossing fires", len(crossed()) == 1 and crossed()[0]["count"] == 1)
move(0.1, t0 + 60)
check("staying over doesn't fire again", crossed()[0]["count"] == 1)
move(0.01, t0 + 3700)                 # the burst has left the hour
move(1.2, t0 + 3800)
check("dropping under and crossing again counts again", crossed()[0]["count"] == 2,
      crossed()[0]["count"])

e = engine(); e.threshold_mb = 1
move(0.6, t0); move(0.6, t0, "other.exe")
check("each program has its own hour", crossed() == [])

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
