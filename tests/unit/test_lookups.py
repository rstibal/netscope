import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_lookups as LK
import netscope_latency as LT

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

# The Lookups view (1.50): each DNS query this machine sends, paired with its
# answer, kept for an hour as answered / refused / never answered.

L, S = "10.0.0.5", "10.0.0.1"
def q(ts, name, id_=7, lport=50000, server=S, proc="svchost.exe", iface="Wi-Fi", proto="DNS", outer=False, qtype="A"):
    rec = {"ts": ts, "src": L, "sport": lport, "dst": server, "dport": 53, "dir": "out",
           "proto": proto, "process": proc, "iface": iface, "remote": server,
           "decoded": {"dns": {"id": id_, "response": False, "queries": [{"name": name, "type": qtype}], "answers": []}}}
    if outer:
        rec["tunnel_outer"] = True
    return rec
def a(ts, name, rcode=0, id_=7, lport=50000, server=S, answers=1, iface="Wi-Fi", proto="DNS"):
    d = {"id": id_, "response": True, "queries": [{"name": name, "type": "A"}],
         "answers": [{"name": name, "type": "A", "data": "1.2.3.4"}] * answers}
    if rcode is not None:
        d["rcode"] = rcode
    return {"ts": ts, "src": server, "sport": 53, "dst": L, "dport": lport, "dir": "in",
            "proto": proto, "process": "svchost.exe", "iface": iface, "remote": server, "decoded": {"dns": d}}
def other(ts):
    return {"ts": ts, "src": L, "sport": 50001, "dst": "9.9.9.9", "dport": 443, "dir": "out",
            "proto": "TLS", "process": "chrome.exe", "iface": "Wi-Fi", "remote": "9.9.9.9", "decoded": {}}
def rows(lk, **kw):
    return lk.snapshot(**kw)["samples"]

# ---- answered
lk = LK.Lookups()
lk.observe(q(100.000, "github.com"))
check("a query on its own is not yet a lookup", rows(lk) == [], rows(lk))
lk.observe(a(100.012, "github.com"))
check("a query and its answer are one lookup: when, what, how it ended, how long, who asked whom",
      rows(lk) == [[100.0, "github.com", "A", "ok", 12.0, "svchost.exe", S, "Wi-Fi"]], rows(lk))
lk.observe(a(100.020, "github.com"))
check("the same answer again is not a second lookup", len(rows(lk)) == 1, rows(lk))

# ---- refused
lk = LK.Lookups()
lk.observe(q(100.0, "nope.example", id_=1)); lk.observe(a(100.030, "nope.example", rcode=3, id_=1, answers=0))
lk.observe(q(101.0, "broken.example", id_=2)); lk.observe(a(101.5, "broken.example", rcode=2, id_=2, answers=0))
lk.observe(q(102.0, "v4only.example", id_=3, qtype="AAAA")); lk.observe(a(102.01, "v4only.example", rcode=0, id_=3, answers=0))
lk.observe(q(103.0, "old.example", id_=4)); lk.observe(a(103.01, "old.example", rcode=None, id_=4))
got = [(r[1], r[3]) for r in rows(lk)]
check("a name that doesn't exist, and a server error, are failures of two kinds",
      got[:2] == [("nope.example", "nxdomain"), ("broken.example", "error")], got)
check("an answer with no addresses is still an answer", got[2] == ("v4only.example", "ok") and rows(lk)[2][2] == "AAAA", got)
check("a decode with no result code reads as answered", got[3] == ("old.example", "ok"), got)

# ---- never answered
lk = LK.Lookups()
lk.observe(q(100.0, "silent.example", id_=9))
lk.observe(other(104.9))
check("a query is given five seconds", rows(lk) == [], rows(lk))
lk.observe(other(105.1))
check("...then it is a lookup nobody answered, timed from when it was asked",
      rows(lk) == [[100.0, "silent.example", "A", "timeout", None, "svchost.exe", S, "Wi-Fi"]], rows(lk))
lk.observe(a(106.0, "silent.example", id_=9))
check("...and an answer that late does not make a second one", len(rows(lk)) == 1, rows(lk))

lk = LK.Lookups()
lk.observe(q(100.0, "retry.example", id_=5)); lk.observe(q(101.0, "retry.example", id_=5))
lk.observe(a(101.2, "retry.example", id_=5))
check("a query sent again is the same lookup, timed from the first", [(r[0], r[4]) for r in rows(lk)] == [(100.0, 1200.0)], rows(lk))

lk = LK.Lookups()
lk.observe(q(100.0, "quiet.example"))
check("with the capture quiet, reading it is what notices the silence",
      rows(lk, now=104.0) == [] and [r[3] for r in rows(lk, now=106.0)] == ["timeout"], rows(lk))

# ---- pairing
lk = LK.Lookups()
lk.observe(q(100.0, "a.example", id_=7, lport=50000)); lk.observe(q(100.0, "b.example", id_=7, lport=50001))
lk.observe(a(100.05, "b.example", id_=7, lport=50001)); lk.observe(a(100.09, "a.example", id_=7, lport=50000))
check("two lookups with one id are told apart by port", [(r[1], r[4]) for r in rows(lk)] == [("b.example", 50.0), ("a.example", 90.0)], rows(lk))
lk = LK.Lookups()
lk.observe(q(100.0, "a.example", server="10.0.0.1")); lk.observe(a(100.05, "a.example", server="8.8.8.8"))
check("an answer from a server that wasn't asked is not this lookup's", rows(lk) == [], rows(lk))
lk = LK.Lookups()
lk.observe(a(100.0, "a.example"))
check("an answer with no question seen is not a lookup", rows(lk) == [])

# ---- what is not a lookup
lk = LK.Lookups()
lk.observe(q(100.0, "printer.local", proto="MDNS")); lk.observe(a(100.01, "printer.local", proto="MDNS"))
lk.observe(q(100.0, "wpad", proto="LLMNR"))
lk.observe(q(100.0, "vpn.example", outer=True))
lk.observe(other(100.0)); lk.observe({"ts": 100.0})
lk.observe(other(110.0))
check("mDNS, LLMNR, the VPN's copy and everything else are left out", rows(lk) == [], rows(lk))
lk = LK.Lookups()
for i in range(LK.MAX_PENDING + 50):
    lk.observe(q(100.0 + i * 1e-6, "n%d.example" % i, id_=i % 65536, lport=1024 + i))
check("questions waiting for an answer are bounded", lk.pending() <= LK.MAX_PENDING, lk.pending())

# ---- read like the latency samples: a slice at a time, an hour, cleared
lk = LK.Lookups()
lk.observe(q(100.0, "a.example", id_=1)); lk.observe(a(100.01, "a.example", id_=1))
s = lk.snapshot()
lk.observe(q(101.0, "b.example", id_=2)); lk.observe(a(101.01, "b.example", id_=2))
s2 = lk.snapshot(after=s["next"], gen=s["gen"])
check("a second read gets only what is new", [r[1] for r in s2["samples"]] == ["b.example"] and s2["start"] == 1 and s2["next"] == 2, s2)
lk.clear()
s3 = lk.snapshot(after=s2["next"], gen=s2["gen"])
check("Clear empties it, the waiting questions too, and tells readers to start over",
      s3["samples"] == [] and s3["gen"] != s["gen"] and lk.pending() == 0, s3)
check("the store is the one the latency samples use", isinstance(lk.log, LT.SampleLog) and isinstance(LT.Latency(), LT.SampleLog))

print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
