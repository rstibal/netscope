import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
from netscope_conn import FlowTable
import netscope_latency as LT

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

# The Latency view (1.49): one sample per outbound TCP handshake, kept for an
# hour, handed to the page a slice at a time.

L, R = "10.0.0.5", "1.2.3.4"
def pkt(ts, d, flags, lport=5000, rport=443, remote=R, proc="chrome.exe", host="", iface="Wi-Fi", outer=False):
    out = d == "out"
    rec = {"src": L if out else remote, "sport": lport if out else rport,
           "dst": remote if out else L, "dport": rport if out else lport,
           "transport": "tcp", "iface": iface, "dir": d, "length": 66, "payload_len": 0,
           "ts": ts, "process": proc, "rhost": host, "remote": remote,
           "decoded": {"tcp": {"flags": flags, "seq": 1, "ack": 1, "window": 64240}}}
    if outer:
        rec["tunnel_outer"] = True
    return rec

# ---- the flow table says when a handshake has been timed
got = []
ft = FlowTable()
ft.on_rtt = lambda rec, f: got.append((rec["ts"], f["rtt"], f["process"], rec["remote"], rec["sport"], rec["iface"]))
ft.observe(pkt(100.000, "out", "S"))
ft.observe(pkt(100.042, "in", "SA"))
ft.observe(pkt(100.043, "out", "A"))
check("a timed handshake is reported once, with who and where",
      got == [(100.042, 42.0, "chrome.exe", R, 443, "Wi-Fi")], got)
ft.observe(pkt(100.300, "in", "SA"))            # the SYN/ACK sent again
check("...and a repeated SYN/ACK is not a second sample", len(got) == 1, got)

got.clear()
ft = FlowTable()
ft.on_rtt = lambda rec, f: got.append(f["rtt"])
ft.observe(pkt(100.0, "in", "S", lport=8080, rport=51000))
ft.observe(pkt(100.001, "out", "SA", lport=8080, rport=51000))
check("a connection someone else opened is not timed", got == [], got)
ft = FlowTable()
ft.on_rtt = lambda rec, f: 1 / 0
ft.observe(pkt(100.000, "out", "S"))
try:
    ft.observe(pkt(100.042, "in", "SA"))
    ok = True
except Exception as e:
    ok = False
check("a failing listener never breaks packet accounting", ok and list(ft.snapshot().values())[0]["packets"] == 2)
ft = FlowTable()                                # no listener at all
ft.observe(pkt(100.000, "out", "S")); ft.observe(pkt(100.042, "in", "SA"))
check("no listener is fine", list(ft.snapshot().values())[0]["rtt"] == 42.0)

# ---- the store
lt = LT.Latency()
lt.note(1000.5, 24.0, "chrome.exe", "github.com", "140.82.112.3", 443, "eth0")
lt.note(1001.5, 180.0, "steam.exe", "", "23.1.2.3", 443, "eth0")
s = lt.snapshot()
check("samples come back in order, as lists",
      s["samples"] == [[1000.5, 24.0, "chrome.exe", "github.com", "140.82.112.3", 443, "eth0"],
                       [1001.5, 180.0, "steam.exe", "", "23.1.2.3", 443, "eth0"]], s["samples"])
check("...with where they start, where the next read starts and the newest time",
      (s["start"], s["next"], s["newest"]) == (0, 2, 1001.5), (s["start"], s["next"], s["newest"]))
s2 = lt.snapshot(after=s["next"], gen=s["gen"])
check("a read from where the last one ended is empty", s2["samples"] == [] and s2["next"] == 2, s2)
lt.note(1002.0, 30.0, "chrome.exe", "github.com", "140.82.112.3", 443, "eth0")
s3 = lt.snapshot(after=s["next"], gen=s["gen"])
check("...and then only what is new", [x[0] for x in s3["samples"]] == [1002.0] and s3["start"] == 2 and s3["next"] == 3, s3)

s4 = lt.snapshot(name_for=lambda ip: {"23.1.2.3": "cdn.steam.example"}.get(ip))
check("a host named after its handshake is named when read",
      [x[3] for x in s4["samples"]] == ["github.com", "cdn.steam.example", "github.com"], s4["samples"])
check("...without changing a name it already had, or the stored sample",
      lt.snapshot()["samples"][1][3] == "", lt.snapshot()["samples"][1])

# ---- an hour, and a cap
lt = LT.Latency(retain=3600)
lt.note(1000.0, 10.0, "a.exe", "old.example", "1.1.1.1", 443, "eth0")
lt.note(1000.0 + 3601, 10.0, "a.exe", "new.example", "1.1.1.2", 443, "eth0")
s = lt.snapshot()
check("samples older than the hour are dropped", [x[3] for x in s["samples"]] == ["new.example"] and s["start"] == 1, s)
check("...and a reader behind the drop is given what is left, from where it starts",
      lt.snapshot(after=0, gen=s["gen"])["start"] == 1)

lt = LT.Latency(max_samples=50)
for i in range(120):
    lt.note(2000.0 + i, float(i), "a.exe", "h", "1.1.1.1", 443, "eth0")
s = lt.snapshot()
check("the store is capped, keeping the newest", len(s["samples"]) == 50 and s["samples"][-1][1] == 119.0 and s["next"] == 120,
      (len(s["samples"]), s["next"]))

g = s["gen"]
lt.clear()
s = lt.snapshot(after=120, gen=g)
check("Clear empties it and tells readers to start over", s["samples"] == [] and s["gen"] != g and s["start"] == 0 and s["next"] == 0, s)

lt.note(3000.0, -5.0, "a.exe", "h", "1.1.1.1", 443, "eth0")
lt.note(3000.0, None, "a.exe", "h", "1.1.1.1", 443, "eth0")
check("a time that makes no sense is not kept", lt.snapshot()["samples"] == [], lt.snapshot()["samples"])

print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
