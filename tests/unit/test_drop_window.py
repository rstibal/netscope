"""
"Dropping N%" says whether packets are being lost now, and where.

The driver's counters run from when each adapter's capture opened, so the
header's figure used to be a lifetime average: a burst at startup read as
loss for the rest of the run, and with several adapters there was no saying
which one. capture_stats() now adds the last minute and a per-adapter split.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N

eng = N.CaptureEngine(N.PacketStore(), N.ProcessResolver())

# ---- the last minute, from successive readings of running totals ------------
r = eng._recent_drops(1000, 0, now=100.0)
check("first reading: nothing to compare yet", r["dropped"] == 0 and r["secs"] == 0, r)
r = eng._recent_drops(5000, 400, now=130.0)
check("losses since the first reading", (r["received"], r["dropped"]) == (4000, 400), r)
check("...as a share of what reached the driver", r["loss_pct"] == round(400 * 100 / 4400, 2), r)
for t in range(131, 200):
    r = eng._recent_drops(5000 + (t - 130) * 100, 400, now=float(t))
check("a burst over a minute ago no longer counts",
      r["dropped"] == 0 and 55 <= r["secs"] <= 61, r)
r = eng._recent_drops(10, 0, now=200.0)
check("counters that go backwards (capture reopened) start the window over",
      r["dropped"] == 0 and r["received"] == 0, r)

# ---- totals and the per-adapter split, from stand-in sockets -----------------
stats = {"wifi": (60000, 9990, 10), "eth": (30000, 0, 0)}
real = N.pcap_stats_for
N.pcap_stats_for = lambda sock: stats.get(sock.name)
class Sock:
    def __init__(self, name): self.name, self.closed = name, False
eng.sniffers = [("Wi-Fi", None, Sock("wifi")), ("Ethernet", None, Sock("eth"))]
try:
    st = eng.capture_stats()
finally:
    N.pcap_stats_for = real
check("totals add up across adapters",
      (st["received"], st["dropped"], st["buffer_dropped"], st["iface_dropped"]) ==
      (90000, 10000, 9990, 10), st)
ad = {a["name"]: a for a in st["adapters"]}
check("each adapter is reported on its own",
      ad["Wi-Fi"]["dropped"] == 10000 and ad["Ethernet"]["dropped"] == 0, st["adapters"])
check("...with its own share", ad["Wi-Fi"]["loss_pct"] == round(10000 * 100 / 70000, 2), ad["Wi-Fi"])
check("the last-minute figure comes with it", set(st["recent"]) >= {"secs", "received", "dropped", "loss_pct"})

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
