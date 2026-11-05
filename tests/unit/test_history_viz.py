"""
1.43: a trend per day beside each History bar, a day of the daily chart
opened into its hours, programs and hosts, and live throughput per adapter.
"""
import os, sys, tempfile, time
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_history as H

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def pkt(proc, host, n, ts, iface="Wi-Fi", out=True):
    return {"process": proc, "rhost": host, "remote": "203.0.113.9", "length": n,
            "dir": "out" if out else "in", "ts": ts, "iface": iface}

h = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-viz-"), "h.db"))
noon = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0)
today = noon.timestamp()
two_ago = (noon - timedelta(days=2)).timestamp()
h.record(pkt("steady.exe", "a.example", 100, today))
h.record(pkt("steady.exe", "a.example", 100, two_ago))
h.record(pkt("burst.exe", "b.example", 5000, two_ago, iface="VR"))
h.record(pkt("-", "b.example", 7, today))
h.flush()

# -- trends ---------------------------------------------------------------------------
procs = {r["name"]: r["trend"] for r in h.by_process(7)}
check("each program carries one figure per day of the range",
      all(len(t) == 7 for t in procs.values()), procs)
check("...placed on the right days", procs["steady.exe"][-1] == 100 and procs["steady.exe"][-3] == 100
      and procs["steady.exe"][-2] == 0 and procs["burst.exe"] == [0, 0, 0, 0, 5000, 0, 0], procs)
hosts = {r["host"]: r["trend"] for r in h.by_host(7)}
check("hosts carry them too, unattributed traffic included",
      hosts["b.example"][-1] == 7 and hosts["b.example"][-3] == 5000, hosts)
check("an adapter filter narrows the trend as it does the total",
      {r["name"]: r["trend"][-3] for r in h.by_process(7, iface="VR")} == {"burst.exe": 5000})
check("a 30-day range gives 30 figures", len(h.by_process(30)[0]["trend"]) == 30)

# -- a day opened ------------------------------------------------------------------------
day = noon.strftime("%Y-%m-%d")
d = h.day_detail(day)
check("a day has its 24 hours", len(d["hours"]) == 24 and d["hours"][12]["bytes_out"] == 107, d["hours"][12])
check("...and the programs and hosts behind it",
      [r["name"] for r in d["programs"]] == ["steady.exe"]
      and sorted(r["host"] for r in d["hosts"]) == ["a.example", "b.example"], d)
two = h.day_detail((noon - timedelta(days=2)).strftime("%Y-%m-%d"), iface="VR")
check("...for one adapter, only its traffic",
      [r["name"] for r in two["programs"]] == ["burst.exe"] and two["hours"][12]["bytes_out"] == 5000, two)
check("an empty day is all zeros, not an error",
      sum(r["bytes_in"] + r["bytes_out"] for r in h.day_detail("2001-01-01")["hours"]) == 0)
h.stop()

# -- per adapter, live ------------------------------------------------------------------
sys.argv = [sys.argv[0]]
import netscope as N
st = N.PacketStore()
now = int(time.time())
def live(iface, n, ts, out=False, outer=False):
    rec = {"ts": ts, "length": n, "dir": "out" if out else "in", "process": "x.exe",
           "remote": "203.0.113.9", "proto": "TLS", "iface": iface,
           "src": "203.0.113.9", "dst": "192.168.1.2"}
    if outer:
        rec["tunnel_outer"] = True
    st.add(rec, b"")
live("Wi-Fi", 1000, now - 10)
live("Wi-Fi", 300, now - 10, out=True)
live("Wi-Fi", 400, now - 5, outer=True)
live("VR", 90000, now - 2)
live("Wi-Fi", 5, now - N.IFACE_WINDOW - 50)          # too old to show
r = st.adapter_rates(now)
names = [a["name"] for a in r["adapters"]]
check("adapters are listed busiest first", names == ["VR", "Wi-Fi"], names)
wifi = dict((x[0], x[1:]) for x in r["adapters"][1]["series"])
check("each second has received, sent and the VPN copy",
      wifi.get(now - 10) == [1000, 300, 0] and wifi.get(now - 5) == [400, 0, 400], wifi)
check("...and only the window's seconds", min(wifi) > now - N.IFACE_WINDOW, sorted(wifi))
st.clear()
check("Clear empties it", st.adapter_rates(now)["adapters"] == [])

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
