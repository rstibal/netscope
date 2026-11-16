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
h.record(pkt("steady.exe", "a.example", 40, today, out=False))
four_ago = (noon - timedelta(days=4)).timestamp()
h.record(pkt("two.exe", "x.example", 11, two_ago))
h.record(pkt("two.exe", "y.example", 22, four_ago))
# Recording began ten days ago: the 7-day range is full, the 30-day one is not.
ten_ago_d = noon - timedelta(days=10)
h.record(pkt("old.exe", "o.example", 3, ten_ago_d.timestamp()))
h.flush()

# -- an opened row's own rows have their days too ----------------------------------------
dp = {r["name"]: r for r in h.detail("program", "two.exe", 7)["rows"]}
check("a program's hosts each carry their days with that program",
      dp["x.example"]["trend_out"] == [0, 0, 0, 0, 11, 0, 0]
      and dp["y.example"]["trend_out"] == [0, 0, 22, 0, 0, 0, 0]
      and dp["x.example"]["trend_in"] == [0] * 7, dp)
dhh = {r["name"]: r for r in h.detail("host", "b.example", 7)["rows"]}
check("a host's programs each carry their days with that host",
      dhh["burst.exe"]["trend_out"] == [0, 0, 0, 0, 5000, 0, 0]
      and dhh["-"]["trend_out"] == [0, 0, 0, 0, 0, 0, 7], dhh)
check("...only that host's share of a program that talks to others",
      h.detail("host", "x.example", 7)["rows"][0]["trend_out"] == [0, 0, 0, 0, 11, 0, 0])
check("...and only the chosen adapter's",
      [(r["name"], r["trend_out"][-3]) for r in h.detail("host", "b.example", 7, iface="VR")["rows"]]
      == [("burst.exe", 5000)])

# -- trends ---------------------------------------------------------------------------
# 1.51: received and sent apart, so the page can draw one above the other.
rows = h.by_process(7)
procs = {r["name"]: r["trend_out"] for r in rows}
recv = {r["name"]: r["trend_in"] for r in rows}
check("each program carries one figure per day of the range, each way",
      all(len(t) == 7 for t in procs.values()) and all(len(t) == 7 for t in recv.values()), procs)
check("...placed on the right days", procs["steady.exe"][-1] == 100 and procs["steady.exe"][-3] == 100
      and procs["steady.exe"][-2] == 0 and procs["burst.exe"] == [0, 0, 0, 0, 5000, 0, 0], procs)
check("...received kept apart from sent",
      recv["steady.exe"] == [0, 0, 0, 0, 0, 0, 40] and recv["burst.exe"] == [0] * 7, recv)
hosts = {r["host"]: r["trend_out"] for r in h.by_host(7)}
check("hosts carry them too, unattributed traffic included",
      hosts["b.example"][-1] == 7 and hosts["b.example"][-3] == 5000, hosts)
check("...received as well",
      {r["host"]: r["trend_in"][-1] for r in h.by_host(7)}["a.example"] == 40)
check("an adapter filter narrows the trend as it does the total",
      {r["name"]: r["trend_out"][-3] for r in h.by_process(7, iface="VR")} == {"burst.exe": 5000})

# -- a history shorter than the range fills it (1.51.1) ---------------------------------
# The columns start at the first recorded day, not at an empty stretch before it.
d30 = h.daily(30)
check("a range longer than the history starts at the first recorded day",
      len(d30) == 11 and d30[0]["day"] == ten_ago_d.strftime("%Y-%m-%d")
      and d30[-1]["day"] == noon.strftime("%Y-%m-%d"), [r["day"] for r in d30])
check("...days with nothing after that are still there, as zeros",
      d30[1]["bytes_in"] + d30[1]["bytes_out"] == 0 and d30[0]["bytes_out"] == 3, d30[:2])
check("...and every row has a figure for exactly those days",
      all(len(r["trend_out"]) == 11 and len(r["trend_in"]) == 11 for r in h.by_process(30) + h.by_host(30))
      and {r["name"]: r["trend_out"] for r in h.by_process(30)}["old.exe"] == [3] + [0] * 10)
check("...an opened row's rows too",
      [len(r["trend_out"]) for r in h.detail("program", "two.exe", 30)["rows"]] == [11, 11])
check("a range the history covers is unchanged", len(h.daily(7)) == 7 and len(h.daily(90)) == 11)
check("one adapter starts at its own first day",
      [r["day"] for r in h.daily(30, iface="VR")][0] == (noon - timedelta(days=2)).strftime("%Y-%m-%d")
      and len(h.by_process(30, iface="VR")[0]["trend_out"]) == 3)
empty = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-viz-"), "e.db"))
check("an empty history is one day, today", [r["day"] for r in empty.daily(30)] == [noon.strftime("%Y-%m-%d")])
empty.stop()

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
