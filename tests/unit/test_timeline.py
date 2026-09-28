import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_timeline as T

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def pkt(ts, proc="chrome.exe", host="example.com", ip="1.2.3.4", d="out",
        n=100, rport=443, proto="TLS"):
    out = d == "out"
    return {"ts": ts, "process": proc, "rhost": host, "remote": ip,
            "src": "10.0.0.2" if out else ip, "dst": ip if out else "10.0.0.2",
            "sport": 50000 if out else rport, "dport": rport if out else 50000,
            "dir": d, "proto": proto, "length": n, "iface": "eth0"}

def totals(snap):
    keys = snap["keys"]
    got = {}
    for sec, lst in snap["buckets"]:
        for k, b, p in lst:
            key = (sec, keys[k][0], keys[k][4])
            got[key] = (got.get(key, (0, 0))[0] + b, got.get(key, (0, 0))[1] + p)
    return got

# ---- per second, per key
t = T.Timeline()
t.observe(pkt(1000.2)); t.observe(pkt(1000.9, n=50)); t.observe(pkt(1000.5, d="in", n=900))
t.observe(pkt(1001.1, proc="svc.exe"))
s = t.snapshot()
got = totals(s)
check("packets in the same second and key add up", got[(1000, "chrome.exe", "out")] == (150, 2), got)
check("direction is part of the key", got[(1000, "chrome.exe", "in")] == (900, 1), got)
check("a new second is a new bucket", got[(1001, "svc.exe", "out")] == (100, 1), got)
k = s["keys"][0]
check("a key carries program, host, remote, local, dir, proto, remote port, adapter",
      k == ["chrome.exe", "example.com", "1.2.3.4", "10.0.0.2", "out", "TLS", 443, "eth0"], k)
k_in = [x for x in s["keys"] if x[4] == "in"][0]
check("...and the remote port for inbound packets is their source port", k_in[6] == 443, k_in)
check("the local port is not kept, so one conversation is one key",
      len(s["keys"]) == 3, s["keys"])

# ---- incremental fetches
gen = s["gen"]
t.observe(pkt(1002.0, proc="new.exe"))
inc = t.snapshot(since=1001, kfrom=3, gen=gen)
check("since= returns that second on", [b[0] for b in inc["buckets"]] == [1001, 1002], inc["buckets"])
check("kfrom= returns only keys the page hasn't seen, numbered on from there",
      inc["kfrom"] == 3 and [x[0] for x in inc["keys"]] == ["new.exe"], inc)
check("...and says it is not a full answer", inc["full"] is False)
stale = t.snapshot(since=1001, kfrom=3, gen=gen - 1)
check("a stale generation gets everything", stale["full"] and stale["kfrom"] == 0 and
      len(stale["keys"]) == 4, stale)

# ---- out of order
t.observe(pkt(999.5, proc="late.exe"))
check("a packet from an earlier second still lands in order",
      [b[0] for b in t.snapshot()["buckets"]] == [999, 1000, 1001, 1002])

# ---- retention
t = T.Timeline(retain=60)
t.observe(pkt(1000)); t.observe(pkt(1030)); t.observe(pkt(1070))
check("seconds older than the retention before the newest are dropped",
      [b[0] for b in t.snapshot()["buckets"]] == [1030, 1070])
t.observe(pkt(1005))
check("...and one arriving that late is ignored",
      [b[0] for b in t.snapshot()["buckets"]] == [1030, 1070])

# ---- a scan doesn't make one key per probe
t = T.Timeline()
for i in range(T.MAX_KEYS_PER_SEC + 50):
    t.observe(pkt(2000.5, proc="nmap.exe", host="", ip="10.1.%d.%d" % (i // 250, i % 250),
                  rport=i))
s = t.snapshot()
lst = s["buckets"][0][1]
check("one second holds at most MAX_KEYS_PER_SEC keys, plus the lump",
      len(lst) == T.MAX_KEYS_PER_SEC + 1, len(lst))
lump = [x for x in lst if s["keys"][x[0]][2] == "(many)"]
check("...the rest are counted under the program, not dropped",
      len(lump) == 1 and lump[0][2] == 50 and s["keys"][lump[0][0]][0] == "nmap.exe", lump)
check("...so the program's packet count is exact",
      sum(x[2] for x in lst) == T.MAX_KEYS_PER_SEC + 50)

# ---- compaction renumbers keys and changes the generation
t = T.Timeline(retain=10)
old_max = T.MAX_KEYS
T.MAX_KEYS = 50
try:
    for i in range(49):
        t.observe(pkt(3000, proc="p%d.exe" % i))
    t.observe(pkt(3100, proc="now.exe"))    # pushes the old second out
    g = t.gen
    t.observe(pkt(3100, proc="after.exe"))  # the 51st key: compaction
    s = t.snapshot()
    check("a full key table is compacted to the keys still in use",
          t.gen == g + 1 and [k[0] for k in s["keys"]] == ["now.exe", "after.exe"], s["keys"])
    check("...and the buckets use the new numbers",
          totals(s) == {(3100, "now.exe", "out"): (100, 1), (3100, "after.exe", "out"): (100, 1)},
          totals(s))
finally:
    T.MAX_KEYS = old_max

# ---- bad records and clear
t = T.Timeline()
t.observe({"ts": None}); t.observe({})
check("a record without a usable time is skipped", t.snapshot()["buckets"] == [])
t.observe(pkt(5000))
g = t.gen
t.clear()
s = t.snapshot()
check("clear empties it and changes the generation",
      s["buckets"] == [] and s["keys"] == [] and t.gen == g + 1 and t.newest == 0)

# ---- wired into the store
import netscope as N
st = N.PacketStore()
st.add(pkt(6000.0), b"")
check("every packet the store takes reaches the timeline",
      totals(st.timeline.snapshot()) == {(6000, "chrome.exe", "out"): (100, 1)})
st.clear()
check("...and Clear clears it", st.timeline.snapshot()["buckets"] == [])

print("\nFAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
