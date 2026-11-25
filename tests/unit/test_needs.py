import os, sys, sqlite3, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_needs as N
from netscope_history import HistoryStore
from netscope_conn import flow_key

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

tmp = tempfile.mkdtemp()

# ---- dedup, reload, act
path = os.path.join(tmp, "h.db")
h = HistoryStore(path)
n = N.NeedsYou(h)
a = n.add("program", "evil.exe", {"path": "C:\\x"})
b = n.add("program", "evil.exe", {"path": "C:\\y"})
check("add twice -> one card", a is not None and b is None and len(n.open()) == 1)
check("same subject, other kind is a separate card",
      n.add("arp", "evil.exe", {}) is not None)
arp = [c for c in n.open() if c["kind"] == "arp"][0]
n.act(arp["id"], "dismissed")
n2 = N.NeedsYou(HistoryStore(path))
check("reload shows the one still open", [c["kind"] for c in n2.open()] == ["program"],
      str(n2.open()))
n3 = N.NeedsYou(HistoryStore(path))
for c in n3.open():
    n3.act(c["id"], "dismissed")
check("acted cards gone after reload", N.NeedsYou(HistoryStore(path)).open() == [])

# ---- in-memory mode
m = N.NeedsYou(None)
c = m.add("arp", "192.168.1.1", {"k": 1})
check("memory: add", c is not None and m.add("arp", "192.168.1.1", {}) is None)
check("memory: open/get", [x["id"] for x in m.open()] == [c["id"]]
      and m.get(c["id"])["subject"] == "192.168.1.1")
r = m.act(c["id"], "expected")
check("memory: act", r["state"] == "expected" and r["acted"] and m.open() == [])
check("memory: act on unknown id", m.act(999, "trusted") is None)
check("memory: bad state refused", m.add("arp", "x", {}) and m.act(2, "bogus") is None)
d = N.NeedsYou(HistoryStore(":memory:"))
check("history :memory: works", d.add("program", "a.exe", {}) is not None
      and len(d.open()) == 1)
d = N.NeedsYou(HistoryStore(os.path.join(tmp, "off.db"), enabled=False))
check("disabled history works", d.add("program", "a.exe", {}) is not None
      and len(d.open()) == 1)

# ---- newest first
m = N.NeedsYou(None)
m.add("program", "a", {}); m.add("program", "b", {})
check("newest first", [c["subject"] for c in m.open()] == ["b", "a"])

# ---- merge_talk
saved = {"k1": {"host": "h", "in": 100, "out": 50}}
cur = {"k1": {"host": "h", "in": 10, "out": 60}}
mt = N.merge_talk(saved, cur)
check("merge keeps larger figures", mt["k1"]["in"] == 100 and mt["k1"]["out"] == 60)
big = {f"k{i}": {"host": "h", "in": i, "out": 0} for i in range(250)}
mt = N.merge_talk({}, big)
check("merge caps at 200 biggest", len(mt) == 200 and "k249" in mt
      and "k50" in mt and "k49" not in mt)

# ---- talk_by_host
t = {"a": {"host": "x.com", "in": 10, "out": 5},
     "b": {"host": "x.com", "in": 1, "out": 2},
     "c": {"host": "y.com", "in": 100, "out": 0}}
rows = N.talk_by_host(t)
check("talk_by_host sums", rows[0]["host"] == "y.com" and rows[1] == {
    "host": "x.com", "conns": 2, "in": 11, "out": 7}, str(rows))

# ---- flows_for
k1 = flow_key("TCP", "10.0.0.2", 5000, "1.2.3.4", 443, "Wi-Fi")
k2 = flow_key("TCP", "10.0.0.2", 5001, "5.6.7.8", 443, "Wi-Fi")
k3 = flow_key("TCP", "10.0.0.2", 5002, "9.9.9.9", 443, "Wi-Fi")
snap = {k1: {"process": "Evil.EXE", "rhost": "evil.example", "in": 5, "out": 6},
        k2: {"process": "evil.exe", "rhost": "", "in": 1, "out": 2},
        k3: {"process": "other.exe", "rhost": "z", "in": 1, "out": 1}}
ff = N.flows_for(snap, "evil.exe")
check("flows_for filters and keys by str", set(ff) == {str(k1), str(k2)})
check("flows_for host", ff[str(k1)]["host"] == "evil.example"
      and ff[str(k2)]["host"] == "5.6.7.8", str(ff))
check("flows_for figures", ff[str(k1)]["in"] == 5 and ff[str(k1)]["out"] == 6)

# ---- update_talk
m = N.NeedsYou(None)
c = m.add("program", "evil.exe", {})
m.update_talk(c["id"], ff, 1000.0)
g = m.get(c["id"])
check("update_talk merges", g["data"]["talk"][str(k1)]["in"] == 5
      and g["data"]["talk_at"] == 1000.0)
p = os.path.join(tmp, "t.db")
nt = N.NeedsYou(HistoryStore(p))
c = nt.add("program", "evil.exe", {})
nt.update_talk(c["id"], ff, 1000.0)
nt.update_talk(c["id"], {str(k1): {"host": "h", "in": 99, "out": 99}}, 1010.0)
check("update_talk memory is current", nt.get(c["id"])["data"]["talk"][str(k1)]["in"] == 99)
r1 = N.NeedsYou(HistoryStore(p)).get(c["id"])["data"]["talk"][str(k1)]["in"]
check("persists at most once per 60 s", r1 == 5, str(r1))
nt.update_talk(c["id"], {str(k1): {"host": "h", "in": 120, "out": 99}}, 1061.0)
r2 = N.NeedsYou(HistoryStore(p)).get(c["id"])["data"]["talk"][str(k1)]["in"]
check("persists after 60 s", r2 == 120, str(r2))

# ---- alert log pile
h = HistoryStore(os.path.join(tmp, "a.db"))
h.record_alert({"ts": 1.0, "severity": "warn", "rule": "r", "title": "t",
                "detail": "d", "pile": "needs"})
h.record_alert({"ts": 2.0, "severity": "warn", "rule": "r", "title": "t2",
                "detail": "d"})
h.flush()
rows, _ = h.alert_log()
piles = {r["title"]: r["pile"] for r in rows}
check("pile written and read", piles == {"t": "needs", "t2": "recorded"}, str(piles))

# old database without the column
old = os.path.join(tmp, "old.db")
db = sqlite3.connect(old)
db.executescript("""CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts REAL NOT NULL, severity TEXT NOT NULL, rule TEXT NOT NULL, title TEXT NOT NULL,
 detail TEXT NOT NULL, process TEXT, peer TEXT);
 INSERT INTO alerts(ts,severity,rule,title,detail) VALUES (1,'warn','r','old','d');""")
db.commit(); db.close()
h = HistoryStore(old)
cols = {r[1] for r in h._db.execute("PRAGMA table_info(alerts)")}
rows, _ = h.alert_log()
check("old database gets pile; old rows read recorded",
      h.enabled and "pile" in cols and rows[0]["pile"] == "recorded",
      str(h.error) + str(rows))

# ---- wipe keeps open cards
p = os.path.join(tmp, "w.db")
hw = HistoryStore(p)
nw = N.NeedsYou(hw)
nw.add("program", "keep.exe", {})
hw.wipe()
check("wipe leaves open card", len(N.NeedsYou(HistoryStore(p)).open()) == 1)

# ---- a database that fails every write
class Boom:
    def execute(self, *a, **k): raise RuntimeError("disk")
    def commit(self): pass
hb = HistoryStore(os.path.join(tmp, "b.db"))
nb = N.NeedsYou(hb)
hb._db = Boom()
c1 = nb.add("program", "a.exe", {}); c2 = nb.add("program", "b.exe", {})
check("failed inserts: distinct ids", c1["id"] != c2["id"] and None not in (c1["id"], c2["id"]))
check("failed inserts: both gettable and listed",
      nb.get(c1["id"])["subject"] == "a.exe" and nb.get(c2["id"])["subject"] == "b.exe"
      and len(nb.open()) == 2)
check("failed insert card is actable", nb.act(c1["id"], "trusted")["state"] == "trusted"
      and len(nb.open()) == 1)
check("failed insert still dedups", nb.add("program", "b.exe", {}) is None)

sys.exit(1 if fails else 0)
