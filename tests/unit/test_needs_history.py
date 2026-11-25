"""
Needs you cards in the history database: what Erase, pruning and history
exclusions do to them, and the talk beat's work when no program card is open.
"""
import os, sys, tempfile, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, ROOT)

from netscope_history import HistoryStore
from netscope_needs import NeedsYou

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp(prefix="ns_needs_hist_")
n_db = [0]
def store():
    n_db[0] += 1
    return HistoryStore(os.path.join(tmp, "h%d.db" % n_db[0]))

def rows(h):
    return h._q("SELECT id, state, acted FROM needs_you ORDER BY id")

# ---- Erase all history: acted cards go, open ones stay
h = store()
n = NeedsYou(h)
keep = n.add("program", "open.exe", {"name": "open.exe"})
done = n.add("program", "done.exe", {"name": "done.exe"})
n.act(done["id"], "dismissed")
check("before the wipe: two rows", len(rows(h)) == 2, rows(h))
h.wipe()
r = rows(h)
check("wipe removes the acted card", [x["id"] for x in r] == [keep["id"]], r)
check("...and keeps the open one", r and r[0]["state"] == "open", r)
check("...which still loads", [c["subject"] for c in NeedsYou(h).open()] == ["open.exe"])

# ---- pruning: acted cards older than alert_retain_days go
h = store()
n = NeedsYou(h)
old_open = n.add("program", "oldopen.exe", {})
old_done = n.add("program", "olddone.exe", {})
new_done = n.add("program", "newdone.exe", {})
n.act(old_done["id"], "trusted")
n.act(new_done["id"], "blocked")
long_ago = time.time() - (h.alert_retain_days + 1) * 86400
with h._db_lock:
    h._db.execute("UPDATE needs_you SET ts=? WHERE id=?", (long_ago, old_open["id"]))
    h._db.execute("UPDATE needs_you SET ts=?, acted=? WHERE id=?",
                  (long_ago, long_ago, old_done["id"]))
    h._db.commit()
h.prune()
ids = [x["id"] for x in rows(h)]
check("prune drops an acted card past alert_retain_days", old_done["id"] not in ids, ids)
check("...keeps a recently acted one", new_done["id"] in ids, ids)
check("...and an open card however old", old_open["id"] in ids, ids)

# ---- excluded hosts stay out of a card's saved talk
h = store()
h.set_exclusions(hosts=["private.example"])
n = NeedsYou(h)
c = n.add("program", "app.exe", {"name": "app.exe", "talk": {}})
n.update_talk(c["id"], {"k1": {"host": "cdn.example", "in": 10, "out": 5},
                        "k2": {"host": "www.private.example", "in": 99, "out": 9}},
              time.time())
talk = n.get(c["id"])["data"]["talk"]
check("talk keeps an ordinary host", "k1" in talk, talk)
check("talk leaves out an excluded host", "k2" not in talk, talk)
saved = [x for x in h.needs_load() if x["id"] == c["id"]][0]["data"]["talk"]
check("...on disk too", "k2" not in saved and "k1" in saved, saved)
h.set_exclusions(hosts=["private.example", "cdn.example"])
n.update_talk(c["id"], {}, time.time() + 120)
check("a host excluded later is taken out of the saved talk",
      n.get(c["id"])["data"]["talk"] == {}, n.get(c["id"])["data"]["talk"])

# without history nothing is excluded (and nothing reaches disk anyway)
m = NeedsYou(None)
c = m.add("program", "app.exe", {"name": "app.exe"})
m.update_talk(c["id"], {"k": {"host": "x.example", "in": 1, "out": 1}}, time.time())
check("no history: talk kept", "k" in m.get(c["id"])["data"]["talk"])

# ---- the talk beat: no snapshot when no program card is open
import netscope as N

class Flows:
    def __init__(self): self.calls = 0
    def snapshot(self):
        self.calls += 1
        return {}

f = Flows()
m = NeedsYou(None)
N.refresh_needs_talk(f, m)
check("no cards: no flow snapshot", f.calls == 0, f.calls)
m.add("arp", "192.168.1.1", {})
N.refresh_needs_talk(f, m)
check("only an ARP card: no flow snapshot", f.calls == 0, f.calls)
m.add("program", "app.exe", {"name": "app.exe"})
N.refresh_needs_talk(f, m)
check("an open program card: one snapshot", f.calls == 1, f.calls)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
