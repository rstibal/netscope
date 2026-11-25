"""Every alert goes in a pile; only Needs you interrupts (toasts)."""
import os, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import netscope_alerts as A
import netscope_timeline as T
from netscope_history import HistoryStore
from netscope_trust import ProgramJudge, TrustList, Sig

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + str(extra)) if extra and not cond else ""))
    if not cond: fails.append(name)

tmp = tempfile.mkdtemp(prefix="ns_piles_")

class FakeNotifier:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.sent = []
    def notify(self, title, message):
        if self.enabled:
            self.sent.append((title, message))

class FakeChecker:
    def __init__(self, sig):
        self.sig = sig
    def check(self, path):
        return self.sig

n_db = [0]
def engine(history=True):
    h = None
    if history:
        n_db[0] += 1
        h = HistoryStore(os.path.join(tmp, "h%d.db" % n_db[0]))
    e = A.AlertEngine(notifier=FakeNotifier(), history=h,
                      dns_source=lambda: (None, None))
    e._dns_read = A._now()
    e.warmup_until = 0
    return e

def judge_for(e, sig, path):
    return ProgramJudge(FakeChecker(sig), TrustList(),
                        lambda name, pid: (path, "explorer.exe"),
                        e.on_program_verdict, hash_file=lambda p: "ab" * 32)

def exe(name):
    d = tempfile.mkdtemp(dir=tmp)       # under %LOCALAPPDATA%\Temp on Windows
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(b"MZ")
    return p

REC = {"process": "x.exe", "pid": 4242, "remote": "203.0.113.5", "dir": "out",
       "length": 100}

# ---- an unsigned program in a folder anyone can write to: Needs you
e = engine()
path = exe("evil.exe")
j = judge_for(e, Sig("unsigned", ""), path)
e.attach_judge(j)
info = j.judge("evil.exe", 4242, dict(REC, process="evil.exe"))
cards = e.needs.open()
alerts = e.list()
check("unsigned in LOCALAPPDATA -> one card", len(cards) == 1, cards)
check("...about the program", cards and cards[0]["kind"] == "program"
      and cards[0]["subject"] == "evil.exe", cards)
check("...one toast", len(e.notifier.sent) == 1, e.notifier.sent)
check("...alert in the needs pile, high", len(alerts) == 1 and alerts[0]["pile"] == "needs"
      and alerts[0]["severity"] == "high", alerts)
check("...titled from the reason",
      alerts and alerts[0]["title"] == "Unsigned program in a folder anyone can write to",
      alerts)
check("...and carries its card's id", alerts and cards and alerts[0].get("card") == cards[0]["id"])
d = cards[0]["data"] if cards else {}
check("card data has the fields",
      set(d) == {"name", "path", "signer", "sig", "reason", "parent", "pid", "sha256",
                 "first_seen", "talk", "talk_at"}, sorted(d))
check("card data values", d.get("path") == path and d.get("sig") == "unsigned"
      and d.get("reason") == "unsigned_writable" and d.get("pid") == 4242
      and d.get("parent") == "explorer.exe" and d.get("talk") == {}
      and d.get("talk_at") is None and d.get("sha256") == "ab" * 32, d)

# the same program again: the card is already open, no second toast
j.judge("evil.exe", 4242, dict(REC, process="evil.exe"))
check("again -> still one card, no second toast",
      len(e.needs.open()) == 1 and len(e.notifier.sent) == 1, e.notifier.sent)
check("...folded into the alert", e.list()[0]["count"] == 2, e.list())

# ---- the other Needs you titles
for sig, p, name, title in [
        (Sig("valid", "Evil"), exe("svchost.exe"), "svchost.exe",
         "Program with a Windows name outside Windows"),
        (None, None, "gone.exe", "New program whose file can't be found"),
        (Sig("unknown", ""), exe("odd.exe"), "odd.exe",
         "New program whose signature couldn't be checked")]:
    e = engine()
    judge_for(e, sig, p).judge(name, 1, dict(REC, process=name))
    check("title: " + title, [a["title"] for a in e.list()] == [title], e.list())

# ---- a signed program: Recorded, no card, no toast
e = engine()
j = judge_for(e, Sig("valid", "Acme Corp"), exe("good.exe"))
j.judge("good.exe", 1, dict(REC, process="good.exe"))
a = e.list()
check("signed -> no card", e.needs.open() == [])
check("signed -> no toast", e.notifier.sent == [])
check("signed -> recorded, info, 'New program'",
      len(a) == 1 and a[0]["pile"] == "recorded" and a[0]["severity"] == "info"
      and a[0]["title"] == "New program", a)
check("signed -> detail names the signer",
      a and a[0]["detail"] == "good.exe · signed by Acme Corp", a)

# unsigned in Program Files, and trusted
e = engine()
pf = os.environ.get("ProgramFiles", "C:\\Program Files") + "\\Vendor\\tool.exe"
judge_for(e, Sig("unsigned", ""), pf).judge("tool.exe", 1, dict(REC, process="tool.exe"))
check("unsigned in Program Files -> recorded detail",
      [x["detail"] for x in e.list()] == ["tool.exe · in Program Files, unsigned"], e.list())
e = engine()
tp = exe("mine.exe")
j = judge_for(e, Sig("unsigned", ""), tp)
j.trust.add("mine.exe", tp, "ab" * 32)
j.judge("mine.exe", 1, dict(REC, process="mine.exe"))
check("trusted -> recorded detail, no card",
      [x["detail"] for x in e.list()] == ["mine.exe · trusted"] and e.needs.open() == [],
      e.list())

# ---- _change_rules submits, never judges inline
class StubJudge:
    def __init__(self): self.got = []
    def submit(self, name, pid, rec): self.got.append((name, pid))
e = engine()
e.baselining = False
sj = StubJudge(); e.attach_judge(sj)
e._change_rules(dict(REC, process="new.exe", pid=77))
check("history on: a new program is submitted to the judge",
      sj.got == [("new.exe", 77)] and e.list() == [], (sj.got, e.list()))
e = engine()
e.baselining = False
e._change_rules(dict(REC, process="new.exe", pid=77))
a = e.list()
check("no judge -> recorded alert as before, no toast",
      len(a) == 1 and a[0]["pile"] == "recorded" and e.notifier.sent == [], a)
e = engine(history=False)
sj = StubJudge(); e.attach_judge(sj)
e._change_rules(dict(REC, process="new.exe", pid=77))
a = e.list()
check("history off -> not judged, session note, recorded",
      sj.got == [] and len(a) == 1 and a[0]["pile"] == "recorded"
      and a[0]["title"] == "Program started using the network", (sj.got, a))

# ---- the warn rules: all Recorded, no toasts
e = engine(history=False)
# check-in
NOW = int(time.time())
t = T.Timeline()
for s in range(NOW - 3000, NOW):
    if (NOW - s) % 45 == 0:
        t.observe({"ts": s + .3, "process": "Agent.exe", "rhost": "c2.example",
                   "remote": "1.2.3.4", "src": "10.0.0.2", "dst": "1.2.3.4",
                   "sport": 50000, "dport": 443, "dir": "out", "proto": "TLS",
                   "length": 100, "iface": "eth0"})
e.check_checkins(t)
# threshold
e.threshold_mb = 1
e._change_rules({"process": "big.exe", "length": 2 * 1024 * 1024, "ts": NOW})
# dns resolver
e.dns_configured = {"192.168.1.1"}
e.dns_by_iface = {"Wi-Fi": {"192.168.1.1"}}
for _ in range(200):
    e._dns_rule({"proto": "DNS", "dir": "out", "remote": "192.168.1.1",
                 "iface": "Wi-Fi", "process": "svchost.exe", "length": 80})
for _ in range(10):
    e._dns_rule({"proto": "DNS", "dir": "out", "remote": "45.33.12.9",
                 "iface": "Wi-Fi", "process": "sketchy.exe", "length": 80})
# port scan
for i in range(A.SCAN_PORT_THRESHOLD):
    e._scan_rule({"dir": "in", "remote": "45.33.12.9", "sport": 40000,
                  "dport": 1000 + i, "ts": A._now(), "transport": "tcp",
                  "decoded": {"tcp": {"flags": "S"}}})
# dhcp rogue server
for server in ("192.168.1.1", "192.168.1.66"):
    e._dhcp_rule({"decoded": {"dhcp": {"msg_type": "OFFER", "server_id": server}}})
rules = sorted({a["rule"] for a in e.list()})
check("the warn rules all fired",
      {"checkin", "threshold", "dns_resolver", "port_scan", "dhcp_rogue_server"} <= set(rules),
      rules)
check("...all recorded", all(a["pile"] == "recorded" for a in e.list()),
      [(a["rule"], a["pile"]) for a in e.list()])
check("...with no toasts", e.notifier.sent == [], e.notifier.sent)
check("...and no cards", e.needs.open() == [])

# ---- ARP
def arp(ip, mac, ts, iface="Ethernet"):
    return {"iface": iface, "ts": ts, "decoded": {"arp": {
        "op": 2, "sender_ip": ip, "sender_mac": mac, "target_ip": "192.168.1.1"}}}
T0 = 1000.0
def fight(e, ip="192.168.1.50", t=T0):
    """The address changing hands three times inside the hold."""
    e._arp_rule(arp(ip, "AA:BB:CC:11:22:33", t))
    e._arp_rule(arp(ip, "de:ad:be:ef:00:01", t + 1))
    e._arp_rule(arp(ip, "aa:bb:cc:11:22:33", t + 2))   # the old one again
    e._arp_rule(arp(ip, "de:ad:be:ef:00:01", t + 3))   # and again

# one flip back: two devices claimed it, Recorded, no card, no toast
e = engine()
e._arp_rule(arp("192.168.1.50", "AA:BB:CC:11:22:33", T0))
e._arp_rule(arp("192.168.1.50", "de:ad:be:ef:00:01", T0 + 1))
e._arp_rule(arp("192.168.1.50", "aa:bb:cc:11:22:33", T0 + 2))
e.tick(T0 + 3)
a = e.list()
check("one reclaim -> recorded, no card, no toast",
      len(a) == 1 and a[0]["pile"] == "recorded" and e.needs.open() == []
      and e.notifier.sent == [], a)
check("one reclaim -> titled and names both MACs",
      a and a[0]["title"] == "Two devices claimed 192.168.1.50"
      and "aa:bb:cc:11:22:33" in a[0]["detail"] and "de:ad:be:ef:00:01" in a[0]["detail"]
      and a[0]["subject"] == "192.168.1.50", a)

e = engine()
fight(e)
check("impersonation -> nothing until tick()",
      e.list() == [] and e.needs.open() == [] and e.notifier.sent == [])
e.tick(T0 + 4)
a = [x for x in e.list() if x["pile"] == "needs"]; cards = e.needs.open()
check("impersonation -> one card", len(cards) == 1 and cards[0]["kind"] == "arp"
      and cards[0]["subject"] == "192.168.1.50", cards)
check("impersonation -> one toast", len(e.notifier.sent) == 1, e.notifier.sent)
check("impersonation -> high, needs, titled",
      len(a) == 1 and a[0]["severity"] == "high" and a[0]["pile"] == "needs"
      and a[0]["title"] == "Another device is claiming 192.168.1.50", a)
check("...after the contested record, not folded into it",
      [x["title"] for x in e.list()] ==
      ["Another device is claiming 192.168.1.50", "Two devices claimed 192.168.1.50"],
      e.list())

# an impersonation after a replacement is its own alert, logged as needs
e = engine()
logged = []
e.history.record_alert = lambda al: logged.append(dict(al))
e._arp_rule(arp("192.168.1.70", "aa:bb:cc:11:22:33", T0))
e._arp_rule(arp("192.168.1.70", "de:ad:be:ef:00:01", T0 + 1))
e.tick(T0 + 1 + 61)                                    # replaced
fight(e, "192.168.1.70", T0 + 100)
e.tick(T0 + 105)
a = e.list()
check("replaced then impersonated -> both alerts",
      sorted(x["title"] for x in a if x["title"] != "Two devices claimed 192.168.1.70") ==
      ["A device was replaced", "Another device is claiming 192.168.1.70"], a)
imp = [x for x in a if x["title"].startswith("Another device")]
check("...the impersonation is in the needs pile", imp and imp[0]["pile"] == "needs"
      and imp[0]["count"] == 1, imp)
check("...and logged as needs",
      [x["pile"] for x in logged if x["title"].startswith("Another device")] == ["needs"],
      logged)
check("...both keep the IP as the subject (mutes)",
      {x["subject"] for x in a} == {"192.168.1.70"}, a)
e.mute("arp_spoof", "192.168.1.70")
check("...and one mute silences them all", e.list() == [], e.list())
cd = cards[0]["data"] if cards else {}
check("impersonation data", cd.get("iface") == "Ethernet" and cd.get("ip") == "192.168.1.50"
      and sorted(m["mac"] for m in cd.get("macs", [])) ==
      ["aa:bb:cc:11:22:33", "de:ad:be:ef:00:01"]
      and all("last_seen" in m for m in cd.get("macs", [])), cd)

e = engine()
e._arp_rule(arp("192.168.1.60", "aa:bb:cc:11:22:33", T0))
e._arp_rule(arp("192.168.1.60", "de:ad:be:ef:00:01", T0 + 1))
e.tick(T0 + 30)
check("replacement -> nothing during the hold", e.list() == [])
e.tick(T0 + 1 + 61)
a = e.list()
check("replacement -> recorded info, no toast, no card",
      len(a) == 1 and a[0]["pile"] == "recorded" and a[0]["severity"] == "info"
      and a[0]["title"] == "A device was replaced" and e.notifier.sent == []
      and e.needs.open() == [], a)
check("replacement detail", a and a[0]["detail"] ==
      "192.168.1.60 on Ethernet is a different device now "
      "(aa:bb:cc:11:22:33 → de:ad:be:ef:00:01), and has stayed so", a)

# ---- counts and clear
e = engine()
fight(e)
e.tick(T0 + 4)
check("counts() says how many need you", e.counts().get("needs") == 1, e.counts())
e.clear()
check("clear() keeps the open card", len(e.needs.open()) == 1 and e.list() == [])
check("...and forgets the ARP state", e.arp.tick(T0 + 999) == [] and not e.arp._entries)

# ---- the toast migration
store = {"alert_toasts": False}
e = engine(history=False); e.notifier.enabled = False
e.attach_settings(lambda: dict(store), lambda k, v: store.__setitem__(k, v))
check("migration: toasts turned on once", e.notifier.enabled is True)
check("migration: saved", store.get("needs_toasts_on") is True
      and store.get("alert_toasts") is True, store)
store = {"alert_toasts": False, "needs_toasts_on": True}
e = engine(history=False)
e.attach_settings(lambda: dict(store), lambda k, v: store.__setitem__(k, v))
check("after the migration, Rob's choice stands", e.notifier.enabled is False)
store = {}
e = engine(history=False); e.notifier.enabled = False
e.attach_settings(lambda: dict(store), lambda k, v: store.__setitem__(k, v))
check("fresh install -> on", e.notifier.enabled is True and store.get("needs_toasts_on") is True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
