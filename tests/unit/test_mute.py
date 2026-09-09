import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, time
import netscope_alerts as A

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def engine():
    e = A.AlertEngine(); e.warmup_until = 0; return e

# ---- subject extraction across the key shapes the rules actually use
check("tuple key -> last element is the subject",
      A.AlertEngine.subject_of(("dns_alt","Wi-Fi","10.0.0.38"))=="10.0.0.38")
check("plain key -> itself", A.AlertEngine.subject_of("chrome.exe")=="chrome.exe")
check("two-part key", A.AlertEngine.subject_of(("new_host","1.2.3.4"))=="1.2.3.4")

# ---- muting one subject leaves the rule watching everything else
e = engine()
e._fire(("dns_alt","Wi-Fi","10.0.0.38"), A.WARN, "dns_resolver", "t", "d")
check("alert fires normally", len(e.list())==1)
check("alert carries its subject", e.list()[0]["subject"]=="10.0.0.38")

e.mute("dns_resolver", "10.0.0.38")
check("muting clears what is already on screen", e.list()==[], e.list())
e._fire(("dns_alt","Wi-Fi","10.0.0.38"), A.WARN, "dns_resolver", "t", "d")
check("muted subject no longer fires", e.list()==[], e.list())
e._fire(("dns_alt","Wi-Fi","45.33.12.9"), A.WARN, "dns_resolver", "t", "d")
check("the same rule still fires for other subjects", len(e.list())==1, e.list())
check("the rule itself is still enabled", e.rules["dns_resolver"] is True)

# a different rule with the same subject is unaffected
e._fire(("new_host","10.0.0.38"), A.INFO, "new_host", "t", "d")
check("mute is per rule, not global to the subject", len(e.list())==2, len(e.list()))

# ---- expiry
e = engine()
until = e.mute("new_process", "x.exe", minutes=60)
check("timed mute returns an expiry", until and until > time.time())
check("is_muted true before expiry", e.is_muted("new_process","x.exe"))
e.mutes[("new_process","x.exe")] = time.time() - 1
check("expired mute stops muting", not e.is_muted("new_process","x.exe"))
check("expired mute is dropped from the list",
      ("new_process","x.exe") not in e.mutes, e.mutes)

# indefinite mutes never expire
e = engine(); e.mute("new_process","y.exe")
check("indefinite mute has no expiry", e.list_mutes()[0]["until"] is None)
check("indefinite mute still holds", e.is_muted("new_process","y.exe"))

# ---- unmute
e = engine(); e.mute("new_process","z.exe")
e.unmute("new_process","z.exe")
check("unmute restores the alert", not e.is_muted("new_process","z.exe"))
e._fire("z.exe", A.INFO, "new_process", "t", "d")
check("...and it fires again", len(e.list())==1)

# ---- dismiss one without touching the rest
e = engine()
e._fire("a.exe", A.INFO, "new_process", "t", "d")
e._fire("b.exe", A.INFO, "new_process", "t", "d")
aid = [x for x in e.list() if x["subject"]=="a.exe"][0]["id"]
check("dismiss reports success", e.dismiss(aid) is True)
left = [x["subject"] for x in e.list()]
check("only that alert went", left==["b.exe"], left)
check("dismissing an unknown id is harmless", e.dismiss(99999) is False)

# ---- Clear keeps mutes
e = engine(); e.mute("new_process","keep.exe")
e._fire("other.exe", A.INFO, "new_process", "t", "d")
e.clear()
check("Clear empties the alerts", e.list()==[])
check("Clear keeps the mutes", e.is_muted("new_process","keep.exe"))

# ---- persistence round trip
store = {}
load = lambda: dict(store)
save = lambda k, v: store.__setitem__(k, v)

e = engine()
e.attach_settings(load, save)
e.rules["new_host"] = True
e.rules["cert_problems"] = False
e.threshold_mb = 250
e.notifier.enabled = True
e.save_config()
e.mute("dns_resolver", "10.0.0.38")

check("rules were written", store.get("alert_rules",{}).get("new_host") is True, store.get("alert_rules"))
check("threshold was written", store.get("alert_threshold_mb")==250, store.get("alert_threshold_mb"))
check("toasts were written", store.get("alert_toasts") is True)
check("mutes were written", store.get("alert_mutes")==[{"rule":"dns_resolver","subject":"10.0.0.38","until":None}],
      store.get("alert_mutes"))

# a fresh engine, as if the machine had rebooted
e2 = A.AlertEngine(); e2.warmup_until = 0
check("a fresh engine starts at defaults",
      e2.rules["new_host"] is False and e2.threshold_mb==500)
e2.attach_settings(load, save)
check("rules restored", e2.rules["new_host"] is True and e2.rules["cert_problems"] is False)
check("threshold restored", e2.threshold_mb==250)
check("toasts restored", e2.notifier.enabled is True)
check("mutes restored", e2.is_muted("dns_resolver","10.0.0.38"))

# an expired mute in the file is not resurrected
store["alert_mutes"] = [{"rule":"new_process","subject":"old.exe","until": time.time()-5}]
e3 = A.AlertEngine(); e3.attach_settings(load, save)
check("expired mute in the file is dropped on load",
      not e3.is_muted("new_process","old.exe"), e3.mutes)

# ---- degrades without a settings sink, and survives a broken one
e4 = A.AlertEngine(); e4.warmup_until = 0
e4.mute("new_process","q.exe"); e4.save_config()
check("no settings sink -> no crash, muting still works", e4.is_muted("new_process","q.exe"))

def boom(*a, **k): raise IOError("disk full")
e5 = A.AlertEngine()
e5.attach_settings(boom, boom)
e5.mute("new_process","r.exe"); e5.save_config()
check("a failing settings store never breaks alerting", e5.is_muted("new_process","r.exe"))

# ---- every rule has an explanation
check("every rule can say why it fired",
      set(A.AlertEngine().rules) <= set(A.RULE_WHY),
      set(A.AlertEngine().rules) - set(A.RULE_WHY))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
