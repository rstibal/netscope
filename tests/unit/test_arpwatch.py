import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_arpwatch as W

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

OLD, NEW, THIRD = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"
IP = "192.168.1.1"

def kinds(ev):
    return [e[0] for e in ev]

# ---- first sighting and repeats are silent.
w = W.ArpWatch()
check("first sighting -> []", w.observe("Eth", IP, OLD, 0) == [])
check("same MAC again -> []", w.observe("Eth", IP, OLD, 5) == [])

# ---- router swap: new MAC, old one never returns.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
check("new MAC alone -> [] (pending)", w.observe("Eth", IP, NEW, 100) == [])
check("tick before the hold -> []", w.tick(159) == [])
ev = w.tick(161)
check("tick after the hold -> one replaced",
      ev == [("replaced", "Eth", IP, OLD, NEW)], str(ev))
check("replaced only once", w.tick(300) == [])
check("new MAC is current, silent", w.observe("Eth", IP, NEW, 310) == [])

# ---- one flip back during the hold: contested, not impersonated.
# A sleep proxy, a MAC-translating extender or an overlapping router swap
# all reclaim an address once.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
ev = w.observe("Eth", IP, OLD, 110)
check("old MAC once during hold -> one contested",
      ev == [("contested", "Eth", IP, OLD, NEW)], str(ev))
check("...only once per change", w.observe("Eth", IP, OLD, 115) == [])
check("...and no replaced afterwards", w.tick(400) == [])

# ---- the address changing hands three times within the hold: impersonated.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)                 # 1st change of hands
ev = w.observe("Eth", IP, OLD, 110)            # 2nd
check("two changes -> contested only", kinds(ev) == ["contested"], str(ev))
ev = w.observe("Eth", IP, NEW, 120)            # 3rd, within 60 s of the 1st
check("three changes in 60 s -> impersonated",
      kinds(ev) == ["impersonated"], str(ev))
check("impersonated names both MACs",
      set(ev[0][3]) >= {OLD, NEW} and ev[0][1:3] == ("Eth", IP), str(ev))
check("last-seen times reported", ev[0][3][OLD] == 110 and ev[0][3][NEW] == 120, str(ev))
check("further flips give no second event",
      w.observe("Eth", IP, OLD, 125) == [] and w.observe("Eth", IP, NEW, 130) == []
      and w.tick(400) == [])
w.clear()
check("clear() forgets: next sighting is a baseline", w.observe("Eth", IP, NEW, 500) == [])
w.observe("Eth", IP, OLD, 501)
w.observe("Eth", IP, NEW, 502)
check("clear() re-arms impersonation",
      kinds(w.observe("Eth", IP, OLD, 503)) == ["impersonated"])

# ---- three changes spread wider than the hold are not an impersonation.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)                 # change at 100
w.observe("Eth", IP, OLD, 140)                 # change at 140 (contested)
ev = w.observe("Eth", IP, NEW, 161)            # 61 s after the first
check("three changes over 61 s -> not impersonated",
      "impersonated" not in kinds(ev), str(ev))

# ---- a third device during the hold is a change of hands, nothing more.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
ev = w.observe("Eth", IP, THIRD, 105)
check("third MAC during pending -> no event", ev == [], str(ev))
ev = w.observe("Eth", IP, OLD, 110)            # third change of hands
check("...but it counts: old, new, third, old -> impersonated",
      kinds(ev) == ["impersonated"] and set(ev[0][3]) >= {OLD, NEW, THIRD}, str(ev))
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
w.observe("Eth", IP, THIRD, 105)
ev = w.tick(166)
check("third MAC that stays -> replaced by the third",
      ev == [("replaced", "Eth", IP, OLD, THIRD)], str(ev))

# ---- after a replacement the old MAC returning within flip_window.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
w.tick(161)                       # replaced at 161, until 161 + 3600
ev = w.observe("Eth", IP, OLD, 161 + 1800)
check("old MAC at +1800 s after replacement -> contested",
      ev == [("contested", "Eth", IP, NEW, OLD)], str(ev))
check("...and no replaced back if the new one goes quiet",
      w.tick(161 + 1800 + 61) == [])

w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
w.tick(161)
ev = w.observe("Eth", IP, OLD, 161 + 3700)
check("old MAC at +3700 s -> no event, a new pending change", ev == [], str(ev))
ev = w.tick(161 + 3700 + 61)
check("... which settles as an ordinary replaced",
      ev == [("replaced", "Eth", IP, NEW, OLD)], str(ev))

# ---- a late observe settles the pending change first.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
w.observe("Eth", IP, NEW, 100)
ev = w.observe("Eth", IP, OLD, 200)       # hold over, tick not yet run
check("old MAC after the hold but before tick -> replaced, then contested",
      kinds(ev) == ["replaced", "contested"], str(ev))

# ---- adapters are separate.
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
check("same IP, other adapter: baseline", w.observe("Wi-Fi", IP, NEW, 1) == [])
w.observe("Eth", IP, NEW, 100)
check("other adapter unaffected by Eth's change",
      w.observe("Wi-Fi", IP, NEW, 110) == [] and w.tick(130) == [])
check("Eth change still settles on its own",
      w.tick(161) == [("replaced", "Eth", IP, OLD, NEW)])

# ---- bounded state.
w = W.ArpWatch()
for i in range(W.MAX_ENTRIES + 50):
    w.observe("Eth", f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}", OLD, i)
check("tracked entries are capped", len(w._entries) == W.MAX_ENTRIES, str(len(w._entries)))
check("the oldest was dropped, the newest kept",
      ("Eth", "10.0.0.0") not in w._entries
      and ("Eth", f"10.{(W.MAX_ENTRIES + 49) >> 16}.{((W.MAX_ENTRIES + 49) >> 8) & 255}.{(W.MAX_ENTRIES + 49) & 255}") in w._entries)
w = W.ArpWatch()
w.observe("Eth", IP, OLD, 0)
for i in range(50):
    w.observe("Eth", IP, f"de:ad:be:ef:00:{i:02x}", 1 + i)
check("per-entry seen is small", len(w._entries[("Eth", IP)]["seen"]) <= W.MAX_SEEN)
check("per-entry change times are small", len(w._entries[("Eth", IP)]["hands"]) <= W.REPEATS)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
