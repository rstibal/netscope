import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_tray as T

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

class FakeIcon:
    def __init__(self):
        self.title = None
        self.icon = None

class OneShot:
    """Stands in for threading.Event: lets _refresh's loop body run exactly once."""
    def __init__(self):
        self.n = 0
    def wait(self, timeout=None):
        self.n += 1
        return self.n > 1
    def set(self):
        pass

# ---- 1. _title(s) uses the status handed to it, never calls status_fn again.
# status_fn's "rate" is a stateful delta since the *previous* call — calling
# it twice per tick is what made the tray always read 0 B/s.
calls = []
def status_fn():
    calls.append(1)
    return {"rate": "44.4 KB/s", "packets": 100, "alerts": {"total": 0}, "running": True}

tr = T.Tray(url="http://x", on_quit=lambda: None, status_fn=status_fn)
snapshot = status_fn()
calls.clear()
title = tr._title(snapshot)
check("title(s) does not re-call status_fn", calls == [], str(calls))
check("title carries the rate from the snapshot", "44.4 KB/s" in title, title)

# ---- 2. _title() with no argument still works standalone.
calls.clear()
title2 = tr._title()
check("title() with no arg falls back to status_fn", calls == [1], str(calls))

# ---- 3. The actual bug: one refresh tick must call status_fn exactly once.
calls = []
def status_fn2():
    calls.append(1)
    return {"rate": "9.0 KB/s", "packets": 5, "alerts": {}, "running": True}

tr2 = T.Tray(url="http://x", on_quit=lambda: None, status_fn=status_fn2)
tr2.icon = FakeIcon()
tr2._stop = OneShot()
tr2._refresh()
check("one refresh tick calls status_fn exactly once", len(calls) == 1, str(len(calls)))
check("icon title reflects that single snapshot's rate",
      tr2.icon.title is not None and "9.0 KB/s" in tr2.icon.title, str(tr2.icon.title))

# ---- 4. The icon is static apart from running/stopped: no redraw for an
# unchanged state, a redraw to "off" when capture stops.
def status_fn3():
    return {"rate": "x", "packets": 0, "alerts": {}, "running": True}

tr3 = T.Tray(url="http://x", on_quit=lambda: None, status_fn=status_fn3)
tr3.icon = FakeIcon()
tr3._stop = OneShot()
tr3._refresh()
check("state starts idle while running", tr3.state == "idle", tr3.state)
check("no redraw yet -- state matched the Tray's own default", tr3.icon.icon is None)

def status_fn4():
    return {"rate": "x", "packets": 0, "alerts": {}, "running": False}

tr3.status_fn = status_fn4
tr3._stop = OneShot()
tr3._refresh()
check("state flips to off once capture stops", tr3.state == "off", tr3.state)
check("icon is redrawn once the state actually changes", tr3.icon.icon is not None)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
