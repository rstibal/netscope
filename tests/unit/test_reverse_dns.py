import os, sys, unittest.mock as mock
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


def resolver(enabled=True):
    r = N.ReverseResolver(N.PacketStore(), enabled=enabled)
    return r


# ---- off by default, and request() is a no-op while off -------------------
r = resolver(enabled=False)
check("disabled by construction default", N.ReverseResolver(N.PacketStore()).enabled is False)
r.request("203.0.113.9")
check("disabled -> nothing queued", r._queue.qsize() == 0)

# ---- enabled: a fresh IP gets queued and marked in-flight ------------------
r = resolver()
r.request("203.0.113.9")
check("fresh IP is queued", r._queue.qsize() == 1)
check("fresh IP is tracked as in-flight", "203.0.113.9" in r._queued)

# ---- calling request() again for the same IP while in-flight doesn't double-queue
r.request("203.0.113.9")
check("in-flight IP is not re-queued", r._queue.qsize() == 1)

# ---- an IP the store already has a name for is never queued ---------------
r = resolver()
r.store.note_host("203.0.113.10", "known.example")
r.request("203.0.113.10")
check("already-named IP is never queued", r._queue.qsize() == 0)

# ---- negative cache: a recent failure is not retried -----------------------
r = resolver()
r._negative["203.0.113.11"] = N.time.time() + 600
r.request("203.0.113.11")
check("recently-failed IP is not retried", r._queue.qsize() == 0)

r._negative["203.0.113.11"] = N.time.time() - 1   # expired
r.request("203.0.113.11")
check("an expired negative-cache entry can be retried", r._queue.qsize() == 1)

# ---- a successful resolution lands in the store via note_host() -----------
r = resolver()
r.request("203.0.113.12")
r._queue.get_nowait()      # simulate a worker thread dequeuing it
with mock.patch.object(N.socket, "gethostbyaddr", return_value=("host.example", [], [])):
    r._resolve_one("203.0.113.12")
check("successful lookup names the IP", r.store.hostname("203.0.113.12") == "host.example")
check("resolved IP is no longer in-flight", "203.0.113.12" not in r._queued)

# ---- a failed resolution negative-caches instead of crashing ---------------
r = resolver()
r.request("203.0.113.13")
r._queue.get_nowait()      # simulate a worker thread dequeuing it
with mock.patch.object(N.socket, "gethostbyaddr", side_effect=OSError("no PTR record")):
    r._resolve_one("203.0.113.13")
check("failed lookup -> no crash, IP left unnamed", r.store.hostname("203.0.113.13") is None)
check("failed lookup is negative-cached",
      r._negative.get("203.0.113.13", 0) > N.time.time())
check("failed lookup is no longer in-flight", "203.0.113.13" not in r._queued)
r.request("203.0.113.13")
check("negative-cached IP is not immediately re-queued", r._queue.qsize() == 0)

# ---- the attempt cap stops a huge capture from queuing forever ------------
r = resolver()
r.MAX_ATTEMPTS = 2
r.request("203.0.113.20")
r.request("203.0.113.21")
r.request("203.0.113.22")
check("attempt cap stops further requests", r._queue.qsize() == 2)

# ---- persistence round trip, same shape as AlertEngine's ------------------
store_dict = {}
load = lambda: dict(store_dict)
save = lambda k, v: store_dict.__setitem__(k, v)

r = resolver(enabled=False)
r.attach_settings(load, save)
check("no stored value -> stays at the constructor default", r.enabled is False)

r.set_enabled(True)
check("set_enabled updates the live flag", r.enabled is True)
check("set_enabled persists", store_dict.get("reverse_dns") is True)

r2 = N.ReverseResolver(N.PacketStore(), enabled=False)
r2.attach_settings(load, save)
check("a fresh instance picks up the persisted choice", r2.enabled is True)

# ---- degrades without a settings sink, and survives a broken one ----------
r3 = resolver(enabled=False)
r3.set_enabled(True)  # no sink attached -- must not raise
check("no settings sink -> no crash, flag still updates", r3.enabled is True)

def boom(*a, **k): raise IOError("disk full")
r4 = resolver(enabled=False)
r4.attach_settings(boom, boom)
r4.set_enabled(True)
check("a failing settings store never breaks the toggle", r4.enabled is True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
