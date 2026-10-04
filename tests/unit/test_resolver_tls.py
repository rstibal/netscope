import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def resolver(pmap, local_ips):
    r = N.ProcessResolver.__new__(N.ProcessResolver)
    r._map, r._local_ips = dict(pmap), set(local_ips)
    r._names, r._lock = {}, N.threading.Lock()
    r.available = False
    return r

LOCAL, REMOTE = "192.168.1.20", "93.184.216.34"

# ---- attribution: the remote port must not claim a remote conversation ------
# A local web server (pid 4) listens on 443. An outbound HTTPS connection from
# a short-lived program is not in the socket table yet.
r = resolver({(443, "tcp"): 4}, [LOCAL])
r.name_for_pid = lambda pid: "System" if pid == 4 else "other"
name, pid, d = r.lookup(52000, 443, "tcp", LOCAL, REMOTE)
check("an outbound connection to a remote :443 is not given to the local :443 server",
      pid is None and d == "out", (name, pid, d))
name, pid, d = r.lookup(443, 52000, "tcp", REMOTE, LOCAL)
check("...nor is its reply", pid is None and d == "in", (name, pid, d))

# Loopback, where both ends are sockets on this machine, still falls back.
r = resolver({(8080, "tcp"): 4242}, [LOCAL, "127.0.0.1"])
r.name_for_pid = lambda pid: "server.exe"
name, pid, d = r.lookup(53000, 8080, "tcp", "127.0.0.1", "127.0.0.1")
check("loopback traffic still finds the listener by the other port", pid == 4242, (name, pid, d))
r = resolver({(8080, "tcp"): 4242}, [])      # no address list yet: keep the old behaviour
r.name_for_pid = lambda pid: "server.exe"
check("with no address list the fallback still works", r.lookup(53000, 8080, "tcp", "10.0.0.1", "10.0.0.2")[1] == 4242)

# ---- names: a reused pid is not given the old name ---------------------------
r = resolver({}, [])
names = iter(["old.exe", "new.exe"])
class P:
    def __init__(self, pid): pass
    def name(self): return next(names)
real = N.psutil
class FakePsutil:
    Process = P
N.psutil = FakePsutil
try:
    check("first lookup", r.name_for_pid(77) == "old.exe")
    check("cached within the TTL", r.name_for_pid(77) == "old.exe")
    r._names[77] = ("old.exe", time.time() - 1)          # TTL passed
    check("re-read after the TTL, so a reused pid gets its new name", r.name_for_pid(77) == "new.exe")
    class Gone:
        def __init__(self, pid): raise ProcessLookupError()
    FakePsutil.Process = Gone
    check("a failed lookup falls back to the pid", r.name_for_pid(9) == "pid 9")
    r._names[9] = ("pid 9", time.time() - 1)             # only retried briefly
    FakePsutil.Process = P
    names = iter(["came-back.exe"])
    check("...and is retried soon rather than kept for good", r.name_for_pid(9) == "came-back.exe")
finally:
    N.psutil = real

# ---- TLS: arbitrary data segments are not mistaken for records ---------------
import struct
def rec(rtype, ver, ln, body=b"\x01\x00\x00\x00"):
    return bytes([rtype]) + struct.pack("!HH", ver, ln) + body
check("a real handshake record is recognised", N.decode_tls(rec(0x16, 0x0303, 60)) is not None)
check("TLS 1.3 application data is recognised", N.decode_tls(rec(0x17, 0x0303, 1200, b"x" * 20)) is not None)
check("SSL 3.0 is named", (N.decode_tls(rec(0x16, 0x0300, 60)) or {}).get("version") == "SSL 3.0")
check("a record claiming 60 KB is not TLS", N.decode_tls(rec(0x17, 0x0303, 60000)) is None)
check("an impossible version is not TLS", N.decode_tls(rec(0x17, 0x03FF, 100)) is None
      and N.decode_tls(rec(0x17, 0x0305, 100)) is None)

sys.exit(1 if fails else 0)
