"""
A second NetScope on the same port must fail loudly, not silently squat.

Windows' SO_REUSEADDR (which http.server.HTTPServer sets by default) lets a
second process bind a port another process is already listening on — no
error, and every request just keeps going to whichever one bound first. A
second launch then prints and opens a URL carrying its own, different token,
which the process actually serving requests never recognises: a "bad token"
403 with no hint that a second copy is running. Only reproducible on Windows,
where SO_EXCLUSIVEADDRUSE is the fix; harmless to import and skip elsewhere.
"""

import os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

if os.name != "nt":
    print("SKIP  test_dashboard_server.py needs Windows (SO_EXCLUSIVEADDRUSE)")
    sys.exit(0)

import netscope as N


class DummyHandler:
    pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


port = free_port()

first = N.DashboardServer(("127.0.0.1", port), N.Handler)
try:
    threw = False
    try:
        N.DashboardServer(("127.0.0.1", port), N.Handler)
    except OSError:
        threw = True
    check("a second DashboardServer on the same port fails to bind", threw)
finally:
    first.server_close()

# ---- the port is free again once the first server releases it -------------
second = N.DashboardServer(("127.0.0.1", port), N.Handler)
check("the port can be reused once the first server closes", True)
second.server_close()

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
