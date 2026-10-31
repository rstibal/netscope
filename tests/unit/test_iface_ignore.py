"""
Ignored adapters: left out of "All active interfaces", including ones that
reconnect later, while naming one still captures it.

Drives the real Handler over HTTP with a stand-in engine, and the real
resolve_ifaces() against a made-up adapter list, so no Npcap is needed.
"""

import json, os, socket, sys, threading, urllib.error, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N

ADAPTERS = [
    {"name": "Ethernet", "description": "Intel(R) Ethernet", "ip": "192.168.1.20", "mac": ""},
    {"name": "Ethernet 2", "description": "Realtek USB GbE", "ip": "192.168.50.2", "mac": ""},
    {"name": "Wi-Fi", "description": "Intel(R) Wi-Fi 6E", "ip": "", "mac": ""},
    {"name": "Loopback", "description": "Npcap Loopback", "ip": "127.0.0.1", "mac": ""},
]
N.CaptureEngine.interfaces = staticmethod(lambda refresh=True: list(ADAPTERS))
resolve = N.CaptureEngine.resolve_ifaces

# -- resolve_ifaces ----------------------------------------------------------------
check("all, with nothing ignored, is every adapter with an address",
      resolve("all") == ["Ethernet", "Ethernet 2"], resolve("all"))
check("an ignored adapter is left out of all",
      resolve("all", ["Ethernet 2"]) == ["Ethernet"], resolve("all", ["Ethernet 2"]))
check("...and out of the default too",
      resolve("default", ["Ethernet 2"]) == ["Ethernet"], resolve("default", ["Ethernet 2"]))
check("naming an ignored adapter still captures it",
      resolve("Ethernet 2", ["Ethernet 2"]) == ["Ethernet 2"])
check("the no-address fallback does not bring an ignored adapter back",
      "Ethernet 2" not in resolve("all", ["Ethernet", "Ethernet 2"]),
      resolve("all", ["Ethernet", "Ethernet 2"]))


# -- the API -----------------------------------------------------------------------
class FakeEngine:
    """Enough of CaptureEngine for the control and status paths."""
    interfaces = staticmethod(lambda refresh=True: list(ADAPTERS))
    resolve_ifaces = staticmethod(resolve)
    def __init__(self):
        self.running, self.ignored, self.spec = False, [], "all"
        self.ifaces, self.iface, self.bpf, self.error = [], None, "", None
        self.starts = 0
    def start(self, iface=None, bpf=""):
        self.spec = iface or "default"
        self.ifaces = self.resolve_ifaces(self.spec, self.ignored)
        self.iface = ", ".join(self.ifaces)
        self.running = True
        self.starts += 1
        return True
    def stop(self):
        self.running = False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

eng = FakeEngine()
eng.start("all")
saved = {}
token = "test-token"
N.Handler.app = N.App(N.PacketStore(), eng, N.ProcessResolver(), token,
                      save_setting=lambda k, v: saved.__setitem__(k, v))
port = free_port()
httpd = N.DashboardServer(("127.0.0.1", port), N.Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"

def ignore(names):
    req = urllib.request.Request(base + "/api/control?t=" + token, method="POST",
                                 data=json.dumps({"action": "ignore_ifaces",
                                                  "ignore": names}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

try:
    code, d = ignore(["Ethernet 2"])
    check("ignoring an adapter is accepted", code == 200, d)
    check("the running all-adapters capture moved off it",
          eng.ifaces == ["Ethernet"] and eng.running and eng.starts == 2, (eng.ifaces, eng.starts))
    check("the choice is saved", saved.get("ignore_ifaces") == ["Ethernet 2"], saved)
    check("status names it, so the header can say so",
          d["status"]["ignored_ifaces"] == ["Ethernet 2"], d["status"])

    code, d = ignore(["Ethernet 2", "Wi-Fi"])
    check("ignoring an adapter not being captured does not restart",
          eng.starts == 2, eng.starts)

    code, d = ignore(["Ethernet", "Ethernet 2"])
    check("ignoring every adapter with an address is refused",
          code == 400 and "no adapter" in d.get("error", ""), d)
    check("...and leaves the list as it was", eng.ignored == ["Ethernet 2", "Wi-Fi"], eng.ignored)

    code, d = ignore("Ethernet")
    check("a list is required", code == 400, d)

    eng.stop(); eng.start("Ethernet 2")
    starts = eng.starts
    code, d = ignore(["Ethernet 2"])
    check("a capture on a named adapter is left alone",
          eng.starts == starts and eng.ifaces == ["Ethernet 2"], (eng.starts, eng.ifaces))

    eng.stop(); eng.start("all")
    code, d = ignore([])
    check("capturing an adapter again puts it back under all",
          eng.ifaces == ["Ethernet", "Ethernet 2"], eng.ifaces)
finally:
    httpd.shutdown()
    httpd.server_close()

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
