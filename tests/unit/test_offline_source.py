"""
Going live after a .pcap import leaves offline mode.

Importing sets App.source, which the status bar shows as "offline · <file>"
and which detaches the Connections tab from the real socket table. Nothing
ever cleared it, so pressing Start after an import captured live traffic
while the page went on insisting it was showing a saved file.

Drives the real Handler over HTTP, with a stand-in capture engine so no
adapter, Npcap or admin rights are needed.
"""

import json, os, socket, sys, threading, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N

if not N.SCAPY_OK:
    print("SKIP  test_offline_source.py needs scapy to read a .pcap")
    sys.exit(0)


class FakeEngine:
    """Enough of CaptureEngine for the control and status paths."""
    def __init__(self):
        self.running = False
        self.iface, self.ifaces, self.spec = "eth0", ["eth0"], "eth0"
        self.bpf, self.error = "", None
    def start(self, iface=None, bpf=""):
        self.running = True
        return True
    def stop(self):
        self.running = False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


store = N.PacketStore()
resolver = N.ProcessResolver()
streams = N.StreamTracker()
objects = N.ObjectStore()
alerts = N.AlertEngine()
alerts._dns_read = N.time.time()
decoder = N.CaptureEngine(store, resolver, streams=streams, alerts=alerts)
token = "test-token"
N.Handler.app = N.App(store, FakeEngine(), resolver, token, streams=streams,
                      objects=objects, alerts=alerts, decoder=decoder)
# Don't let a real (unrelated) settings file be written by the start action.
N.save_setting = lambda *a, **k: None

port = free_port()
httpd = N.DashboardServer(("127.0.0.1", port), N.Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"


def post(path, data, ctype="application/json"):
    req = urllib.request.Request(base + path + ("&" if "?" in path else "?") +
                                 "t=" + token, data=data, method="POST",
                                 headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def control(**body):
    return post("/api/control", json.dumps(body).encode())["status"]


frame = N.DemoEngine.frame("192.168.1.20", 50000, "203.0.113.5", 80, b"GET / HTTP/1.1\r\n\r\n")
pcap = N.write_pcap([(1_700_000_000.0, frame, len(frame))])

try:
    got = post("/api/import?name=saved.pcap", pcap, "application/octet-stream")
    check("import loads the file", got.get("loaded") == 1, str(got))
    check("import puts the dashboard in offline mode",
          got["status"]["source"] == "saved.pcap", str(got["status"]["source"]))

    st = control(action="start", iface="eth0")
    check("Start after an import leaves offline mode",
          st["source"] is None and st["running"], str(st["source"]))

    post("/api/import?name=again.pcap", pcap, "application/octet-stream")
    st = control(action="restart", iface="eth0")
    check("Apply (restart) after an import leaves offline mode too",
          st["source"] is None, str(st["source"]))

    post("/api/import?name=kept.pcap", pcap, "application/octet-stream")
    st = control(action="clear")
    check("Clear keeps offline mode (still looking at the file)",
          st["source"] == "kept.pcap", str(st["source"]))
finally:
    httpd.shutdown()
    httpd.server_close()

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
