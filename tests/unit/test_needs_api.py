"""
Needs you over the API: who a new program is, trusting it, the demo's cards.

Two parts. Without a server: locate_program()'s fallbacks, trust_card()'s
two refusals-or-not (the file changed since the alert, the file is gone),
the demo's notifier that can never send, and imported .pcap records that
must never open a card. Against a real demo server (sys.executable, a
scratch LOCALAPPDATA, as in test_demo_isolation.py): the three cards the
demo opens at start, acting on them, and nothing written to disk.
"""

import hashlib, json, os, queue, re, shutil, socket, subprocess, sys, tempfile
import threading, time
import urllib.error, urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, ROOT)

import netscope as N
from netscope_alerts import AlertEngine
from netscope_needs import NeedsYou
from netscope_trust import TrustList, file_sha256

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


# ---- Without a server ------------------------------------------------------

scratch = tempfile.mkdtemp(prefix="netscope-needs-api-")
try:
    # locate_falls_back: the pid is gone, the session saw the file.
    exe = os.path.join(scratch, "Thing.exe")
    with open(exe, "wb") as f:
        f.write(b"MZ thing")

    class FakeResolver:
        def known_paths(self, name):
            return {exe} if name.lower() == "thing.exe" else set()

    class FakeHistory:
        def known_paths(self, name):
            return set()

    gone_pid = 2 ** 31 - 7          # no such process
    got = N.locate_program(FakeResolver(), FakeHistory(), "Thing.exe", gone_pid)
    check("locate_falls_back: a gone pid falls back to the session's path",
          got == (exe, None), str(got))
    got = N.locate_program(FakeResolver(), FakeHistory(), "Other.exe", gone_pid)
    check("locate_falls_back: nothing known gives (None, None)",
          got == (None, None), str(got))

    # trust_changed_or_gone
    needs = NeedsYou(None)
    trust = TrustList()
    card = needs.add("program", "Thing.exe",
                     {"name": "Thing.exe", "path": exe, "sha256": "0" * 64})
    code, body = N.trust_card(trust, needs, file_sha256, card)
    want = hashlib.sha256(b"MZ thing").hexdigest()
    check("trust_changed: a file whose hash moved is trusted (200)", code == 200, str(body))
    check("trust_changed: ...marked changed since the alert",
          body.get("trusted", {}).get("changed") is True, str(body))
    check("trust_changed: ...at the hash it has now",
          body.get("trusted", {}).get("sha256") == want, str(body))
    check("trust_changed: ...and the Trusted list says changed",
          any(e.get("changed") for e in trust.entries()), str(trust.entries()))
    check("trust_changed: the card is acted on", needs.get(card["id"])["state"] == "trusted")

    gone = os.path.join(scratch, "Gone.exe")
    with open(gone, "wb") as f:
        f.write(b"MZ gone")
    card2 = needs.add("program", "Gone.exe",
                      {"name": "Gone.exe", "path": gone,
                       "sha256": hashlib.sha256(b"MZ gone").hexdigest()})
    os.remove(gone)
    before = trust.entries()
    code, body = N.trust_card(trust, needs, file_sha256, card2)
    check("trust_gone: a deleted file gives 409", code == 409, str((code, body)))
    check("trust_gone: ...saying to dismiss instead",
          "Dismiss it instead" in body.get("error", ""), str(body))
    check("trust_gone: ...the card stays open", needs.get(card2["id"])["state"] == "open")
    check("trust_gone: ...the trust list is unchanged", trust.entries() == before)
finally:
    shutil.rmtree(scratch, True)

# The demo's notifier never sends, though it reads as on.
calls = []
import subprocess as _sp
orig = _sp.run
_sp.run = lambda *a, **k: calls.append(a)
try:
    quiet = N.SilentNotifier(enabled=True)
    quiet.notify("NetScope: test", "body")
    quiet._send("NetScope: test", "body")
    time.sleep(0.2)
finally:
    _sp.run = orig
check("the demo's notifier reads as enabled", quiet.enabled is True)
check("...and never sends a toast", calls == [], str(calls))

# A verdict arriving after the rule was switched off says nothing.
eng = AlertEngine()
eng.rules["new_process"] = False
from netscope_trust import Sig, Verdict
r = eng.on_program_verdict("Late.exe", {"pid": 1},
                           {"verdict": Verdict("needs", "unsigned_writable"),
                            "sig": Sig("unsigned", ""), "path": r"C:\Temp\Late.exe",
                            "parent": None, "sha256": "x"})
check("a verdict after new_process was switched off opens no card",
      r is None and eng.needs.open() == [], str(r))


# Imported records: never ArpWatch, never the judge.
class CountingJudge:
    def __init__(self):
        self.got = []
    def submit(self, name, pid, rec):
        self.got.append(name)


class KnowsNothing:
    """A history that has seen nothing, so every program is new."""
    enabled = True
    was_empty = False
    def known_process(self, name): return False
    def note_process(self, name): pass
    def record_alert(self, a): pass
    def needs_load(self): return []
    def needs_save(self, c): return None


eng = AlertEngine(history=KnowsNothing())
eng._dns_read = time.time()
eng.baselining = False
judge = CountingJudge()
eng.attach_judge(judge)


def arp_rec(mac, offline):
    rec = {"ts": time.time(), "iface": "eth0", "process": "(link layer)", "length": 42,
           "proto": "ARP", "decoded": {"arp": {"op": 2, "sender_ip": "192.168.1.1",
                                               "sender_mac": mac}}}
    if offline:
        rec["offline"] = True
    return rec


for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa"):
    eng.inspect(arp_rec(mac, True), b"")
eng.inspect({"ts": time.time(), "process": "Imported.exe", "pid": 9, "length": 60,
             "offline": True, "decoded": {}}, b"")
eng.tick()
check("an imported ARP flip is not watched", eng.arp._entries == {} and eng.needs.open() == [],
      str(eng.arp._entries))
check("an imported program is not judged", judge.got == [], str(judge.got))
eng.inspect({"ts": time.time(), "process": "Imported.exe", "pid": 9, "length": 60,
             "decoded": {}}, b"")
check("...and is judged once it turns up live", judge.got == ["Imported.exe"], str(judge.got))

if N.SCAPY_OK:
    from scapy.layers.l2 import Ether, ARP
    seen = []
    a2 = AlertEngine()
    a2._dns_read = time.time()
    orig_inspect = a2.inspect
    a2.inspect = lambda rec, payload: (seen.append(rec), orig_inspect(rec, payload))
    dec = N.CaptureEngine(N.PacketStore(), N.ProcessResolver(), alerts=a2)
    frames = []
    for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa"):
        p = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc=mac, psrc="192.168.1.1", pdst="192.168.1.2")
        p.time = time.time()
        frames.append(p)
    dec.ingest_file(frames)
    a2.tick()
    check("ingest_file marks its records offline",
          len(seen) == 3 and all(r.get("offline") is True for r in seen),
          str([r.get("offline") for r in seen]))
    check("...so an imported capture opens no card", a2.needs.open() == [])
    seen.clear()
    dec._on_packet(frames[0], "eth0")
    check("a live packet is not marked offline", seen and "offline" not in seen[0])
else:
    print("SKIP  ingest_file offline marking needs scapy")


# ---- Against a demo server ---------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


home = tempfile.mkdtemp(prefix="netscope-needs-api-home-")
port = free_port()
proc = subprocess.Popen(
    [sys.executable, "-u", os.path.join(ROOT, "netscope.py"), "--demo",
     "--port", str(port), "--no-browser"],
    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    env={**os.environ, "PYTHONUNBUFFERED": "1", "LOCALAPPDATA": home, "HOME": home})

lines = queue.Queue()
def pump():
    for line in proc.stdout:
        lines.put(line)
    lines.put(None)
threading.Thread(target=pump, daemon=True).start()

banner, token = [], None
deadline = time.time() + 60
while time.time() < deadline and token is None:
    try:
        line = lines.get(timeout=1)
    except queue.Empty:
        continue
    if line is None:
        break
    banner.append(line)
    m = re.search(r"\?t=([\w-]+)", line)
    if m:
        token = m.group(1)


def call(path, body=None):
    """(status, json body), 4xx included."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=None if body is None else json.dumps(body).encode(),
        headers={"X-NetScope-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def find(needs, kind, subject):
    return next((c for c in needs if c["kind"] == kind and c["subject"] == subject), None)


SU_PATH = r"C:\Users\Demo\AppData\Local\Temp\su7\SilentUpdater.exe"

try:
    check("the demo server starts", token is not None, "".join(banner))
    if token:
        al = {}
        until = time.time() + 30
        while time.time() < until:
            _, al = call("/api/alerts")
            if len(al.get("needs") or []) >= 3:
                break
            time.sleep(1)
        needs = al.get("needs") or []
        su = find(needs, "program", "SilentUpdater.exe")
        va = find(needs, "program", "Vanished.exe")
        arp = find(needs, "arp", "192.168.1.1")
        check("exactly three open cards", len(needs) == 3,
              str([(c["kind"], c["subject"]) for c in needs]))
        check("SilentUpdater: unsigned in a writable folder, started by chrome.exe",
              su is not None and su["data"].get("reason") == "unsigned_writable"
              and su["data"].get("parent") == "chrome.exe", str(su))
        check("Vanished: its file can't be found",
              va is not None and va["data"].get("reason") == "no_file", str(va))
        check("an ARP card for the router", arp is not None, str(needs))
        check("counts.needs == 3", (al.get("counts") or {}).get("needs") == 3,
              str(al.get("counts")))
        check("program cards carry talk_hosts",
              su is not None and isinstance(su["data"].get("talk_hosts"), list), str(su))
        check("the payload says when the last program check was",
              isinstance(al.get("last_program_check"), (int, float)), str(al.get("last_program_check")))
        check("...and since when NetScope has been watching",
              isinstance(al.get("watching_since"), (int, float)))
        check("the demo's toasts read as on", al.get("toasts") is True, str(al.get("toasts")))

        if su:
            # Blocking is off until switched on: Block is refused, the card stays.
            code, body = call("/api/control", {"action": "needs_act", "id": su["id"],
                                               "act": "block"})
            check("block with blocking off returns 400",
                  code == 400 and "switched off" in body.get("error", ""), str((code, body)))
            _, al = call("/api/alerts")
            check("...and the card stays",
                  find(al["needs"], "program", "SilentUpdater.exe") is not None)
            code, body = call("/api/control", {"action": "needs_act", "id": su["id"],
                                               "act": "bogus"})
            check("an act that isn't one returns 400", code == 400, str((code, body)))
            code, body = call("/api/control", {"action": "needs_act", "id": su["id"],
                                               "act": "expected"})
            check("'expected' on a program card returns 400", code == 400, str((code, body)))
            code, body = call("/api/control", {"action": "needs_act", "id": su["id"],
                                               "act": "trust"})
            check("trusting SilentUpdater returns 200", code == 200, str((code, body)))
            _, al = call("/api/alerts")
            check("...its card is gone",
                  find(al["needs"], "program", "SilentUpdater.exe") is None)
            check("...and Trusted lists its demo path",
                  any(e.get("path") == SU_PATH for e in al.get("trusted") or []),
                  str(al.get("trusted")))
        if va:
            code, body = call("/api/control", {"action": "needs_act", "id": va["id"],
                                               "act": "trust"})
            check("trusting Vanished returns 409", code == 409, str((code, body)))
            _, al = call("/api/alerts")
            check("...and its card stays", find(al["needs"], "program", "Vanished.exe") is not None)
            code, body = call("/api/control", {"action": "needs_act", "id": va["id"],
                                               "act": "dismiss"})
            check("dismissing Vanished returns 200", code == 200, str((code, body)))
        if arp:
            code, body = call("/api/control", {"action": "needs_act", "id": arp["id"],
                                               "act": "block"})
            check("block on an ARP card returns 400", code == 400, str((code, body)))
            code, body = call("/api/control", {"action": "needs_act", "id": arp["id"],
                                               "act": "expected"})
            check("'expected' on the ARP card returns 200", code == 200, str((code, body)))
            _, al = call("/api/alerts")
            check("...and it goes", find(al["needs"], "arp", "192.168.1.1") is None)
            check("...muting the router's address",
                  any(m.get("rule") == "arp_spoof" and m.get("subject") == "192.168.1.1"
                      for m in al.get("mutes") or []), str(al.get("mutes")))
        code, body = call("/api/control", {"action": "trust_remove", "path": SU_PATH})
        _, al = call("/api/alerts")
        check("trust_remove takes it off the Trusted list",
              code == 200 and not any(e.get("path") == SU_PATH for e in al.get("trusted") or []),
              str((code, al.get("trusted"))))
        code, body = call("/api/control", {"action": "needs_act", "id": 999999, "act": "dismiss"})
        check("acting on a card that isn't open is a 404", code == 404, str((code, body)))
finally:
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()

written = []
for dirpath, _dirs, files in os.walk(home):
    for f in files:
        written.append(os.path.relpath(os.path.join(dirpath, f), home))
ours = [w for w in written if re.search(r"netscope", w, re.I)]
check("nothing was written to the settings folder", not ours, str(ours))
shutil.rmtree(home, True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
