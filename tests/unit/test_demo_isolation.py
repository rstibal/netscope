"""
--demo invents its traffic, so none of it may reach this machine's real state.

It used to: the demo's chrome.exe, Code.exe and github.com went into the real
history database (inflating its totals and making those names "known", so a
real first sighting never warned), rule and mute changes went into the real
settings.json, and its DNS lookups went to the looked-up host itself
(github.com:53), which set off the unconfigured-resolver alert against the
machine's real resolver list. Runs a real demo server against an empty
LOCALAPPDATA and checks nothing lands there.
"""

import json, os, queue, re, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


home = tempfile.mkdtemp(prefix="netscope-demo-iso-")
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
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=None if body is None else json.dumps(body).encode(),
        headers={"X-NetScope-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


try:
    check("the demo server starts", token is not None, "".join(banner))
    if token:
        check("the banner says history is in memory",
              any("History:" in l and "in memory" in l for l in banner), "".join(banner))

        hist = call("/api/history")
        check("History still works in demo", hist.get("enabled") is True, str(hist)[:200])
        check("...and says it is in memory, not a file",
              "in memory" in (hist.get("summary") or {}).get("path", ""),
              str(hist.get("summary")))

        # Let some DNS go by: about one packet in eight.
        dns = []
        until = time.time() + 30
        while time.time() < until and len(dns) < 3:
            time.sleep(1)
            dns = [p for p in call("/api/state?since=0")["packets"]
                   if p.get("proto") == "DNS" and 53 in (p.get("sport"), p.get("dport"))]
        check("the demo produced DNS lookups", len(dns) >= 1)
        check("every demo DNS lookup is with the demo's resolver",
              dns and all(p["remote"] == "192.168.1.1" for p in dns),
              str({(p["remote"], p.get("rhost")) for p in dns}))

        al = call("/api/alerts")
        kinds = [a["rule"] for a in al["alerts"]]
        check("no unconfigured-resolver alert from demo traffic",
              "dns_resolver" not in kinds, str(kinds))
        check("the demo's regular programs are not 'new on this machine'",
              not any(a["rule"] == "new_process" and a.get("severity") == "warn"
                      and "SilentUpdater" not in a.get("detail", "")
                      and "CrashReporter" not in a.get("detail", "")
                      for a in al["alerts"]),
              str([(a["rule"], a.get("severity"), a.get("detail")) for a in al["alerts"]]))

        # Every kind of setting the dashboard can change.
        call("/api/control", {"action": "alerts", "rules": {"new_host": True},
                              "threshold_mb": 7, "reverse_dns": True})
        call("/api/control", {"action": "mute", "rule": "port_scan", "subject": "10.9.9.9"})
        call("/api/control", {"action": "history_exclude", "kind": "host",
                              "pattern": "example.org"})
        call("/api/control", {"action": "history_flush"})
        al = call("/api/alerts")
        check("changes still apply for the session",
              al["rules"]["new_host"] is True and al["threshold_mb"] == 7, str(al["rules"]))
        check("...and the exclusion is listed",
              "example.org" in call("/api/history")["exclude"]["hosts"])
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
# Python's own launcher may keep a cache under LOCALAPPDATA; only ours matters.
ours = [w for w in written if re.search(r"netscope", w, re.I)]
check("nothing was written to the settings folder", not ours, str(ours))
shutil.rmtree(home, True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
