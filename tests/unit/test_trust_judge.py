import os, sys, tempfile, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_trust as T
from netscope_trust import Sig, Verdict

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

tmp = tempfile.mkdtemp(prefix="ns_trust_")
def write(name, data=b"x"):
    p = os.path.join(tmp, name)
    with open(p, "wb") as f:
        f.write(data)
    return p

# ---- cache
calls = []
def fake_run(path, timeout):
    calls.append((path, timeout))
    return Sig("valid", "Acme")
ck = T.SignatureChecker(run=fake_run, cap=5.0)
f1 = write("a.exe")
s1 = ck.check(f1); s2 = ck.check(f1)
check("cache: same result", s1 == s2 == Sig("valid", "Acme"))
check("cache: run called once", len(calls) == 1, str(calls))
check("cache: run gets the cap", calls[0][1] == 5.0)
time.sleep(0.02)
write("a.exe", b"longer content")
ck.check(f1)
check("cache: rewritten file is checked again", len(calls) == 2)
check("missing file -> missing", ck.check(os.path.join(tmp, "nope.exe")) == Sig("missing", ""))
check("missing never reaches run", len(calls) == 2)

# ---- timeout and errors
def slow_run(path, timeout):
    time.sleep(3)
    return Sig("valid", "x")
ck2 = T.SignatureChecker(run=slow_run, cap=0.3)
t0 = time.time()
r = ck2.check(f1)
check("checker_timeout: unknown", r == Sig("unknown", ""), str(r))
check("checker_timeout: within cap + 1s", time.time() - t0 < 1.3, str(time.time() - t0))

def no_ps(path, timeout):
    raise FileNotFoundError("powershell")
ck3 = T.SignatureChecker(run=no_ps)
check("no PowerShell -> unknown", ck3.check(f1) == Sig("unknown", ""))
n = []
def flaky(path, timeout):
    n.append(1)
    if len(n) == 1:
        return Sig("unknown", "")
    return Sig("valid", "Acme")
ck4 = T.SignatureChecker(run=flaky)
ck4.check(f1)
check("unknown is not cached", ck4.check(f1) == Sig("valid", "Acme"))

# ---- trust list
tl = T.TrustList()
e = tl.add("a.exe", f1, "h1")
check("add returns entry", set(e) == {"name", "path", "sha256", "ts"} and e["name"] == "a.exe")
check("trusted at same hash", tl.is_trusted(f1, "h1"))
check("not trusted at other hash", not tl.is_trusted(f1, "h2"))
check("path compare is normalised", tl.is_trusted(f1.upper().replace("\\", "/"), "h1"))
tl2 = T.TrustList(tl.entries())
check("entries round-trip", tl2.is_trusted(f1, "h1") and tl2.entries() == tl.entries())
check("remove once", tl.remove(f1) is True)
check("remove twice", tl.remove(f1) is False)
check("removed is untrusted", not tl.is_trusted(f1, "h1"))

# ---- hash
check("file_sha256 missing -> None", T.file_sha256(os.path.join(tmp, "nope")) is None)
import hashlib
check("file_sha256 value", T.file_sha256(f1) == hashlib.sha256(open(f1, "rb").read()).hexdigest())

# ---- judge
class Boom(Exception): pass
got = []
def on_v(name, rec, info):
    got.append((name, rec, info))

def mkjudge(locate, checker=None, trust=None):
    return T.ProgramJudge(checker or T.SignatureChecker(run=fake_run),
                          trust or T.TrustList(), locate, on_v,
                          hash_file=lambda p: "hash-" + os.path.basename(p))

calls.clear()
trust = T.TrustList()
trust.add("a.exe", f1, "hash-a.exe")
j = mkjudge(lambda n, pid: (f1, "parent.exe"), trust=trust)
info = j.judge("a.exe", 5, {"k": 1})
check("trusted -> recorded/trusted", info["verdict"] == Verdict("recorded", "trusted"), str(info))
check("trusted skips the checker", calls == [])
check("on_verdict got same info", got and got[-1][2] is info and got[-1][1] == {"k": 1})
check("info fields", info["path"] == f1 and info["parent"] == "parent.exe"
      and info["sha256"] == "hash-a.exe")
check("last_ts set", j.last_ts is not None)

j = mkjudge(lambda n, pid: (None, None))
info = j.judge("a.exe", 5, {})
check("no path -> needs/no_file", info["verdict"] == Verdict("needs", "no_file"), str(info))

# changed hash is not trusted
j = mkjudge(lambda n, pid: (f1, None), trust=trust)
trust2 = T.TrustList(); trust2.add("a.exe", f1, "other")
j = mkjudge(lambda n, pid: (f1, None), trust=trust2)
info = j.judge("a.exe", 5, {})
check("hash changed -> judged normally", info["verdict"] == Verdict("recorded", "signed"), str(info))

# a raising locate still delivers one needs/unchecked verdict, sync and worker
def bad_locate(n, pid):
    raise Boom()
got.clear()
info = mkjudge(bad_locate).judge("bad.exe", 1, {"r": 0})
check("raising locate -> one needs/unchecked", len(got) == 1
      and got[0][2]["verdict"] == Verdict("needs", "unchecked")
      and info is got[0][2] and info["path"] is None, str(got))

got.clear()
def sometimes_bad(n, pid):
    if n == "bad.exe":
        raise Boom()
    return (f1, None)
j = mkjudge(sometimes_bad)
j.start()
j.submit("bad.exe", 1, {})
j.submit("a.exe", 2, {})
end = time.time() + 2
while len(got) < 2 and time.time() < end:
    time.sleep(0.02)
check("worker survives: bad then good both delivered",
      [g[0] for g in got] == ["bad.exe", "a.exe"]
      and got[0][2]["verdict"] == Verdict("needs", "unchecked")
      and got[1][2]["verdict"] == Verdict("recorded", "signed"), str(got))

# an on_verdict that raises is caught by the worker, which carries on
got.clear()
boom_once = []
def flaky_on_v(name, rec, info):
    if not boom_once:
        boom_once.append(1)
        raise Boom()
    got.append(name)
j = T.ProgramJudge(T.SignatureChecker(run=fake_run), T.TrustList(),
                   lambda n, pid: (f1, None), flaky_on_v,
                   hash_file=lambda p: "h")
j.start()
j.submit("one.exe", 1, {}); j.submit("two.exe", 2, {})
end = time.time() + 2
while not got and time.time() < end:
    time.sleep(0.02)
check("worker survives a raising on_verdict", got == ["two.exe"], str(got))

# ---- submit + worker
got.clear()
j = mkjudge(lambda n, pid: (f1, None))
j.start()
j.submit("a.exe", 1, {"r": 1})
end = time.time() + 2
while not got and time.time() < end:
    time.sleep(0.02)
time.sleep(0.2)
check("submit delivers exactly once", len(got) == 1, str(len(got)))
check("worker thread name", any(t.name == "program-judge" for t in threading.enumerate()))

# ---- real PowerShell
if os.name == "nt":
    exe = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(exe):
        exe = r"C:\Windows\System32\cmd.exe"
    s = T.powershell_signature(exe, 20.0)
    check("real: system exe is valid", s.status == "valid" and s.signer, str(s))
    s = T.powershell_signature(f1, 20.0)
    # Windows reports UnknownError (-> invalid) for a file that is not a PE
    # image, not NotSigned; either way it is not valid and has no signer.
    check("real: tiny file is not valid", s.status in ("unsigned", "invalid")
          and not s.signer, str(s))
    s = T.powershell_signature(os.path.join(tmp, "nope.exe"), 20.0)
    check("real: missing file", s.status == "missing", str(s))
    evil = write("it's $(calc) ‘x’.exe")
    s = T.powershell_signature(evil, 20.0)
    check("real: odd characters in the path are inert",
          s.status in ("unsigned", "invalid") and not s.signer, str(s))
else:
    print("SKIP  real powershell_signature (not Windows)")

# ---- the signature check runs PowerShell by full path, not off PATH
root = tempfile.mkdtemp()
ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
check("powershell_exe: no such file -> bare name",
      T.powershell_exe({"SystemRoot": root}) == "powershell")
os.makedirs(os.path.dirname(ps))
open(ps, "wb").close()
check("powershell_exe: the full path under %SystemRoot%",
      T.powershell_exe({"SystemRoot": root}) == ps, T.powershell_exe({"SystemRoot": root}))
seen = []
orig_run = T.subprocess.run
T.subprocess.run = lambda cmd, **k: seen.append(cmd) or (_ for _ in ()).throw(OSError())
try:
    T.powershell_signature(f1, 1)
finally:
    T.subprocess.run = orig_run
check("powershell_signature launches powershell_exe()",
      seen and seen[0][0] == T.powershell_exe(), str(seen))

print()
print("FAILED: " + ", ".join(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
