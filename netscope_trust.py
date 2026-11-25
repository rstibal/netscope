"""Should a newly seen program interrupt the user?

The classifier (`classify_program`, `windows_home` and the folder helpers) is
pure: a program's name, file path and signature in, a verdict out, touching
nothing. The rest does I/O: `file_sha256` reads the file,
`powershell_signature` and `SignatureChecker` run PowerShell to read its
Authenticode signature, and `ProgramJudge` locates, hashes and checks a new
program off the capture thread. None of it touches the network.
"""
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections import namedtuple

Sig = namedtuple("Sig", "status signer")
Verdict = namedtuple("Verdict", "pile reason")

WINDOWS_NAMES = frozenset("""
svchost.exe lsass.exe csrss.exe smss.exe wininit.exe winlogon.exe
services.exe explorer.exe rundll32.exe dllhost.exe taskhostw.exe conhost.exe
spoolsv.exe sihost.exe ctfmon.exe dwm.exe regsvr32.exe powershell.exe cmd.exe
wmiprvse.exe msiexec.exe searchindexer.exe
""".split())

_WRITABLE_SUB = ("Temp", "Tasks", "Tracing", "Debug", "ServiceProfiles",
                 r"Registration\CRMLog", r"System32\Tasks", r"System32\spool",
                 r"SysWOW64\Tasks")


def norm_path(path):
    p = (path or "").replace("/", "\\")
    if p.startswith("\\\\?\\"):
        p = p[4:]
    return p.lower()


def _env(env, name, default):
    """Case-insensitive lookup; a missing or blank value takes the default."""
    want = name.lower()
    for k, val in env.items():
        if str(k).lower() == want and val and str(val).strip():
            return str(val)
    return default


def _dir(path):
    p = norm_path(path).rstrip("\\")
    return p + "\\" if p else ""


def _root(env):
    drive = _env(env, "SystemDrive", "C:")
    return _env(env, "SystemRoot", drive + "\\Windows")


def admin_dirs(env=os.environ):
    drive = _env(env, "SystemDrive", "C:")
    pf = _env(env, "ProgramFiles", drive + "\\Program Files")
    out = [pf,
           _env(env, "ProgramFiles(x86)", drive + "\\Program Files (x86)"),
           _env(env, "ProgramW6432", pf),
           _root(env)]
    seen = []
    for d in map(_dir, out):
        if d and d not in seen:
            seen.append(d)
    return seen


def writable_under_windows(env=os.environ):
    root = _root(env)
    return [_dir(root)] + [_dir(root + "\\" + s) for s in _WRITABLE_SUB]


def system_dirs(env=os.environ):
    root = _root(env)
    return [_dir(root + "\\" + s) for s in ("System32", "SysWOW64", "WinSxS")]


def _under(npath, dirs):
    return any(npath.startswith(d) for d in dirs)


def windows_home(path, env=os.environ):
    """
    Is `path` where Windows keeps its own programs: System32, SysWOW64,
    WinSxS, or directly in %SystemRoot% (explorer.exe's home)? Not the
    folders under them a user can write to (System32\\Tasks, spool...).
    """
    p = norm_path(path)
    if _under(p, writable_under_windows(env)[1:]):
        return False
    return (_under(p, system_dirs(env))
            or _dir(p.rpartition("\\")[0]) == _dir(_root(env)))


def classify_program(name, path, sig, env=os.environ):
    if not (name or "").lower().endswith(".exe"):
        return Verdict("recorded", "not_a_file")
    if not path or (sig is not None and sig.status == "missing"):
        return Verdict("needs", "no_file")
    p = norm_path(path)
    if name.lower() in WINDOWS_NAMES and not windows_home(p, env):
        return Verdict("needs", "windows_name_misplaced")
    status = sig.status if sig is not None else "unknown"
    if status == "unknown":
        return Verdict("needs", "unchecked")
    if status == "valid":
        return Verdict("recorded", "signed")
    # unsigned or invalid
    root = _dir(_root(env))
    if (_under(p, admin_dirs(env))
            and not (p.startswith(root)
                     and _under(p, writable_under_windows(env)[1:]))):
        return Verdict("recorded", "unsigned_admin")
    return Verdict("needs", "unsigned_writable")


# ---- Reading the world: the file's hash and signature -----------------------

def file_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, ValueError, TypeError):
        return None


# A constant script. The path comes off the machine (a process's image file,
# which can be named anything) so it travels only in NS_SIG_PATH, never in the
# script text: see DesktopNotifier.SCRIPT in netscope_alerts.py for why
# quoting a name into PowerShell is breakable (curly quotes count as quotes,
# and this process is usually elevated).
SIG_SCRIPT = (
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$s=Get-AuthenticodeSignature -LiteralPath $env:NS_SIG_PATH;"
    "$n='';"
    "if($s.SignerCertificate){$n=$s.SignerCertificate.GetNameInfo("
    "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,"
    "$false)};"
    "@{Status=[string]$s.Status;Signer=[string]$n}|ConvertTo-Json -Compress"
)


def powershell_exe(env=os.environ):
    """
    Windows PowerShell by full path. The process is usually elevated, so a
    bare "powershell" would be whatever comes first on PATH or in the
    working folder. "powershell" only when that file isn't there.
    """
    exe = os.path.join(_root(env), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    return exe if os.path.isfile(exe) else "powershell"


def powershell_signature(path, timeout):
    """The Authenticode status of `path`: a Sig. Never raises."""
    try:
        if not os.path.exists(path):
            return Sig("missing", "")
        env = dict(os.environ)
        env["NS_SIG_PATH"] = str(path)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        out = subprocess.run(
            [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command",
             SIG_SCRIPT],
            env=env, capture_output=True, timeout=timeout,
            creationflags=flags, stdin=subprocess.DEVNULL)
        if out.returncode != 0:
            return Sig("unknown", "")
        data = json.loads(out.stdout.decode("utf-8-sig", "replace"))
        status = str(data.get("Status", ""))
        signer = str(data.get("Signer", "") or "")
        if status == "Valid":
            return Sig("valid", signer)
        if status == "NotSigned":
            return Sig("unsigned", "")
        if not status:
            return Sig("unknown", "")
        return Sig("invalid", signer)
    except Exception:
        return Sig("unknown", "")


class SignatureChecker:
    """Signature lookups, cached by (path, size, mtime), capped in time."""

    def __init__(self, run=powershell_signature, cap=5.0):
        self.run = run
        self.cap = cap
        self._cache = {}
        self._lock = threading.Lock()

    def check(self, path):
        try:
            st = os.stat(path)
        except (OSError, ValueError, TypeError):
            return Sig("missing", "")
        key = (norm_path(path), st.st_size, st.st_mtime_ns)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        box = []

        def job():
            try:
                box.append(self.run(path, timeout=self.cap))
            except Exception:
                box.append(Sig("unknown", ""))

        t = threading.Thread(target=job, daemon=True, name="sig-check")
        t.start()
        t.join(self.cap)
        sig = box[0] if box else Sig("unknown", "")
        if not isinstance(sig, Sig):
            sig = Sig("unknown", "")
        if sig.status != "unknown":     # a later check may do better
            with self._lock:
                self._cache[key] = sig
        return sig


class TrustList:
    """Programs the user has said are fine, at the hash they were trusted at."""

    def __init__(self, entries=None):
        self._lock = threading.Lock()
        self._by_path = {}
        for e in entries or []:
            try:
                entry = {"name": e["name"], "path": e["path"],
                         "sha256": e["sha256"], "ts": e.get("ts", 0)}
                if e.get("changed"):
                    entry["changed"] = True
                self._by_path[norm_path(e["path"])] = entry
            except (KeyError, TypeError):
                continue

    def add(self, name, path, sha256, changed=False):
        """`changed`: the file was not the one the alert was about when it
        was trusted, so the Trusted list can say so."""
        entry = {"name": name, "path": path, "sha256": sha256,
                 "ts": time.time()}
        if changed:
            entry["changed"] = True
        with self._lock:
            self._by_path[norm_path(path)] = entry
        return dict(entry)

    def remove(self, path):
        with self._lock:
            return self._by_path.pop(norm_path(path), None) is not None

    def is_trusted(self, path, sha256):
        with self._lock:
            e = self._by_path.get(norm_path(path))
        return bool(e and sha256 and e["sha256"] == sha256)

    def entries(self):
        with self._lock:
            return [dict(e) for e in self._by_path.values()]


class ProgramJudge:
    """Looks a new program up (file, hash, signature) off the capture thread
    and hands the verdict to on_verdict(name, rec, info)."""

    def __init__(self, checker, trust, locate, on_verdict,
                 hash_file=file_sha256):
        self.checker = checker
        self.trust = trust
        self.locate = locate
        self.on_verdict = on_verdict
        self.hash_file = hash_file
        self.last_ts = None
        self._q = queue.Queue()
        self._thread = None

    def judge(self, name, pid, rec):
        try:
            path, parent = self.locate(name, pid)
            sha = self.hash_file(path) if path else None
        except Exception as e:
            # Never lose a new program: say it could not be checked.
            print(f"  Program judge: could not look up {name}: {e!r}",
                  file=sys.stderr)
            info = {"path": None, "parent": None, "sig": None,
                    "sha256": None, "verdict": Verdict("needs", "unchecked")}
            self.last_ts = time.time()
            self.on_verdict(name, rec, info)
            return info
        if path and sha and self.trust.is_trusted(path, sha):
            sig = None
            verdict = Verdict("recorded", "trusted")
        else:
            sig = self.checker.check(path) if path else None
            verdict = classify_program(name, path, sig)
        info = {"path": path, "parent": parent, "sig": sig,
                "sha256": sha, "verdict": verdict}
        self.last_ts = time.time()
        self.on_verdict(name, rec, info)
        return info

    def submit(self, name, pid, rec):
        self._q.put((name, pid, rec))

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="program-judge")
            self._thread.start()

    def _run(self):
        while True:
            name, pid, rec = self._q.get()
            try:
                self.judge(name, pid, rec)
            except Exception as e:
                print(f"  Program judge: verdict for {name} failed: {e!r}",
                      file=sys.stderr)
