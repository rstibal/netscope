import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, os, io, tempfile, contextlib, types
import unittest.mock as mock
import netscope_tray as T
import netscope as N

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

d = tempfile.mkdtemp()
console = os.path.join(d, "NetScope.exe")
tray_exe = os.path.join(d, "NetScopeTray.exe")
open(console, "w").close()

def frozen_as(path):
    return mock.patch.multiple(T.sys, frozen=True, executable=path, create=True)

# ---- tray_twin()
with frozen_as(console):
    p, ok = T.tray_twin()
check("twin missing -> exists False", p == tray_exe and ok is False, f"{p} {ok}")

open(tray_exe, "w").close()
with frozen_as(console):
    p, ok = T.tray_twin()
check("twin present -> exists True", p == tray_exe and ok is True, f"{p} {ok}")

with frozen_as(tray_exe):
    p, ok = T.tray_twin()
check("already the tray build -> itself", p == tray_exe and ok is True, f"{p} {ok}")

with mock.patch.object(T.sys, "frozen", False, create=True):
    p, ok = T.tray_twin()
check("running from source -> (None, False)", p is None and ok is False, f"{p} {ok}")

# ---- is_console_command()
cases = [
    (r'C:\ns\NetScope.exe --tray', True),
    (r'C:\ns\NetScopeTray.exe --tray', False),
    (r'C:\ns\netscopetray.exe --tray', False),
    ("", False), (None, False),
]
for cmd, want in cases:
    got = T.is_console_command(cmd)
    check(f"is_console_command({cmd!r}) == {want}", got == want, str(got))

# ---- the --install-task warning actually prints
def run_main(argv, twin_ret, install_ret=(True, r'C:\ns\NetScope.exe --tray'),
             status_ret=None):
    buf = io.StringIO()
    with mock.patch.object(N.tray, "tray_twin", return_value=twin_ret), \
         mock.patch.object(N.tray, "install_task", return_value=install_ret), \
         mock.patch.object(N.tray, "task_status", return_value=status_ret or {}), \
         mock.patch.object(N.tray, "autostart_status", return_value={"enabled": False}), \
         mock.patch.object(N.tray, "_exe_and_args", return_value=(r'C:\ns\NetScope.exe','--tray',r'C:\ns')), \
         contextlib.redirect_stdout(buf):
        try: N.main(argv)
        except SystemExit: pass
    return buf.getvalue()

out = run_main(["--install-task"], (tray_exe, False))
check("install warns when the twin is missing",
      "NOTE" in out and "console window will open at every logon" in out
      and "build.bat" in out, out[-260:])

out = run_main(["--install-task"], (tray_exe, True),
               install_ret=(True, r'C:\ns\NetScopeTray.exe --tray'))
check("install stays quiet when the twin was used", "NOTE" not in out, out[-200:])

out = run_main(["--install-task"], (None, False))
check("install stays quiet when running from source", "NOTE" not in out, out[-200:])

# ---- the --task-status note
st_console = {"supported": True, "exists": True, "command": r'C:\ns\NetScope.exe --tray',
              "state": "Ready", "run_as": "OPTIMUS\\rob", "last_run": "", "last_result": ""}
out = run_main(["--task-status"], (tray_exe, True), status_ret=st_console)
check("status flags a console task and says how to switch",
      "this is the console build" in out and "--install-task" in out, out[-300:])

out = run_main(["--task-status"], (tray_exe, False), status_ret=st_console)
check("status says to build the tray exe when it is absent",
      "is not there" in out and "build.bat" in out, out[-300:])

st_tray = dict(st_console, command=r'C:\ns\NetScopeTray.exe --tray')
out = run_main(["--task-status"], (tray_exe, True), status_ret=st_tray)
check("status stays quiet for a tray task", "console build" not in out, out[-250:])

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
