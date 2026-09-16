# -*- coding: utf-8 -*-
"""
Tray mode and start-on-login — what turns NetScope from a tool you open into
something that just runs.

The tray icon is drawn at runtime rather than shipped as a file, so there is
no asset to bundle and the icon can reflect state: it turns amber when a
warning-level alert is outstanding and red for a high-severity one. Bar count
also reflects current throughput, signal-strength style.

Autostart is a single HKCU Run entry. Per-user, no elevation, and removable
from inside the app — nothing is written anywhere else and nothing is
installed as a service.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import webbrowser

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "NetScope"
TASK_NAME = "NetScope"

# Imported separately: pystray picks a GUI backend at import time and can fail
# where Pillow is perfectly fine (a headless Linux box, for instance). Keeping
# them apart means a missing tray backend doesn't also cost us icon drawing.
try:
    from PIL import Image, ImageDraw
    PIL_OK = True
except Exception as exc:  # pragma: no cover
    PIL_OK = False
    PIL_ERROR = str(exc)

try:
    import pystray
    if not PIL_OK:
        raise ImportError(PIL_ERROR)
    TRAY_OK = True
    TRAY_ERROR = None
except Exception as exc:  # pragma: no cover
    TRAY_OK = False
    TRAY_ERROR = str(exc)


# ---------------------------------------------------------------------------
# Console window
# ---------------------------------------------------------------------------


def owns_console():
    """
    Is the attached console ours, or did we inherit somebody's terminal?

    GetConsoleWindow() returns whatever console this process is attached to.
    Launched from an existing PowerShell or cmd prompt, that is the user's own
    window — hiding it would make their shell vanish. GetConsoleProcessList
    reporting a single attached process means the console was created for us
    and is ours to hide.
    """
    if os.name != "nt":
        return False
    try:
        arr = (ctypes.c_uint * 4)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(arr, 4)
        return n == 1
    except Exception:
        return False


def hide_console():
    """Tuck our own console away in tray mode; never someone else's."""
    if os.name != "nt":
        return False
    if not owns_console():
        return False
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)   # SW_HIDE
            return True
    except Exception:
        pass
    return False


def show_console():
    if os.name != "nt":
        return False
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 5)   # SW_SHOW
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Start on login
# ---------------------------------------------------------------------------


def _launch_command(extra_args=("--tray",)):
    if getattr(sys, "frozen", False):
        base = f'"{sys.executable}"'
    else:
        base = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'
    return base + "".join(" " + a for a in extra_args)


def autostart_status():
    if os.name != "nt":
        return {"supported": False, "enabled": False, "command": ""}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            value, _ = winreg.QueryValueEx(k, RUN_VALUE)
            return {"supported": True, "enabled": True, "command": value}
    except FileNotFoundError:
        return {"supported": True, "enabled": False, "command": ""}
    except Exception as exc:
        return {"supported": True, "enabled": False, "command": "",
                "error": str(exc)}


def enable_autostart(extra_args=("--tray",)):
    if os.name != "nt":
        return False, "Windows only"
    try:
        import winreg
        cmd = _launch_command(extra_args)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, cmd)
        return True, cmd
    except Exception as exc:
        return False, str(exc)


def disable_autostart():
    if os.name != "nt":
        return False, "Windows only"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_VALUE)
        return True, ""
    except FileNotFoundError:
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Start on login, the way an elevated program actually has to do it
#
# NetScope's manifest requests administrator, and Windows will not silently
# elevate anything launched from the Run key — you get a UAC consent prompt at
# every logon, or nothing starts at all. A scheduled task registered with
# HighestAvailable is the supported route: it launches with a full token and no
# prompt. The task is written from XML rather than schtasks flags so the
# execution time limit can be removed (the flag form defaults to killing the
# task after 72 hours) and the battery rules disabled.
# ---------------------------------------------------------------------------

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>{user}</Author>
    <Description>Starts NetScope in the notification area at logon.</Description>
    <URI>\\{task}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
      <Delay>PT20S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _current_user():
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain and user else (user or "")


def tray_twin():
    """
    (path, exists) for the no-console build that should own a logon start.

    _exe_and_args() falls back to the console build without comment when the
    twin is missing, which registers a task that pops a console window at every
    logon and gives no hint why. This lets the caller say so. Returns
    (None, False) when running from source, where there is no twin to look for.
    """
    if not getattr(sys, "frozen", False):
        return None, False
    exe = sys.executable
    if os.path.basename(exe).lower() == "netscopetray.exe":
        return exe, True
    twin = os.path.join(os.path.dirname(exe), "NetScopeTray.exe")
    return twin, os.path.exists(twin)


def is_console_command(cmd):
    """True when a registered task command is the console build."""
    return bool(cmd) and "netscopetray.exe" not in str(cmd).lower()


def _exe_and_args(extra_args=("--tray",)):
    """
    (command, arguments, workdir) for the task action.

    Prefers NetScopeTray.exe when it is sitting next to us: it is built for the
    windows subsystem, so a logon launch never flashes a console.
    """
    if getattr(sys, "frozen", False):
        exe = sys.executable
        twin = os.path.join(os.path.dirname(exe), "NetScopeTray.exe")
        if os.path.basename(exe).lower() != "netscopetray.exe" and os.path.exists(twin):
            exe = twin
        args = list(extra_args)
    else:
        exe = sys.executable
        args = [os.path.abspath(sys.argv[0])] + list(extra_args)
    workdir = os.path.dirname(exe if getattr(sys, "frozen", False)
                              else os.path.abspath(sys.argv[0]))
    return exe, " ".join(f'"{a}"' if " " in a else a for a in args), workdir


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd):
    import subprocess
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("utf-8", "replace") + \
              (p.stderr or b"").decode("utf-8", "replace")
        return p.returncode, out.strip()
    except Exception as exc:
        return -1, str(exc)


_status_cache = {"at": 0.0, "value": None}
_STATUS_TTL = 30.0


def task_status(max_age=_STATUS_TTL):
    """
    Is the logon task registered, and what does it run?

    Cached: this shells out to schtasks, and the dashboard asks for status
    several times a second.
    """
    import time
    if (_status_cache["value"] is not None
            and time.time() - _status_cache["at"] < max_age):
        return _status_cache["value"]
    value = _task_status_uncached()
    _status_cache.update(at=time.time(), value=value)
    return value


def _task_status_uncached():
    if os.name != "nt":
        return {"supported": False, "exists": False, "command": ""}
    code, out = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"])
    if code != 0:
        return {"supported": True, "exists": False, "command": ""}
    info = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip().lower()] = v.strip()
    return {
        "supported": True,
        "exists": True,
        "command": info.get("task to run", ""),
        "state": info.get("scheduled task state", info.get("status", "")),
        "last_run": info.get("last run time", ""),
        "last_result": info.get("last result", ""),
        "run_as": info.get("run as user", ""),
    }


def install_task(extra_args=("--tray",)):
    """Register the logon task. Needs an elevated process."""
    import tempfile
    from xml.sax.saxutils import escape

    if os.name != "nt":
        return False, "Windows only"
    if not _is_admin():
        return False, ("creating a task that runs with highest privileges "
                       "needs an elevated prompt — right-click Command Prompt "
                       "and choose 'Run as administrator', then run this again")

    exe, args, workdir = _exe_and_args(extra_args)
    user = _current_user()
    if not user:
        return False, "could not determine the current user"

    xml = TASK_XML.format(task=escape(TASK_NAME), user=escape(user),
                          command=escape(exe), arguments=escape(args),
                          workdir=escape(workdir))
    path = None
    try:
        # schtasks /XML insists on UTF-16.
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "wb") as fh:
            fh.write(xml.encode("utf-16"))
        code, out = _run(["schtasks", "/Create", "/TN", TASK_NAME,
                          "/XML", path, "/F"])
        if code != 0:
            return False, out or f"schtasks exited {code}"
        _status_cache["value"] = None          # force a re-read
        return True, f'{exe} {args}'
    except Exception as exc:
        return False, str(exc)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def remove_task():
    if os.name != "nt":
        return False, "Windows only"
    code, out = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    _status_cache["value"] = None
    if code != 0 and "cannot find" not in out.lower():
        if not _is_admin():
            return False, "deleting the task needs an elevated prompt"
        return False, out or f"schtasks exited {code}"
    return True, ""


def run_task_now():
    if os.name != "nt":
        return False, "Windows only"
    code, out = _run(["schtasks", "/Run", "/TN", TASK_NAME])
    return code == 0, out


# ---------------------------------------------------------------------------
# The icon
# ---------------------------------------------------------------------------

PALETTE = {
    "idle":  ((22, 27, 34), (77, 163, 255)),
    "warn":  ((36, 28, 12), (227, 179, 65)),
    "high":  ((44, 18, 18), (248, 81, 73)),
    "off":   ((22, 27, 34), (110, 118, 129)),
}


# Bar heights as a fraction of the tile, shortest to tallest.
BAR_HEIGHT_FRACS = (0.28, 0.46, 0.64, 0.82)
DIM_BAR = (255, 255, 255, 36)

# Upper bound of bytes/sec for each bar level (signal-strength style, log
# scaled so typical browsing sits at 1-2 bars and a real download maxes it
# out). A rate at or above the last threshold lights all bars.
RATE_THRESHOLDS = (10_000, 100_000, 1_000_000, 10_000_000)


def rate_to_level(bps):
    """Map a bytes/sec rate to a 0-4 lit-bar count."""
    level = 0
    for threshold in RATE_THRESHOLDS:
        if bps >= threshold:
            level += 1
    return level


def make_icon(state="idle", level=0, size=64):
    """Signal-strength bars on a rounded tile, tinted by alert state and
    lit up to `level` (0-4) by current throughput."""
    if not PIL_OK:
        return None
    bg, fg = PALETTE.get(state, PALETTE["idle"])
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([1, 1, size - 2, size - 2], radius=size // 5,
                        fill=bg + (255,))
    n = len(BAR_HEIGHT_FRACS)
    bar_w = size * 0.12
    gap = size * 0.08
    total_w = n * bar_w + (n - 1) * gap
    start_x = (size - total_w) / 2
    base_y = size * 0.84
    for i, frac in enumerate(BAR_HEIGHT_FRACS):
        h = size * frac
        x0 = start_x + i * (bar_w + gap)
        x1 = x0 + bar_w
        y0 = base_y - h
        y1 = base_y
        color = fg + (255,) if i < level else DIM_BAR
        d.rounded_rectangle([x0, y0, x1, y1], radius=bar_w * 0.3, fill=color)
    return img


class Tray:
    """Wraps pystray so the rest of the app does not care whether it loaded."""

    def __init__(self, url, on_quit, on_toggle=None, status_fn=None):
        self.url = url
        self.on_quit = on_quit
        self.on_toggle = on_toggle
        self.status_fn = status_fn or (lambda: {})
        self.icon = None
        self.state = "idle"
        self.level = 0
        self._stop = threading.Event()

    # -- menu actions -------------------------------------------------------

    def _open(self, *_):
        webbrowser.open(self.url)

    def _toggle(self, *_):
        if self.on_toggle:
            self.on_toggle()

    def _console(self, *_):
        show_console()

    def _quit(self, *_):
        self._stop.set()
        if self.icon:
            self.icon.visible = False
            self.icon.stop()
        self.on_quit()

    def _title(self, s=None):
        # s is passed in by _refresh(), which already paid for one call to
        # status_fn() this tick. status_fn()'s rate is a stateful delta since
        # the *previous* call, so calling it again here would immediately
        # see ~0 bytes and ~0 elapsed time and report 0 B/s forever.
        if s is None:
            s = self.status_fn() or {}
        bits = ["NetScope"]
        if s.get("rate"):
            bits.append(s["rate"])
        if s.get("packets"):
            bits.append(f"{s['packets']:,} packets")
        a = s.get("alerts") or {}
        if a.get("high"):
            bits.append(f"{a['high']} high alerts")
        elif a.get("total"):
            bits.append(f"{a['total']} alerts")
        if not s.get("running", True):
            bits.append("paused")
        return "  ·  ".join(bits)

    # -- lifecycle ----------------------------------------------------------

    def run(self):
        """Blocks on the tray event loop. Must be called from the main thread."""
        if not TRAY_OK:
            return False
        menu = pystray.Menu(
            pystray.MenuItem("Open dashboard", self._open, default=True),
            pystray.MenuItem("Pause / resume capture", self._toggle),
            pystray.MenuItem("Show console", self._console),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )
        self.icon = pystray.Icon("netscope", make_icon("idle"), "NetScope", menu)
        threading.Thread(target=self._refresh, daemon=True,
                         name="tray-refresh").start()
        self.icon.run()
        return True

    def _refresh(self):
        while not self._stop.wait(4.0):
            try:
                s = self.status_fn() or {}
                a = s.get("alerts") or {}
                state = ("off" if not s.get("running", True)
                         else "high" if a.get("high")
                         else "warn" if a.get("warn") else "idle")
                level = rate_to_level(s.get("rate_bps", 0))
                if self.icon:
                    self.icon.title = self._title(s)
                    if state != self.state or level != self.level:
                        self.state = state
                        self.level = level
                        self.icon.icon = make_icon(state, level)
            except Exception:
                pass
