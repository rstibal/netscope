import os, sys, tempfile, unittest.mock as mock
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_tray as T

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

# ---- the task's command is found on a non-English Windows ---------------------
# schtasks /V translates its field names; the XML's element names are fixed.
GERMAN = ("Hostname:  PC\nTaskName:  \\NetScope\nStatus:  Bereit\n"
          "Auszuf\u00fchrende Aufgabe:  C:\\Tools\\NetScope.exe --tray\n")
XML = ('<?xml version="1.0" encoding="UTF-16"?><Task><Actions Context="Author"><Exec>'
       '<Command>C:\\Program Files\\NetScope\\NetScope.exe</Command>'
       '<Arguments>--tray &amp; more</Arguments></Exec></Actions></Task>')
calls = []
def fake_run(cmd):
    calls.append(cmd)
    return (0, XML if "/XML" in cmd else GERMAN)
with mock.patch.object(T, "_run", fake_run), mock.patch.object(T.os, "name", "nt"):
    st = T._task_status_uncached()
check("the command comes from the XML when the listing is translated",
      st["command"] == "C:\\Program Files\\NetScope\\NetScope.exe --tray & more", st["command"])
check("...so the console-build check still works",
      T.is_console_command(st["command"]) is True)

ENGLISH = "TaskName:  \\NetScope\nTask To Run:  C:\\X\\NetScopeTray.exe --tray\n"
calls.clear()
with mock.patch.object(T, "_run", lambda c: (calls.append(c) or (0, ENGLISH))), mock.patch.object(T.os, "name", "nt"):
    st = T._task_status_uncached()
check("an English listing is used as before, with no second call",
      st["command"] == "C:\\X\\NetScopeTray.exe --tray" and len(calls) == 1, (st, calls))
with mock.patch.object(T, "_run", lambda c: (1, "")), mock.patch.object(T.os, "name", "nt"):
    check("no task: nothing found", T._command_from_xml() == "")

# ---- the task definition is not left in a folder the user can write to -------
seen = {}
def fake_mkstemp(suffix="", dir=None):
    seen["dir"] = dir
    if dir and seen.get("deny"):
        raise PermissionError("denied")
    return 99, "x"
with mock.patch.dict(os.environ, {"SystemRoot": "C:\\Windows"}), mock.patch.object(tempfile, "mkstemp", fake_mkstemp):
    T._make_xml_file()
    check("the XML goes in the Windows temp folder, not the user's",
          seen["dir"] == os.path.join("C:\\Windows", "Temp"), seen)
    seen["deny"] = True
    got = T._make_xml_file()
    check("if that is refused it falls back to the default rather than failing",
          seen["dir"] is None and got == (99, "x"), seen)

# ---- a task that runs from a user-writable folder is reported -----------------
pf = os.path.abspath("C:\\Program Files")
env = {"ProgramFiles": pf, "SystemRoot": os.path.abspath("C:\\Windows")}
with mock.patch.dict(os.environ, env), mock.patch.object(T.sys, "frozen", True, create=True):
    with mock.patch.object(T.sys, "executable", os.path.join(pf, "NetScope", "NetScope.exe")):
        check("Program Files is fine", T.user_writable_task_paths() == [])
    userexe = os.path.abspath("C:\\Users\\Rob\\Downloads\\NetScope.exe")
    with mock.patch.object(T.sys, "executable", userexe):
        check("a folder under the user's profile is reported",
              T.user_writable_task_paths() == [userexe])
    sneaky = os.path.abspath("C:\\Program Files Evil\\NetScope.exe")
    with mock.patch.object(T.sys, "executable", sneaky):
        check("a lookalike folder name is not mistaken for Program Files",
              T.user_writable_task_paths() == [sneaky])
script = os.path.abspath("C:\\Users\\Rob\\netscope\\netscope.py")
with mock.patch.dict(os.environ, env), mock.patch.object(T.sys, "frozen", False, create=True):
    with mock.patch.object(T.sys, "executable", os.path.join(pf, "Python", "python.exe")), \
         mock.patch.object(T.sys, "argv", [script]):
        out = T.user_writable_task_paths()
        check("from source, the script counts even when python.exe is in Program Files",
              out == [script], out)

sys.exit(1 if fails else 0)
