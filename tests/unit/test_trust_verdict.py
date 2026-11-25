import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_trust as T
from netscope_trust import Sig

ENV = {"ProgramFiles": r"C:\Program Files",
       "ProgramFiles(x86)": r"C:\Program Files (x86)",
       "ProgramW6432": r"C:\Program Files",
       "SystemRoot": r"C:\Windows"}

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + extra) if extra and not cond else ""))
    if not cond: fails.append(name)

def v(name, path, sig, env=ENV):
    r = T.classify_program(name, path, sig, env)
    return (r.pile, r.reason)

VALID = Sig("valid", "Somebody")
UNSIGNED = Sig("unsigned", "")

# ---- Not a file / no file
check("System is not a file",
      v("System", r"C:\Windows\System32\x.exe", VALID) == ("recorded", "not_a_file"))
check("no path -> needs no_file", v("x.exe", None, None) == ("needs", "no_file"))
check("missing sig -> needs no_file",
      v("x.exe", r"C:\x\x.exe", Sig("missing", "")) == ("needs", "no_file"))

# ---- Windows names
check("svchost in AppData is misplaced",
      v("svchost.exe", r"C:\Users\Alice\AppData\Roaming\svchost.exe",
        Sig("valid", "Microsoft Windows")) == ("needs", "windows_name_misplaced"))
check("svchost in System32 is signed",
      v("svchost.exe", r"C:\Windows\System32\svchost.exe",
        Sig("valid", "Microsoft Windows")) == ("recorded", "signed"))
check("windows name case-insensitive",
      v("SvcHost.EXE", r"C:\Users\x\svchost.exe", VALID) == ("needs", "windows_name_misplaced"))

check("explorer in the Windows folder itself is in place",
      v("explorer.exe", r"C:\Windows\explorer.exe", VALID) == ("recorded", "signed"))
check("explorer in Windows\\Temp is misplaced",
      v("explorer.exe", r"C:\Windows\Temp\explorer.exe", VALID)
      == ("needs", "windows_name_misplaced"))
check("svchost in SysWOW64 is in place",
      v("svchost.exe", r"C:\Windows\SysWOW64\svchost.exe", VALID) == ("recorded", "signed"))
# Folders under System32/SysWOW64 that a user can write to are no home.
for where in (r"C:\Windows\System32\Tasks\svchost.exe",
              r"C:\Windows\System32\spool\drivers\svchost.exe",
              r"C:\Windows\SysWOW64\Tasks\svchost.exe"):
    check("svchost at " + where + " is misplaced",
          v("svchost.exe", where, VALID) == ("needs", "windows_name_misplaced"))
check("windows_home: System32 yes, System32\\Tasks no, the Windows folder yes",
      T.windows_home(r"C:\Windows\System32\svchost.exe", ENV)
      and not T.windows_home(r"C:\Windows\System32\Tasks\svchost.exe", ENV)
      and T.windows_home(r"C:\Windows\explorer.exe", ENV)
      and not T.windows_home(r"C:\Users\Alice\AppData\Roaming\svchost.exe", ENV))

# ---- Unknown
check("unknown sig -> unchecked",
      v("a.exe", r"C:\Program Files\a\a.exe", Sig("unknown", "")) == ("needs", "unchecked"))

# ---- Typical cases
check("vendor service valid -> signed",
      v("vendorsvc.exe",
        r"C:\Program Files\Vendor Corporation\Service\vendorsvc.exe",
        Sig("valid", "Vendor")) == ("recorded", "signed"))
check("updater in the user's folder valid -> signed",
      v("tool-1.2.3-win32-x64.exe",
        r"C:\Users\Alice\.tool\downloads\tool-1.2.3-win32-x64.exe",
        VALID) == ("recorded", "signed"))
check("setup bootstrapper in Temp valid -> signed",
      v("setup_bootstrapper.exe",
        r"C:\Users\Alice\AppData\Local\Temp\x\setup_bootstrapper.exe",
        VALID) == ("recorded", "signed"))
check("curl unsigned in Program Files",
      v("curl.exe", r"C:\Program Files\Git\mingw64\bin\curl.exe", UNSIGNED)
      == ("recorded", "unsigned_admin"))
check("GetHelp unsigned in WindowsApps",
      v("GetHelp.exe",
        r"C:\Program Files\WindowsApps\Microsoft.GetHelp_1.0_x64__8wekyb3d8bbwe\GetHelp.exe",
        UNSIGNED) == ("recorded", "unsigned_admin"))
check("an unsigned tool in AppData",
      v("tool.exe", r"C:\Users\Alice\AppData\Local\Tool\bin\tool.exe", UNSIGNED)
      == ("needs", "unsigned_writable"))
check("an unsigned game installed to another drive",
      v("Some Game.exe", r"E:\Games\SomeGame\Some Game.exe", UNSIGNED)
      == ("needs", "unsigned_writable"))
check("unsigned in Windows\\Temp is writable",
      v("setup.exe", r"C:\Windows\Temp\abc\setup.exe", UNSIGNED)
      == ("needs", "unsigned_writable"))

# ---- Invalid is unsigned
check("invalid treated as unsigned (admin)",
      v("a.exe", r"C:\Program Files\Foo\a.exe", Sig("invalid", "Bad Co"))
      == ("recorded", "unsigned_admin"))
check("invalid treated as unsigned (writable)",
      v("a.exe", r"C:\Users\Alice\a.exe", Sig("invalid", "Bad Co"))
      == ("needs", "unsigned_writable"))

# ---- Odd paths
check("forward slashes and case",
      v("a.exe", "C:/PROGRAM FILES/Foo/a.exe", UNSIGNED) == ("recorded", "unsigned_admin"))
check("\\\\?\\ prefix",
      v("a.exe", "\\\\?\\C:\\Program Files\\Foo\\a.exe", UNSIGNED)
      == ("recorded", "unsigned_admin"))
check("other drive Program Files is writable",
      v("a.exe", r"D:\Program Files\Foo\a.exe", UNSIGNED) == ("needs", "unsigned_writable"))
check("prefix stops at folder boundary",
      v("a.exe", r"C:\Program FilesX\a.exe", UNSIGNED) == ("needs", "unsigned_writable"))

# ---- Helpers and env handling
check("norm_path", T.norm_path("\\\\?\\C:/Foo\\Bar") == "c:\\foo\\bar")
lenv = {k.lower(): val for k, val in ENV.items()}
check("env names case-insensitive",
      v("a.exe", r"C:\Program Files\Foo\a.exe", UNSIGNED, lenv) == ("recorded", "unsigned_admin"))
check("missing x86 var leaves no empty prefix",
      all(d.strip("\\") for d in T.admin_dirs({"SystemRoot": r"C:\Windows"})))
check("empty env: nothing matches everything",
      v("a.exe", r"C:\Users\Alice\a.exe", UNSIGNED, {}) == ("needs", "unsigned_writable"))
check("admin_dirs trailing backslash",
      all(d.endswith("\\") for d in T.admin_dirs(ENV)))
check("system_dirs",
      T.system_dirs(ENV) == ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                             "c:\\windows\\winsxs\\"], str(T.system_dirs(ENV)))
check("writable_under_windows has Temp and root-spool",
      "c:\\windows\\temp\\" in T.writable_under_windows(ENV)
      and "c:\\windows\\system32\\spool\\" in T.writable_under_windows(ENV))
check("WINDOWS_NAMES", len(T.WINDOWS_NAMES) == 22 and "svchost.exe" in T.WINDOWS_NAMES)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
