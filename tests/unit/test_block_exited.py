"""
Blocking from an alert works after the program has exited.

An alert's Block goes by name, and the program behind it has often exited by
the time anyone reads the alert (a check-in alert never had a pid at all).
Finding the file only among running processes refused those with "Can't tell
which ... you mean". The resolver now remembers where each program name was
seen running from, and the name lookup falls back to that.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N

if N.psutil is None:
    print("SKIP  test_block_exited.py needs psutil")
    sys.exit(0)

# ---- the resolver remembers paths as it names pids ----------------------------
class FakeProc:
    def __init__(self, pid): self.pid = pid
    def name(self): return {10: "Agent.exe", 11: "agent.exe", 12: "Tool.exe"}[self.pid]
    def exe(self): return {10: r"C:\Agent\Agent.exe", 11: r"C:\Agent\Agent.exe",
                           12: r"C:\Tool\Tool.exe"}[self.pid]

real_process, real_iter = N.psutil.Process, N.psutil.process_iter
N.psutil.Process = FakeProc
try:
    r = N.ProcessResolver()
    r.name_for_pid(10); r.name_for_pid(11); r.name_for_pid(12)
    check("a named pid's file is remembered, by name in any case",
          r.known_paths("AGENT.EXE") == {r"C:\Agent\Agent.exe"}, r.known_paths("agent.exe"))
    r.note_path("Tool.exe", r"D:\Other\Tool.exe")
    check("two different files under one name are both kept",
          len(r.known_paths("tool.exe")) == 2)

    # ---- the name lookup: running first, then what was seen ----------------------
    N.psutil.process_iter = lambda attrs=None: iter(())        # nothing running
    check("an exited program is found by the file it was seen running from",
          N._exe_of_name("Agent.exe", r.known_paths("Agent.exe")) == r"C:\Agent\Agent.exe")
    check("...but not when two different files had that name",
          N._exe_of_name("Tool.exe", r.known_paths("Tool.exe")) == "")
    check("...nor a name never seen", N._exe_of_name("Never.exe", r.known_paths("Never.exe")) == "")

    class Running:
        def __init__(self, name, exe): self.info = {"name": name, "exe": exe}
    N.psutil.process_iter = lambda attrs=None: iter([Running("Agent.exe", r"E:\New\Agent.exe")])
    check("a running process still wins over what was seen earlier",
          N._exe_of_name("Agent.exe", r.known_paths("Agent.exe")) == r"E:\New\Agent.exe")

    # ---- end to end through the Blocker the real app builds -----------------------
    N.psutil.process_iter = lambda attrs=None: iter(())
    st = {"blocking_enabled": True}
    b = N.Blocker(lambda: st, st.__setitem__, drop=lambda e: 0, run=lambda cmd: (0, ""), available=lambda: True,
                  program_path=lambda pid: "",
                  name_path=lambda n: N._exe_of_name(n, r.known_paths(n)))
    e = b.block_program(pid=None, name="Agent.exe")
    check("Block from an alert about an exited program adds the rule",
          e["target"] == r"C:\Agent\Agent.exe", e)
finally:
    N.psutil.Process, N.psutil.process_iter = real_process, real_iter

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
