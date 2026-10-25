"""
Program paths kept across restarts (only with history on), and the DNS
answers a name block follows (only live ones, never an imported .pcap's).
"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N
from netscope_history import HistoryStore

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

tmp = tempfile.mkdtemp()
exe = os.path.join(tmp, "Agent.exe")
open(exe, "w").close()
db = os.path.join(tmp, "h.db")

# -- history keeps paths ---------------------------------------------------------
h = HistoryStore(path=db)
h.note_path("Agent.exe", exe)
h.note_path("Agent.exe", exe)
check("a path is kept under the name, case-insensitively", h.known_paths("agent.exe") == {exe})
h._db.close()
h2 = HistoryStore(path=db)
check("...and is still there after a restart", h2.known_paths("Agent.exe") == {exe})
check("_saved_paths drops a file that no longer exists",
      N._saved_paths(h2, "Agent.exe") == {exe} and
      (h2.note_path("Agent.exe", os.path.join(tmp, "gone.exe")) or True) and
      N._saved_paths(h2, "Agent.exe") == {exe})
h2.wipe()
check("erasing history erases them", h2.known_paths("Agent.exe") == set())
h2._db.close()

off = HistoryStore(path=os.path.join(tmp, "off.db"), enabled=False)
off.note_path("Agent.exe", exe)
check("with history off nothing is kept", off.known_paths("Agent.exe") == set()
      and not os.path.exists(os.path.join(tmp, "off.db")))

# -- the resolver hands new pairs on, once ---------------------------------------
r = N.ProcessResolver.__new__(N.ProcessResolver)
import threading
r._lock, r._paths, r.on_path = threading.Lock(), {}, None
r.note_path("Agent.exe", exe)
got = []
r.on_path = lambda n, p: got.append((n, p))
r.note_path("Agent.exe", exe)
r.note_path("Other.exe", exe + "2")
check("only a pair new this session is handed on", got == [("Other.exe", exe + "2")], got)
check("...and the ones from before it was attached can be listed",
      sorted(r.all_paths()) == sorted([("agent.exe", exe), ("other.exe", exe + "2")]))

# -- the blocker's name lookup falls back to history -------------------------------
h3 = HistoryStore(path=os.path.join(tmp, "h3.db"))
h3.note_path("Agent.exe", exe)
r3 = N.ProcessResolver.__new__(N.ProcessResolver)
r3._lock, r3._paths, r3.on_path, r3._local_ips = threading.Lock(), {}, None, set()
real_iter = N.psutil.process_iter if N.psutil else None
try:
    if N.psutil:
        N.psutil.process_iter = lambda attrs=None: iter(())
    b = N.make_blocker(r3, history=h3)
    path = b._name_path("Agent.exe")
    check("a program not seen this session is found from history",
          path == (exe if N.psutil else ""), path)
finally:
    if N.psutil:
        N.psutil.process_iter = real_iter

# -- live DNS answers reach the listener, a file's don't ----------------------------
store = N.PacketStore()
heard = []
store.dns_listener = heard.append
ans = [{"name": "t.example.com.", "type": "A", "data": "198.51.100.7"}]
store.note_dns(ans)
check("a live answer is passed on", heard == [ans])
store.note_dns([{"name": "t.example.com", "type": "A", "data": "198.51.100.8"}], live=False)
check("an imported one is not", len(heard) == 1)
check("...but both still name their address",
      sorted(store.addresses_of("T.example.com")) == ["198.51.100.7", "198.51.100.8"])

print(); print("FAILED:", fails or "none")
sys.exit(1 if fails else 0)
