import os, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_history as H

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

h = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-vpn-"), "h.db"))
now = time.time()
def pkt(proc, n, out=True):
    return {"process": proc, "rhost": "", "remote": "1.2.3.4", "length": n,
            "dir": "out" if out else "in", "ts": now}
for _ in range(10):
    h.record(pkt("chrome.exe", 1000))
    h.record(pkt("openvpn.exe", 1100))
    h.record(pkt("NordVPN.exe", 500, out=False))
    h.record(pkt("-", 100))
h.flush()

def usage(proc):
    return h._db.execute("SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM usage WHERE process=?",
                         (proc,)).fetchone()[0]

d = h.purge_vpn(dry=True)
check("a dry run lists the VPN programs with their size",
      d["programs"] == {"openvpn.exe": 11000, "NordVPN.exe": 5000}, d)
check("...and changes nothing", usage("openvpn.exe") == 11000 and usage("chrome.exe") == 10000)

d = h.purge_vpn()
check("the real run erases them", usage("openvpn.exe") == 0 and usage("NordVPN.exe") == 0 and d["usage"] >= 2, d)
check("real programs and unattributed traffic stay", usage("chrome.exe") == 10000 and usage("-") == 1000)
check("the program's name is kept, so it is not 'new' again",
      h.known_process("openvpn.exe"))
check("a second run finds nothing", h.purge_vpn()["programs"] == {})

off = H.HistoryStore(path=os.path.join(tempfile.mkdtemp(prefix="ns-vpn-"), "h.db"), enabled=False)
check("disabled history is a no-op", off.purge_vpn() == {"programs": {}, "usage": 0})
sys.exit(1 if fails else 0)
