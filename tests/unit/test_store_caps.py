import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


def rec(proc, remote, size):
    return {"length": size, "dir": "in", "process": proc, "remote": remote,
            "proto": "TCP", "ts": 1000.0, "src": remote, "dst": "10.0.0.2"}


s = N.PacketStore()
s.MAX_HOSTS = 100
s.add(rec("big.exe", "203.0.113.1", 1_000_000), b"")
for i in range(250):
    s.add(rec("a.exe", "198.51.100.%d" % i, 10 + i), b"")
check("hosts stay near the cap", len(s.by_host) <= 100)
check("the busiest host survives", "203.0.113.1" in s.by_host)
check("eviction is counted", s.evicted["hosts"] > 0)
check("totals are unaffected by eviction", s.total_packets == 251)
check("stats top host is still the busiest",
      s.stats()["hosts"][0]["host"] == "203.0.113.1")

s = N.PacketStore()
s.MAX_PROCESSES = 20
for i in range(60):
    s.add(rec("p%d.exe" % i, "203.0.113.5", 100 + i), b"")
check("processes capped", len(s.by_process) <= 20 and s.evicted["processes"] > 0)

s = N.PacketStore()
s.MAX_NAMES = 5
for i in range(8):
    s.note_host("192.0.2.%d" % i, "h%d" % i)
check("name cache capped, oldest dropped",
      len(s.dns_cache) == 5 and "192.0.2.0" not in s.dns_cache
      and "192.0.2.7" in s.dns_cache and s.evicted["names"] == 3)
s.note_host("192.0.2.7", "other")
check("note_host does not overwrite", s.dns_cache["192.0.2.7"] == "h7")
s.note_dns([{"type": "A", "data": "192.0.2.7", "name": "dns"}])
check("DNS answers do overwrite", s.dns_cache["192.0.2.7"] == "dns")
s.clear()
check("clear resets the counters", not any(s.evicted.values()))

sys.exit(1 if fails else 0)
