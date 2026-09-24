"""
Capture-engine state that outlives a single packet.

- An imported .pcap is kept out of the persistent history and is never
  attributed to processes through this machine's live socket table.
- Clear resets the connection table, not just the packet list.
- capture_stats() never reads a pcap handle that has been closed.
- With history switched off, the "new program" rule still works.
"""

import os, sys, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N
import netscope_alerts as A


class FakeResolver:
    """Claims every packet for a live process, as the real one would if the
    ports happened to match a socket open right now."""
    def __init__(self):
        self.misses = 0
    def lookup(self, sport, dport, proto, src, dst):
        return "chrome.exe", 4242, "out"
    def note_miss(self):
        self.misses += 1
        return False
    def name_for_pid(self, pid):
        return "chrome.exe"


class FakeHistory:
    enabled = True
    def __init__(self):
        self.recorded = []
    def record(self, rec):
        self.recorded.append(rec)


def engine():
    store = N.PacketStore()
    hist = FakeHistory()
    eng = N.CaptureEngine(store, FakeResolver(), history=hist)
    return eng, store, hist


if N.SCAPY_OK:
    from scapy.all import Ether, IP, TCP, Raw

    def pkt(i):
        # Explicit MACs: a bare Ether() makes scapy ARP for the gateway.
        p = (Ether(src="aa:bb:cc:00:11:22", dst="aa:bb:cc:99:88:77") /
             IP(src="192.168.1.20", dst="203.0.113.5") /
             TCP(sport=50000 + i, dport=443, flags="PA") / Raw(b"x" * 10))
        p.time = 1_700_000_000.0 + i
        return p

    # ---- 1. A live packet is recorded and attributed, as before.
    eng, store, hist = engine()
    eng._on_packet(pkt(0), "eth0")
    live = store.since(0)
    check("live packet is written to history", len(hist.recorded) == 1)
    check("live packet is attributed through the socket table",
          live and live[0]["process"] == "chrome.exe", str(live and live[0]["process"]))

    # ---- 2. An imported one is neither.
    eng, store, hist = engine()
    n = eng.ingest_file([pkt(i) for i in range(5)])
    got = store.since(0)
    check("imported packets are all decoded", n == 5 and len(got) == 5, f"{n} {len(got)}")
    check("imported packets are not written to history", hist.recorded == [],
          str(len(hist.recorded)))
    check("imported packets are not attributed to a live process",
          all(r["process"] != "chrome.exe" for r in got),
          str({r["process"] for r in got}))
    check("imported packets keep their direction", all(r["dir"] == "out" for r in got))
    check("the socket table is not refreshed for an import", eng.resolver.misses == 0)

    # ---- 3. Offline mode ends with the import, even if a packet raised.
    check("offline flag is off again after the import", eng._offline is False)
    eng._on_packet(pkt(9), "eth0")
    check("a live packet after an import is recorded again", len(hist.recorded) == 1)

    # ---- 4. Clear resets the Connections tab's flows too.
    eng, store, hist = engine()
    for i in range(3):
        eng._on_packet(pkt(i), "eth0")
    check("flows exist before Clear", len(store.flows.snapshot()) == 3)
    store.clear()
    check("Clear empties the flow table", store.flows.snapshot() == {},
          str(len(store.flows.snapshot())))
else:
    print("SKIP  import/Clear checks need scapy to build packets")


# ---- 5. capture_stats() never reads a closed handle ---------------------------

class FakeSock:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

class FakeSniffer:
    thread = None

reads = []
real_stats = N.pcap_stats_for
N.pcap_stats_for = lambda sock: (reads.append(sock) or
                                 (_ for _ in ()).throw(AssertionError("read closed"))
                                 if sock.closed else (100, 1, 0))
try:
    eng, store, hist = engine()
    open_sock, shut_sock = FakeSock(), FakeSock()
    shut_sock.close()
    eng.sniffers = [("a", FakeSniffer(), open_sock), ("b", FakeSniffer(), shut_sock)]
    st = eng.capture_stats()
    check("a closed socket is skipped, the open one still counted",
          st is not None and st["received"] == 100 and shut_sock not in reads, str(st))

    # Closing waits for any read in progress: hold the handle lock and the
    # closer must not get through until it is released.
    eng, store, hist = engine()
    s = FakeSock()
    eng._handle_lock.acquire()
    t = threading.Thread(target=eng._close_sockets, args=([("a", FakeSniffer(), s)],))
    t.start()
    time.sleep(0.2)
    check("close waits while a stats read holds the handle", s.closed is False)
    eng._handle_lock.release()
    t.join(2)
    check("...and closes once it is released", s.closed is True)
finally:
    N.pcap_stats_for = real_stats


# ---- 6. --no-history: the new-program rule still fires ------------------------
#
# A switched-off HistoryStore knew no programs, so every program looked
# never-seen, and its empty database looked like a first run — the rule sat
# in baseline mode, recording quietly, and never fired at all.
off = N.HistoryStore(enabled=False)
e = A.AlertEngine(history=off)
e._dns_read = A._now()
e.warmup_until = 0
e._change_rules({"process": "curl.exe", "remote": "203.0.113.5", "length": 60})
check("with history off, a program's first packet this session alerts",
      [a["title"] for a in e.list()] == ["Program started using the network"],
      str([a["title"] for a in e.list()]))
check("...and a disabled history is treated as none", e.history is None and not e.baselining)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
