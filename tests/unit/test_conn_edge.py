import os, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
from netscope_conn import FlowTable

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

def seg(seq, plen, ts=1000.0):
    return {"src": "10.0.0.2", "sport": 50000, "dst": "1.2.3.4", "dport": 443,
            "dir": "out", "length": plen + 54, "transport": "tcp", "ts": ts,
            "payload_len": plen, "decoded": {"tcp": {"flags": "A", "seq": seq, "ack": 1}}}

def only(ft):
    return next(iter(ft.snapshot().values()))

# ---- a flow crossing the 2**32 sequence wrap is not "resent" ---------------
ft = FlowTable()
top = 0xFFFFFFFF - 2000
seq = top
for _ in range(6):                       # 6 x 1000 bytes, wraps part-way
    ft.observe(seg(seq, 1000)); seq = (seq + 1000) & 0xFFFFFFFF
check("no false retransmits across the wrap", only(ft)["resent"] == 0, only(ft)["resent"])
ft.observe(seg(top, 1000))               # a genuine retransmit of old ground
check("a real retransmit is still counted", only(ft)["resent"] == 1, only(ft)["resent"])
ft.observe(seg((seq + 5000) & 0xFFFFFFFF, 100))   # a segment ahead (a gap)
check("a segment ahead is not a retransmit", only(ft)["resent"] == 1)

# ---- snapshot while the capture thread mutates ------------------------------
ft = FlowTable(max_flows=50)
stop = threading.Event()
def writer():
    i = 0
    while not stop.is_set():
        i += 1
        r = seg(1000, 10, ts=1000.0 + i)
        r["sport"] = 10000 + (i % 400)
        ft.observe(r)
t = threading.Thread(target=writer); t.start()
errs = 0
for _ in range(3000):
    try: ft.snapshot()
    except RuntimeError: errs += 1
stop.set(); t.join()
check("snapshot never raises under concurrent writes", errs == 0, errs)

sys.exit(1 if fails else 0)
