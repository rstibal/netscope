import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, socket, threading, time
from scapy.config import conf
conf.use_pcap = True
import netscope as N

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def load(port, rounds=400, size=20000):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind(("127.0.0.1", port)); srv.listen(64)
    stop = []
    def serve():
        while not stop:
            try:
                c,_ = srv.accept(); c.recv(65535); c.sendall(b"x"*size); c.close()
            except OSError: return
    threading.Thread(target=serve, daemon=True).start()
    blob = b"y"*size
    for _ in range(rounds):
        try:
            c = socket.create_connection(("127.0.0.1", port)); c.sendall(blob)
            c.recv(65535); c.close()
        except OSError: break
    stop.append(1); srv.close()

# --- without the stall, a modest load should be handled
eng = N.CaptureEngine(N.PacketStore(), N.ProcessResolver())
assert eng.start(iface="lo", bpf="tcp port 9951"), eng.error
check("stress is off by default", eng.stress_us == 0)
load(9951, rounds=120, size=8000)
time.sleep(1.0)
calm = eng.capture_stats()
eng.stop(); time.sleep(0.4)
print("      no stall:", calm)

# --- with the stall, the same shape of load must produce drops
eng2 = N.CaptureEngine(N.PacketStore(), N.ProcessResolver())
eng2.stress_us = 500
assert eng2.start(iface="lo", bpf="tcp port 9952"), eng2.error
load(9952, rounds=120, size=8000)
time.sleep(1.0)
stressed = eng2.capture_stats()
print("      500us stall:", stressed)
check("the stall makes the driver drop packets",
      stressed and stressed["dropped"] > 0, stressed)
check("the loss shows as a percentage above zero",
      stressed and stressed["loss_pct"] > 0, stressed)
check("it is markedly worse than the unstalled run",
      stressed["dropped"] > (calm["dropped"] if calm else 0), (calm, stressed))
eng2.stop(); time.sleep(0.4)
check("stopping a stalled capture does not crash", True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
