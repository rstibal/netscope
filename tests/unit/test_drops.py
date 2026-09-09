import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, os, socket, threading, time
from scapy.config import conf
conf.use_pcap = True
import netscope as N

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

# ---- the reader itself degrades quietly on things that cannot report
class Bare: pass
check("a socket with no pcap handle reports nothing",
      N.pcap_stats_for(Bare()) is None)
class Fake:
    class pcap_fd: pcap = None
check("a wrapper with a null handle reports nothing",
      N.pcap_stats_for(Fake()) is None)

# ---- a real capture through the real engine
store = N.PacketStore()
res = N.ProcessResolver()
eng = N.CaptureEngine(store, res)
ok = eng.start(iface="lo", bpf="tcp port 9944")
check("engine started on loopback", ok, eng.error)
check("the engine kept its socket", eng.sniffers and eng.sniffers[0][2] is not None)

st = eng.capture_stats()
check("stats are available from a live capture", st is not None, st)
check("a fresh capture reports no loss", st and st["dropped"] == 0, st)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9944)); srv.listen(64)
stop = False
def serve():
    while not stop:
        try:
            c,_ = srv.accept(); c.recv(4096); c.sendall(b"x"*2000); c.close()
        except OSError: return
threading.Thread(target=serve, daemon=True).start()
for _ in range(40):
    c = socket.create_connection(("127.0.0.1", 9944)); c.sendall(b"hi"*50); c.recv(4096); c.close()
time.sleep(1.2)

st = eng.capture_stats()
check("the driver's received count moves with traffic", st and st["received"] > 0, st)
check("packets actually reached the store", store.total_packets > 0, store.total_packets)
check("loss is reported as a percentage", st and "loss_pct" in st, st)
stop = True; eng.stop(); srv.close()
time.sleep(0.3)

# ---- now the case the feature exists for: nothing draining the buffer
sock = conf.L2listen(iface="lo", filter="tcp port 9945")
srv2 = socket.socket(); srv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv2.bind(("127.0.0.1", 9945)); srv2.listen(128)
stop2 = False
def serve2():
    while not stop2:
        try:
            c,_ = srv2.accept(); c.recv(65535); c.sendall(b"x"*65000); c.close()
        except OSError: return
threading.Thread(target=serve2, daemon=True).start()
blob = b"y" * 60000
for _ in range(1500):
    try:
        c = socket.create_connection(("127.0.0.1", 9945)); c.sendall(blob); c.recv(65535); c.close()
    except OSError:
        break
time.sleep(0.4)
got = N.pcap_stats_for(sock)
check("the drop counter moves when the buffer overflows", got and got[1] > 0, got)
recv, drop, ifdrop = got
lost = drop + ifdrop
pct = lost * 100.0 / (recv + lost)
check("the loss share is substantial in this scenario", pct > 10, round(pct, 1))
print("      (driver saw %d, discarded %d — %.1f%%)" % (recv, lost, pct))
stop2 = True; sock.close(); srv2.close()

# ---- repeated start/stop must not crash. Closing a pcap handle while its
# sniffer thread is still reading it segfaults, which no test can catch after
# the fact -- so this runs the cycle and simply has to survive it.
for i in range(6):
    e = N.CaptureEngine(N.PacketStore(), res)
    if not e.start(iface="lo", bpf="tcp port 9946"):
        check("cycle %d started" % i, False, e.error); break
    e.capture_stats()
    e.stop()
    e.capture_stats()          # reading after stop must be safe too
else:
    check("six start/stop cycles survive without a crash", True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
