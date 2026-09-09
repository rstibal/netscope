import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, subprocess, time, threading, socket
from scapy.config import conf
conf.use_pcap = True
import netscope as N

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def sh(*a): subprocess.run(list(a), check=True)
def names(): return {i["name"] for i in N.CaptureEngine.interfaces()}

for n in ("nsA",):
    subprocess.run(["ip","link","del",n], capture_output=True)

base = names()
check("test adapter absent to begin with", "nsA" not in base, base)

# ---- the listing must notice a new adapter without restarting the process
sh("ip","link","add","nsA","type","veth","peer","name","nsB")
sh("ip","addr","add","10.78.0.1/24","dev","nsA")
sh("ip","link","set","nsA","up"); sh("ip","link","set","nsB","up")

N.CaptureEngine._ifaces_read = 0.0          # allow an immediate re-read
found = names()
check("a new adapter is listed without restarting", "nsA" in found, sorted(found))

# ---- rate limiting: a second call right after must not re-query the OS
before = N.CaptureEngine._ifaces_read
N.CaptureEngine.interfaces()
check("the re-read is rate limited", N.CaptureEngine._ifaces_read == before)
N.CaptureEngine.refresh_interfaces(force=True)
check("...but force overrides it", N.CaptureEngine._ifaces_read > before)

# ---- and a running capture must attach it
sh("ip","link","del","nsA")
N.CaptureEngine.refresh_interfaces(force=True)
check("adapter removed again", "nsA" not in names())

eng = N.CaptureEngine(N.PacketStore(), N.ProcessResolver())
N.IFACE_WATCH = 1.0                      # keep the test brisk
ok = eng.start(iface="all")
check("capture started on all interfaces", ok, eng.error)
started_with = set(eng.ifaces)
check("the new adapter is not captured yet", "nsA" not in started_with, started_with)

sh("ip","link","add","nsA","type","veth","peer","name","nsB")
sh("ip","addr","add","10.78.0.1/24","dev","nsA")
sh("ip","link","set","nsA","up"); sh("ip","link","set","nsB","up")

deadline = time.time() + 25
while time.time() < deadline and "nsA" not in set(eng.ifaces):
    time.sleep(0.5)
check("the running capture attached the new adapter", "nsA" in set(eng.ifaces),
      sorted(eng.ifaces))
check("it is reported as newly attached", "nsA" in eng.new_ifaces, eng.new_ifaces)
check("the adapters it already had are still captured",
      started_with <= set(eng.ifaces), (started_with, set(eng.ifaces)))
check("there is one sniffer per adapter",
      len(eng.sniffers) == len(set(eng.ifaces)), len(eng.sniffers))

eng.stop(); time.sleep(0.5)
subprocess.run(["ip","link","del","nsA"], capture_output=True)
check("stopping with a watcher running does not crash", True)

# ---- a named-adapter capture must not attach things nobody asked for
eng2 = N.CaptureEngine(N.PacketStore(), N.ProcessResolver())
assert eng2.start(iface="lo"), eng2.error
sh("ip","link","add","nsA","type","veth","peer","name","nsB")
sh("ip","link","set","nsA","up")
time.sleep(3.0)
check("a named capture is left alone", set(eng2.ifaces) == {"lo"}, eng2.ifaces)
eng2.stop(); time.sleep(0.3)
subprocess.run(["ip","link","del","nsA"], capture_output=True)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
