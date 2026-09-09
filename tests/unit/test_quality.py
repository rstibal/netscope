import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys
from netscope_conn import FlowTable, build_view

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

L,R = "10.0.0.5", "1.2.3.4"
def pkt(ts, d, flags=None, seq=None, ack=None, plen=0, tls=None):
    dec = {}
    if flags is not None:
        dec["tcp"] = {"flags": flags, "seq": seq, "ack": ack, "window": 64240}
    if tls is not None:
        dec["tls"] = tls
    return {"src": L if d=="out" else R, "sport": 5000 if d=="out" else 443,
            "dst": R if d=="out" else L, "dport": 443 if d=="out" else 5000,
            "transport":"tcp","iface":"Wi-Fi","dir":d,"length":plen+66,
            "payload_len":plen,"ts":ts,"decoded":dec}

def only(ft):
    return list(ft.snapshot().values())[0]

# ---- handshake RTT
ft = FlowTable()
ft.observe(pkt(100.000, "out", "S",  seq=1000))
ft.observe(pkt(100.042, "in",  "SA", seq=7000, ack=1001))
ft.observe(pkt(100.043, "out", "A",  seq=1001, ack=7001))
check("handshake RTT measured in ms", only(ft)["rtt"]==42.0, only(ft)["rtt"])

# a SYN/ACK with no preceding SYN (capture started mid-connection) must not lie
ft = FlowTable()
ft.observe(pkt(100.0, "in", "SA", seq=7000, ack=1))
check("no SYN seen -> no RTT invented", only(ft)["rtt"] is None, only(ft)["rtt"])

# a second handshake on the same tuple must not overwrite the first
ft = FlowTable()
ft.observe(pkt(100.0, "out","S", seq=1)); ft.observe(pkt(100.02,"in","SA",seq=9,ack=2))
ft.observe(pkt(200.0, "out","S", seq=1)); ft.observe(pkt(200.50,"in","SA",seq=9,ack=2))
check("first RTT is kept, not replaced", only(ft)["rtt"]==20.0, only(ft)["rtt"])

# ---- resent segments
ft = FlowTable()
ft.observe(pkt(1.0, "out", "PA", seq=1000, plen=100))    # covers 1000-1100
ft.observe(pkt(1.1, "out", "PA", seq=1100, plen=100))    # covers 1100-1200
ft.observe(pkt(1.5, "out", "PA", seq=1000, plen=100))    # already covered
check("a resent segment is counted", only(ft)["resent"]==1, only(ft)["resent"])
check("forward progress is not", only(ft)["_next"]["out"]==1200, only(ft)["_next"])

# each direction is tracked separately
ft = FlowTable()
ft.observe(pkt(1.0,"out","PA",seq=500,plen=50))
ft.observe(pkt(1.1,"in","PA",seq=500,plen=50))          # same seq, other direction
check("directions do not collide", only(ft)["resent"]==0, only(ft)["resent"])

# a pure ACK is not a resend however many arrive
ft = FlowTable()
for i in range(5): ft.observe(pkt(1.0+i,"out","A",seq=1000,ack=1,plen=0))
check("bare ACKs are never counted as resends", only(ft)["resent"]==0, only(ft)["resent"])

# ---- duplicate ACKs
ft = FlowTable()
ft.observe(pkt(1.0,"in","A",seq=9,ack=5000))
ft.observe(pkt(1.1,"in","A",seq=9,ack=5000))            # 2nd
ft.observe(pkt(1.2,"in","A",seq=9,ack=5000))            # 3rd -> the signal
ft.observe(pkt(1.3,"in","A",seq=9,ack=5000))            # 4th
check("dup ACKs counted from the third", only(ft)["dup_ack"]==2, only(ft)["dup_ack"])
ft.observe(pkt(1.4,"in","A",seq=9,ack=6000))            # ack advances
ft.observe(pkt(1.5,"in","A",seq=9,ack=6000))
check("advancing ACK resets the run", only(ft)["dup_ack"]==2, only(ft)["dup_ack"])

# ---- TLS handshake duration
HELLO={"record":"Handshake","handshake":"ClientHello","version":"TLS 1.2"}
APP={"record":"ApplicationData","version":"TLS 1.2"}
SH={"record":"Handshake","handshake":"ServerHello","version":"TLS 1.2"}
ft = FlowTable()
ft.observe(pkt(10.0,"out","PA",seq=1,plen=300,tls=HELLO))
ft.observe(pkt(10.03,"in","PA",seq=1,plen=200,tls=SH))
ft.observe(pkt(10.085,"in","PA",seq=201,plen=90,tls=APP))
check("TLS handshake timed to first ApplicationData",
      only(ft)["tls_ms"]==85.0, only(ft)["tls_ms"])
ft.observe(pkt(20.0,"in","PA",seq=999,plen=90,tls=APP))
check("later ApplicationData does not restate it",
      only(ft)["tls_ms"]==85.0, only(ft)["tls_ms"])

# ApplicationData with no ClientHello (capture joined late) reports nothing
ft = FlowTable()
ft.observe(pkt(10.0,"in","PA",seq=1,plen=90,tls=APP))
check("no ClientHello -> no TLS timing invented", only(ft)["tls_ms"] is None)

# ---- UDP flows are untouched by all of this
ft = FlowTable()
r = pkt(1.0,"out"); r["transport"]="udp"; r["decoded"]={}
ft.observe(r)
q = only(ft)
check("UDP flow has empty quality fields, not garbage",
      q["rtt"] is None and q["tls_ms"] is None and q["resent"]==0 and q["dup_ack"]==0, q)

# ---- the numbers reach the rows
ft = FlowTable()
ft.observe(pkt(100.0,"out","S",seq=1000))
ft.observe(pkt(100.042,"in","SA",seq=7000,ack=1001))
ft.observe(pkt(100.1,"out","PA",seq=1001,plen=100,tls=HELLO))
ft.observe(pkt(100.2,"in","PA",seq=7001,plen=50,tls=APP))
ft.observe(pkt(100.3,"out","PA",seq=1001,plen=100))
sk=[{"proto":"tcp","state":"ESTABLISHED","pid":1,"laddr":L,"lport":5000,
     "raddr":R,"rport":443}]
op,_,_ = build_view(sk, ft, now=101.0)
row = op[0]
check("row carries rtt", row["rtt"]==42.0, row["rtt"])
check("row carries tls_ms", row["tls_ms"]==100.0, row["tls_ms"])
check("row carries resent", row["resent"]==1, row["resent"])
check("row exposes no internal state",
      not any(k.startswith("_") for k in row), [k for k in row if k.startswith("_")])

# closed rows carry it too
op2, _, cl2 = build_view([], ft, now=101.0)
check("closed rows carry quality as well",
      cl2 and cl2[0]["rtt"]==42.0 and cl2[0]["resent"]==1, cl2 and cl2[0])

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
