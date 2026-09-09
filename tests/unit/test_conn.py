import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, time
from netscope_conn import FlowTable, flow_key, build_view

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else "")); 
    if not c: fails.append(n)

def rec(src,sport,dst,dport,d,length,proto="tcp",**kw):
    r={"src":src,"sport":sport,"dst":dst,"dport":dport,"dir":d,"length":length,
       "transport":proto,"ts":kw.pop("ts",1000.0)}
    r.update(kw); return r

# ---- both directions land on one row
ft = FlowTable()
ft.observe(rec("192.168.1.20",51000,"142.250.80.46",443,"out",100,process="chrome.exe",pid=9))
ft.observe(rec("142.250.80.46",443,"192.168.1.20",51000,"in",900,rhost="www.google.com"))
snap = ft.snapshot()
check("one flow for both directions", len(snap)==1, len(snap))
f = list(snap.values())[0]
check("bytes split by direction", f["out"]==100 and f["in"]==900, f)
check("packets counted", f["packets"]==2, f["packets"])
check("process learned from either packet", f["process"]=="chrome.exe", f["process"])
check("hostname learned from the later packet", f["rhost"]=="www.google.com", f["rhost"])

# ---- key is direction independent
a = flow_key("tcp","1.1.1.1",1,"2.2.2.2",2)
b = flow_key("tcp","2.2.2.2",2,"1.1.1.1",1)
check("flow_key is symmetric", a==b, f"{a} {b}")
check("proto separates udp from tcp",
      flow_key("udp","1.1.1.1",1,"2.2.2.2",2) != a)
check("scope id stripped from ipv6",
      flow_key("tcp","fe80::1%eth0",1,"::2",2) == flow_key("tcp","fe80::1",1,"::2",2))

# ---- packets without ports are ignored (ARP, ICMP)
ft2 = FlowTable()
ft2.observe({"src":"a","dst":"b","dir":"in","length":60,"ts":1.0})
check("port-less packets ignored", len(ft2.snapshot())==0)

# ---- merge: an open socket picks up its byte counts
sockets = [
  {"proto":"tcp","state":"ESTABLISHED","pid":9,"laddr":"192.168.1.20","lport":51000,
   "raddr":"142.250.80.46","rport":443},
  {"proto":"tcp","state":"LISTEN","pid":4,"laddr":"0.0.0.0","lport":445,"raddr":"","rport":0},
]
names = {9:"chrome.exe", 4:"System"}
op, lis, closed = build_view(sockets, ft, name_for_pid=names.get, now=1000.0)
check("one open connection", len(op)==1, len(op))
check("open row carries byte counts", op[0]["in"]==900 and op[0]["out"]==100, op[0])
check("open row carries hostname", op[0]["rhost"]=="www.google.com", op[0])
check("listener separated out", len(lis)==1 and lis[0]["lport"]==445, lis)
check("listener named from pid", lis[0]["process"]=="System", lis[0])
check("matched flow is not also 'closed'", closed==[], closed)

# ---- a flow with no socket shows as recently closed
ft.observe(rec("192.168.1.20",52000,"93.184.216.34",80,"out",200,ts=1000.0,process="curl.exe"))
op, lis, closed = build_view(sockets, ft, name_for_pid=names.get, now=1000.0)
check("unmatched recent flow -> closed list", len(closed)==1, closed)
check("closed row keeps process", closed[0]["process"]=="curl.exe", closed[0])
check("closed row picks the high port as local",
      closed[0]["lport"]==52000 and closed[0]["rport"]==80, closed[0])

# ---- and drops out once it is stale
op, lis, closed = build_view(sockets, ft, name_for_pid=names.get, now=1000.0+200)
check("stale flow drops off the closed list", closed==[], closed)

# ---- open rows sort busiest first
ft3 = FlowTable()
ft3.observe(rec("10.0.0.1",1111,"8.8.8.8",443,"out",50,ts=1.0))
ft3.observe(rec("10.0.0.1",2222,"9.9.9.9",443,"out",5000,ts=1.0))
sk = [{"proto":"tcp","state":"ESTABLISHED","pid":1,"laddr":"10.0.0.1","lport":1111,"raddr":"8.8.8.8","rport":443},
      {"proto":"tcp","state":"ESTABLISHED","pid":1,"laddr":"10.0.0.1","lport":2222,"raddr":"9.9.9.9","rport":443}]
op,_,_ = build_view(sk, ft3, now=2.0)
check("busiest connection first", op[0]["raddr"]=="9.9.9.9", [r["raddr"] for r in op])

# ---- pruning keeps the table bounded
ft4 = FlowTable(max_flows=50)
for i in range(500):
    ft4.observe(rec("10.0.0.1",1024+i,"1.2.3.4",443,"out",10,ts=1.0+i))
check("flow table stays bounded", len(ft4.snapshot())<=50, len(ft4.snapshot()))

# ---- idle flows age out
ft5 = FlowTable()
ft5.observe(rec("10.0.0.1",1111,"1.2.3.4",443,"out",10,ts=1.0))
ft5.observe(rec("10.0.0.1",2222,"1.2.3.4",443,"out",10,ts=5000.0))
check("idle flow pruned, live one kept", len(ft5.snapshot())==1, ft5.snapshot())

# ---- no sockets at all (offline / no psutil) still lists closed flows
op, lis, closed = build_view([], ft3, now=2.0)
check("no sockets -> everything reads as closed", len(op)==0 and len(closed)==2,
      (len(op), len(closed)))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
