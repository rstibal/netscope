import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys
from netscope_conn import FlowTable, flow_key, build_view

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def rec(src,sport,dst,dport,d,length,proto="udp",iface="",**kw):
    r={"src":src,"sport":sport,"dst":dst,"dport":dport,"dir":d,"length":length,
       "transport":proto,"iface":iface,"ts":kw.pop("ts",1000.0)}
    r.update(kw); return r

# ---------- 1. unconnected UDP: one socket, many conversations
ft = FlowTable()
ft.observe(rec("192.168.1.20",54000,"1.1.1.1",53,"out",80,iface="Wi-Fi",process="svchost.exe"))
ft.observe(rec("1.1.1.1",53,"192.168.1.20",54000,"in",200,iface="Wi-Fi"))
ft.observe(rec("192.168.1.20",54000,"8.8.8.8",53,"out",90,iface="Wi-Fi"))
sock = [{"proto":"udp","state":"NONE","pid":900,"laddr":"192.168.1.20","lport":54000,
         "raddr":"","rport":0}]
op, lis, closed = build_view(sock, ft, name_for_pid={900:"svchost.exe"}.get, now=1000.0)
check("unconnected UDP socket claims both conversations", len(op)==2, [ (r['raddr'],r['in'],r['out']) for r in op])
check("...and neither is reported as closed", closed==[], closed)
check("...and it is not filed as a listener", lis==[], lis)
check("row learns the peer from the flow",
      sorted(r["raddr"] for r in op)==["1.1.1.1","8.8.8.8"], [r["raddr"] for r in op])
check("row is attributed to the socket's process",
      all(r["process"]=="svchost.exe" for r in op), [r["process"] for r in op])

# ---------- 2. wildcard bind matches on port
ft2 = FlowTable()
ft2.observe(rec("192.168.1.20",5353,"224.0.0.251",5353,"out",120,iface="Wi-Fi"))
sk2 = [{"proto":"udp","state":"NONE","pid":4,"laddr":"0.0.0.0","lport":5353,"raddr":"","rport":0}]
op2, lis2, cl2 = build_view(sk2, ft2, name_for_pid={4:"mDNS"}.get, now=1000.0)
check("wildcard bind still finds its traffic", len(op2)==1 and cl2==[], (len(op2), len(cl2)))

# ---------- 3. THE VPN SHAPE: inner on the tunnel, outer on the NIC
ft3 = FlowTable()
# inner: browser -> real site, over the PIA tunnel adapter
ft3.observe(rec("10.4.0.6",51000,"142.250.80.46",443,"out",500,proto="tcp",
                iface="PIA OpenVPN WinTUN Adapter",process="chrome.exe",rhost="www.google.com"))
# outer: the encapsulated copy, PIA client -> PIA server, on the physical NIC
ft3.observe(rec("192.168.1.20",1198,"181.214.1.9",1198,"out",560,proto="udp",
                iface="Wi-Fi",process="pia-openvpn.exe"))
sk3 = [
  # the app's socket lives on the tunnel address
  {"proto":"tcp","state":"ESTABLISHED","pid":11,"laddr":"10.4.0.6","lport":51000,
   "raddr":"142.250.80.46","rport":443},
  # the VPN's own UDP socket is unconnected in this scenario
  {"proto":"udp","state":"NONE","pid":22,"laddr":"192.168.1.20","lport":1198,
   "raddr":"","rport":0},
]
names={11:"chrome.exe",22:"pia-openvpn.exe"}
op3, lis3, cl3 = build_view(sk3, ft3, name_for_pid=names.get, now=1000.0)
check("VPN: both halves are open rows, nothing 'closed'", len(op3)==2 and cl3==[],
      (len(op3), len(cl3)))
ifaces = sorted(r["iface"] for r in op3)
check("VPN: rows carry the adapter they were seen on",
      ifaces==["PIA OpenVPN WinTUN Adapter","Wi-Fi"], ifaces)
inner = [r for r in op3 if r["iface"].startswith("PIA")][0]
outer = [r for r in op3 if r["iface"]=="Wi-Fi"][0]
check("VPN: inner row is the app and the real host",
      inner["process"]=="chrome.exe" and inner["rhost"]=="www.google.com", inner)
check("VPN: outer row is the VPN client and the VPN server",
      outer["process"]=="pia-openvpn.exe" and outer["raddr"]=="181.214.1.9", outer)

# ---------- 4. the same tuple on two adapters must not merge or double-count
ft4 = FlowTable()
for ifc in ("Wi-Fi", "Ethernet"):
    ft4.observe(rec("10.0.0.5",6000,"1.2.3.4",443,"out",100,proto="tcp",iface=ifc))
snap = ft4.snapshot()
check("same tuple on two adapters stays two flows", len(snap)==2, len(snap))
check("...each keeping its own bytes",
      all(f["out"]==100 for f in snap.values()), [f["out"] for f in snap.values()])
sk4=[{"proto":"tcp","state":"ESTABLISHED","pid":1,"laddr":"10.0.0.5","lport":6000,
      "raddr":"1.2.3.4","rport":443}]
op4,_,cl4 = build_view(sk4, ft4, now=1000.0)
check("one socket seen on two adapters -> two rows", len(op4)==2 and cl4==[],
      (len(op4), len(cl4)))
check("...neither row inherits the other's bytes",
      all(r["out"]==100 for r in op4), [r["out"] for r in op4])

# ---------- 5. a genuine TCP listener is still a listener
ft5 = FlowTable()
sk5=[{"proto":"tcp","state":"LISTEN","pid":4,"laddr":"0.0.0.0","lport":445,"raddr":"","rport":0}]
op5, lis5, _ = build_view(sk5, ft5, name_for_pid={4:"System"}.get, now=1000.0)
check("TCP LISTEN is not turned into a connection", op5==[] and len(lis5)==1, (op5,lis5))

# ---------- 6. a silent unconnected UDP socket reads as a listener, not a ghost
ft6 = FlowTable()
sk6=[{"proto":"udp","state":"NONE","pid":7,"laddr":"192.168.1.20","lport":68,"raddr":"","rport":0}]
op6, lis6, _ = build_view(sk6, ft6, name_for_pid={7:"svchost.exe"}.get, now=1000.0)
check("idle unconnected UDP socket listed once, under Listening",
      op6==[] and len(lis6)==1, (op6, lis6))

# ---------- 7. one flow is never claimed by two sockets
ft7 = FlowTable()
ft7.observe(rec("192.168.1.20",7000,"5.6.7.8",443,"out",10,proto="udp",iface="Wi-Fi"))
sk7=[{"proto":"udp","state":"NONE","pid":1,"laddr":"192.168.1.20","lport":7000,"raddr":"","rport":0},
     {"proto":"udp","state":"NONE","pid":2,"laddr":"0.0.0.0","lport":7000,"raddr":"","rport":0}]
op7, lis7, cl7 = build_view(sk7, ft7, now=1000.0)
check("a flow is claimed once, the other socket falls back to Listening",
      len(op7)==1 and len(lis7)==1 and cl7==[], (len(op7), len(lis7), len(cl7)))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
