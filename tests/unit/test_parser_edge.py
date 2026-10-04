import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope as N
import netscope_ftp as F
import netscope_l2 as L
import netscope_smb as SM

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

# ---- FTP: malformed negotiation lines never raise ---------------------------
c = F.FTPCorrelator()
CL, SV = "10.0.0.5", "203.0.113.9"
bad = [b"227 Entering Passive Mode (1,2,3).\r\n",
       b"227 Entering Passive Mode (1,2,3,4,5,6,7,8).\r\n",
       b"227 Entering Passive Mode (300,1,1,1,2,3).\r\n",
       b"227 Entering Passive Mode (,,,,,).\r\n",
       b"229 Entering Extended Passive Mode (|||0|)\r\n",
       b"229 Entering Extended Passive Mode (|||99999|)\r\n"]
ok = True
for r in bad:
    try: c.observe_control(SV, 21, CL, 50000, r, False, 1.0)
    except Exception as e: ok = False; print("   raised on", r, e)
check("malformed PASV/EPSV replies are ignored, not raised", ok)
check("...and arm nothing", not c._negotiated and not c._pending_addr)
try:
    c.observe_control(CL, 50000, SV, 21, b"PORT 999,1,1,1,2,3\r\n", True, 1.0)
    c.observe_control(CL, 50000, SV, 21, b"PORT 1,2,3,4,5\r\n", True, 1.0)
    c.observe_control(CL, 50000, SV, 21, b"EPRT |1|1.2.3.4|0|\r\n", True, 1.0)
    check("malformed PORT/EPRT are ignored too", not c._negotiated)
except Exception as e:
    check("malformed PORT/EPRT are ignored too", False, e)
PUB = "93.184.216.34"      # a routable address (203.0.113.x counts as private)

# ---- FTP: a server behind NAT announces its private address -----------------
c = F.FTPCorrelator()
c.observe_control(CL, 50000, PUB, 21, b"PASV\r\n", True, 1.0)
c.observe_control(CL, 50000, PUB, 21, b"RETR big.iso\r\n", True, 1.0)
c.observe_control(PUB, 21, CL, 50000, b"227 Entering Passive Mode (192,168,0,7,200,54).\r\n", False, 1.0)
meta = c.match_data(PUB, 200 * 256 + 54, CL, 49999)
check("a private PASV address is replaced by the one the client dialled",
      meta and meta["name"] == "big.iso" and meta["endpoint"] == (PUB, 51254), meta)
c = F.FTPCorrelator()       # a LAN server genuinely at a private address
c.observe_control(CL, 50000, "192.168.0.7", 21, b"RETR a.txt\r\n", True, 1.0)
c.observe_control("192.168.0.7", 21, CL, 50000, b"227 x (192,168,0,7,200,54)\r\n", False, 1.0)
check("a LAN server's own private address is left alone",
      c.match_data("192.168.0.7", 51254, CL, 1) is not None)

# ---- STP: type and root bridge read from the right bytes --------------------
bpdu = bytes.fromhex("0000" "00" "00" "00" "8000aabbccddeeff" "00000004"
                     "8000112233445566" "8001" "0000" "1400" "0200" "0f00")
info = L._stp_info(bpdu)
check("root bridge priority and MAC", "root 32768/aa:bb:cc:dd:ee:ff" in info, info)
check("path cost", "cost 4" in info, info)
tc = bytearray(bpdu); tc[4] = 0x01
check("the topology-change flag does not change the BPDU type",
      "configuration BPDU" in L._stp_info(bytes(tc)), L._stp_info(bytes(tc)))
check("a topology change notification is named",
      "topology change notification" in L._stp_info(bytes.fromhex("00000080")))
check("a runt BPDU does not raise", L._stp_info(b"\x00") == "Spanning Tree")

# ---- SMB: an interim PENDING answer doesn't swallow the file name -----------
import struct
def hdr(cmd, flags, msgid, status=0, session=7, tree=1):
    h = bytearray(64)
    h[0:4] = b"\xfeSMB"; h[4:6] = struct.pack("<H", 64)
    h[8:12] = struct.pack("<I", status); h[12:14] = struct.pack("<H", cmd)
    h[16:20] = struct.pack("<I", flags); h[24:32] = struct.pack("<Q", msgid)
    h[36:40] = struct.pack("<I", tree); h[40:48] = struct.pack("<Q", session)
    return bytes(h)
def nbss(m): return b"\x00" + len(m).to_bytes(3, "big") + m

name = "doc.txt".encode("utf-16-le")
body = bytearray(56)
body[0:2] = struct.pack("<H", 57)
body[24:28] = struct.pack("<I", 1)                      # read access
body[36:40] = struct.pack("<I", 1)
body[44:46] = struct.pack("<H", 64 + 56); body[46:48] = struct.pack("<H", len(name))
create_req = nbss(hdr(5, 0, 11) + bytes(body) + name)
fid = bytes(range(1, 17))
resp_body = bytearray(88); resp_body[0:2] = struct.pack("<H", 89)
resp_body[48:56] = struct.pack("<Q", 1234); resp_body[64:80] = fid
interim = nbss(hdr(5, 1, 11, status=0x103) + b"\x09\x00\x00\x00" + b"\x00" * 5)
final = nbss(hdr(5, 1, 11) + bytes(resp_body))
t = SM.SmbTracker()
t.parse(create_req); t.parse(interim)
check("the file name survives an interim response", (7, fid) not in t.files and (7, 11) in t.pending)
r = t.parse(final)
check("...and is attached to the final one", t.files.get((7, fid)) == "doc.txt", t.files)
rd = bytearray(48); rd[0:2] = struct.pack("<H", 49); rd[4:8] = struct.pack("<I", 100); rd[16:32] = fid
read = t.parse(nbss(hdr(8, 0, 12) + bytes(rd)))
check("a READ on it is named", read["messages"][0].get("filename") == "doc.txt", read)
t2 = SM.SmbTracker(); t2.parse(create_req)
t2.parse(nbss(hdr(5, 1, 11, status=0xC0000022) + b"\x09\x00\x00\x00" + b"\x00" * 5))
check("a failed open drops the pending name and records no file", not t2.files and (7, 11) not in t2.pending)

# ---- a decoder that raises must not make the packet vanish ------------------
if N.SCAPY_OK:
    from scapy.all import Ether, IP, TCP, Raw
    store = N.PacketStore()
    eng = N.CaptureEngine(store, N.ProcessResolver())
    def boom(*a, **k): raise RuntimeError("parser bug")
    eng.ftp.observe_control = boom
    pkt = Ether() / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(sport=50000, dport=21) / Raw(b"227 oops\r\n")
    eng._on_packet(pkt, "eth0")
    recs = store.since(0)
    check("the packet is still recorded", len(recs) == 1, len(recs))
    check("...flagged so it is visible", recs and "decode error" in recs[0]["info"], recs and recs[0]["info"])
    check("...and counted", eng.decode_errors == 1, eng.decode_errors)
    check("...with its addresses intact", recs and recs[0]["src"] == "10.0.0.5" and recs[0]["dport"] == 21)
else:
    print("SKIP  scapy not installed")

sys.exit(1 if fails else 0)
