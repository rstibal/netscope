import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import sys, struct
from netscope_pcap import write_pcap, LINKTYPE_ETHERNET, LINKTYPE_RAW

fails=[]
def check(n,c,e=""):
    print(("PASS  " if c else "FAIL  ")+n+(("  -- "+str(e)) if e and not c else ""))
    if not c: fails.append(n)

def dlt(blob): return struct.unpack("<I", blob[20:24])[0]
def frames(blob):
    out, i = [], 24
    while i < len(blob):
        sec, usec, incl, orig = struct.unpack("<IIII", blob[i:i+16])
        out.append((blob[i+16:i+16+incl], orig)); i += 16 + incl
    return out

ETH = b"\xaa"*6 + b"\xbb"*6 + b"\x08\x00" + b"\x45" + b"\x00"*19
IP4 = b"\x45" + b"\x00"*19
IP6 = b"\x60" + b"\x00"*19

# all Ethernet -> Ethernet, untouched
b1 = write_pcap([(1.0, ETH, len(ETH), "eth")])
check("all-Ethernet declares Ethernet", dlt(b1)==LINKTYPE_ETHERNET, dlt(b1))
check("all-Ethernet frames untouched", frames(b1)[0][0]==ETH)

# all raw IP -> LINKTYPE_RAW, untouched (this is the correct, lossless case)
b2 = write_pcap([(1.0, IP4, len(IP4), "raw")])
check("all-raw declares LINKTYPE_RAW", dlt(b2)==LINKTYPE_RAW, dlt(b2))
check("all-raw frames untouched", frames(b2)[0][0]==IP4)

# mixed -> Ethernet, raw ones given a zeroed header
b3 = write_pcap([(1.0, ETH, len(ETH), "eth"), (2.0, IP4, len(IP4), "raw"),
                 (3.0, IP6, len(IP6), "raw")])
check("mixed declares Ethernet", dlt(b3)==LINKTYPE_ETHERNET, dlt(b3))
f3 = frames(b3)
check("mixed leaves real Ethernet alone", f3[0][0]==ETH)
check("mixed prefixes v4 with a zeroed header + 0x0800",
      f3[1][0]==b"\x00"*12+b"\x08\x00"+IP4, f3[1][0][:16])
check("mixed prefixes v6 with a zeroed header + 0x86dd",
      f3[2][0]==b"\x00"*12+b"\x86\xdd"+IP6, f3[2][0][:16])
check("wire length grows with the synthesised header",
      f3[1][1]==len(IP4)+14, f3[1][1])

# legacy 3-tuples still work
b4 = write_pcap([(1.0, ETH, len(ETH))])
check("3-tuple records still accepted", dlt(b4)==LINKTYPE_ETHERNET and frames(b4)[0][0]==ETH)

# explicit linktype still wins
b5 = write_pcap([(1.0, IP4, len(IP4), "raw")], linktype=LINKTYPE_ETHERNET)
check("explicit linktype overrides detection", dlt(b5)==LINKTYPE_ETHERNET, dlt(b5))

# empty payloads skipped, empty input safe
b6 = write_pcap([(1.0, b"", 0, "eth")])
check("empty frames skipped", len(frames(b6))==0)
check("empty input still writes a valid header", len(write_pcap([]))==24)

# round-trip through scapy so the file is genuinely readable
from netscope_pcap import read_pcap
# NB: read_pcap returns (packets, None) on success. This container's scapy has
# no DLT->layer mapping loaded, so every frame comes back as Raw whatever the
# link type -- including on the pure-Ethernet path this change did not touch.
# The byte-level assertions above are the real verification; these only confirm
# the files are structurally readable and the frame count survives.
pkts, err = read_pcap(b3)
check("mixed file parses back", err is None and len(pkts)==3, (err, len(pkts)))
pkts2, err2 = read_pcap(b2)
check("raw-IP file parses back", err2 is None and len(pkts2)==1, (err2, len(pkts2)))
check("raw-IP frame comes back byte-identical",
      pkts2 and bytes(pkts2[0])==IP4, pkts2 and bytes(pkts2[0])[:4])

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
