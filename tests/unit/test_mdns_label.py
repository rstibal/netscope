"""
mDNS and LLMNR are labelled by port, not by whether scapy dissected DNS.

scapy 2.7 binds its DNS layer to UDP 5353, so `DNS in pkt` became true for
mDNS and every Bonjour query was labelled plain "DNS". The resolver alert
then judged Chrome's multicast to 224.0.0.251 / ff02::fb against each
adapter's configured resolvers and warned "DNS to an unconfigured resolver"
on Wi-Fi, Ethernet and the VPN at once.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

import netscope as N
import netscope_alerts as A

if not N.SCAPY_OK:
    print("SKIP  test_mdns_label.py needs scapy")
    sys.exit(0)

from scapy.all import Ether, IP, IPv6, UDP, DNS, DNSQR

store = N.PacketStore()
engine = N.CaptureEngine(store, N.ProcessResolver())


def label(frame):
    rec, _, _ = engine._build(Ether(bytes(frame)))
    return rec and rec["proto"]


def query(name):
    return DNS(rd=0, qd=DNSQR(qname=name))


mdns4 = Ether() / IP(src="192.168.0.5", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / query("_googlecast._tcp.local")
mdns6 = Ether() / IPv6(src="fe80::5", dst="ff02::fb") / UDP(sport=5353, dport=5353) / query("_googlecast._tcp.local")
llmnr = Ether() / IP(src="192.168.0.5", dst="224.0.0.252") / UDP(sport=50000, dport=5355) / query("printer")
dns = Ether() / IP(src="192.168.0.5", dst="192.168.0.1") / UDP(sport=50001, dport=53) / query("example.com")

check("mDNS over IPv4 is MDNS", label(mdns4) == "MDNS", label(mdns4))
check("mDNS over IPv6 is MDNS", label(mdns6) == "MDNS", label(mdns6))
check("LLMNR is LLMNR", label(llmnr) == "LLMNR", label(llmnr))
check("unicast DNS is still DNS", label(dns) == "DNS", label(dns))

# ---- The resolver rule never treats a multicast group as a resolver, even if
# something upstream labels it DNS (a future scapy, an odd pcap).
e = A.AlertEngine()
e._dns_read = A._now()
e.dns_configured = {"192.168.0.1"}
e.dns_by_iface = {"Wi-Fi": {"192.168.0.1"}}
for dst in ("224.0.0.251", "ff02::fb", "224.0.0.252", "ff02::1:3"):
    for _ in range(10):
        e._dns_rule({"proto": "DNS", "dir": "out", "remote": dst,
                     "iface": "Wi-Fi", "process": "chrome.exe"})
check("multicast destinations never fire the resolver rule", e.list() == [],
      [a["detail"] for a in e.list()])

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
