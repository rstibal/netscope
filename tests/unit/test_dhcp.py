import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_dhcp as D

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

MAC = bytes.fromhex("aabbcc112233")
CLIENT_IP = bytes([192, 168, 1, 77])
SERVER_IP = bytes([192, 168, 1, 1])


def opt(tag, value):
    return bytes([tag, len(value)]) + value


def packet(op, msg_type, xid, mac=MAC, yiaddr=b"\x00\x00\x00\x00",
          siaddr=b"\x00\x00\x00\x00", options=b""):
    pkt = bytearray(240)
    pkt[0] = op
    pkt[1] = 1
    pkt[2] = 6
    struct.pack_into("!I", pkt, 4, xid)
    pkt[16:20] = yiaddr
    pkt[20:24] = siaddr
    pkt[28:28 + len(mac)] = mac
    pkt[236:240] = b"\x63\x82\x53\x63"
    return bytes(pkt) + opt(53, bytes([msg_type])) + options + b"\xff"


# ---- 1. Not DHCP at all: too short, or missing the magic cookie.
check("short payload is not DHCP", D.parse(b"\x01\x01\x06") is None)
check("no magic cookie is not DHCP", D.parse(bytes(300)) is None)

# ---- 2. A DISCOVER carries the client's hostname and MAC before any lease exists.
xid = 0x1234ABCD
discover = packet(1, 1, xid, options=opt(12, b"robs-laptop") + opt(60, b"MSFT 5.0"))
d = D.parse(discover)
check("DISCOVER decodes", d is not None and d["msg_type"] == "DISCOVER", str(d))
check("DISCOVER carries the hostname", d["hostname"] == "robs-laptop", str(d))
check("DISCOVER carries the MAC", d["mac"] == "aa:bb:cc:11:22:33", str(d))

# ---- 3. An OFFER names the server and the offered address.
offer = packet(2, 2, xid, yiaddr=CLIENT_IP, siaddr=SERVER_IP,
              options=opt(54, SERVER_IP) + opt(51, struct.pack("!I", 86400)))
d = D.parse(offer)
check("OFFER decodes", d is not None and d["msg_type"] == "OFFER", str(d))
check("OFFER names the offered IP", d["your_ip"] == "192.168.1.77", str(d))
check("OFFER names the server", d["server_id"] == "192.168.1.1", str(d))
check("OFFER carries the lease time", d["lease_secs"] == 86400, str(d))

# ---- 4. The magic cookie alone, with no message-type option, is not DHCP.
no_msg_type = bytes(bytearray(236)) + b"\x63\x82\x53\x63" + b"\xff"
check("no msg-type option is not DHCP", D.parse(no_msg_type) is None)


# ---- tracker: DISCOVER/OFFER/REQUEST/ACK correlates into one lease ---------

t = D.DhcpTracker()
t.observe(discover, 0.0)
t.observe(offer, 0.0)
request = packet(1, 3, xid, options=opt(12, b"robs-laptop") + opt(50, CLIENT_IP) +
                 opt(54, SERVER_IP))
t.observe(request, 0.0)
ack = packet(2, 5, xid, yiaddr=CLIENT_IP, siaddr=SERVER_IP,
            options=opt(54, SERVER_IP) + opt(51, struct.pack("!I", 43200)) +
                    opt(3, SERVER_IP))
t.observe(ack, 1.0)

leases = t.list()
check("ACK completes exactly one lease", len(leases) == 1, str(leases))
lease = leases[0] if leases else {}
check("lease carries the hostname learned from the REQUEST",
      lease.get("hostname") == "robs-laptop", str(lease))
check("lease carries the assigned IP", lease.get("ip") == "192.168.1.77", str(lease))
check("lease carries the answering server", lease.get("server") == "192.168.1.1", str(lease))
check("lease carries the lease time from the ACK",
      lease.get("lease_secs") == 43200, str(lease))
check("the server is remembered for rogue-server detection",
      "192.168.1.1" in t.servers, str(t.servers))
check("latest(mac) finds the same lease",
      t.latest("aa:bb:cc:11:22:33") == lease, str(t.latest("aa:bb:cc:11:22:33")))

# ---- a second, different server answering is a distinct entry in .servers ---
xid2 = 0x9999
rogue_offer = packet(2, 2, xid2, mac=bytes.fromhex("aabbcc445566"),
                     yiaddr=bytes([192, 168, 1, 88]),
                     siaddr=bytes([192, 168, 1, 250]),
                     options=opt(54, bytes([192, 168, 1, 250])))
t.observe(rogue_offer, 2.0)
check("a second DHCP server is tracked separately",
      t.servers == {"192.168.1.1", "192.168.1.250"}, str(t.servers))

# ---- a DECLINE/RELEASE with no server_id never overwrites a completed lease --
before = t.latest("aa:bb:cc:11:22:33")
release = packet(1, 7, xid, options=opt(50, CLIENT_IP))
t.observe(release, 3.0)
check("a RELEASE (no server_id) doesn't touch the completed lease",
      t.latest("aa:bb:cc:11:22:33") == before, str(t.latest("aa:bb:cc:11:22:33")))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
