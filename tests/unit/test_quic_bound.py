import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_quic as Q

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

# ---- fragments at endless offsets are cut off, not collected ---------------
r = Q.InitialReassembler()
for i in range(Q.InitialReassembler.MAX_FRAGMENTS + 10):
    r.feed(b"\x01" * 8, {i * 10: b"x" * 5})          # holes: never completes
e = r._conns[b"\x01" * 8]
check("fragment count is capped", len(e["chunks"]) <= Q.InitialReassembler.MAX_FRAGMENTS + 1,
      len(e["chunks"]))
check("the connection is given up on", e["done"] is True)
check("later packets for it cost nothing", r.feed(b"\x01" * 8, {0: b"y"}) == (None, False))

r = Q.InitialReassembler()
r.feed(b"\x02" * 8, {0: b"\x01\x00\xff\xff" + b"a" * 100})   # claims a 65KB message
r.feed(b"\x02" * 8, {104: b"b" * 40000})
whole, fresh = r.feed(b"\x02" * 8, {40104: b"c" * 40000})
check("byte total is capped", whole is None and r._conns[b"\x02" * 8]["chunks"] == {})

# ---- a genuine split ClientHello still reassembles --------------------------
if Q.CRYPTO_OK:
    r = Q.InitialReassembler()
    pkts = Q.build_split_client_initials(b"\x07" * 8, b"\x08" * 4, "www.example.com", size=2600)
    last = None
    for pk in pkts:
        last = Q.parse_quic(pk, 50000, 443, reassembler=r)
    check("split ClientHello yields its hostname", last and last.get("sni") == "www.example.com", last)
else:
    print("SKIP  cryptography not installed")

sys.exit(1 if fails else 0)
