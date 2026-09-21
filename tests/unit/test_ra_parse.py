import os, socket, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_l2 as L

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


def header(managed=False, other_config=False, lifetime=1800):
    flags = (0x80 if managed else 0) | (0x40 if other_config else 0)
    return bytes([134, 0, 0, 0, 64, flags]) + struct.pack("!H", lifetime) + \
           struct.pack("!I", 0) + struct.pack("!I", 0)


def opt_slla(mac=bytes.fromhex("aabbcc112233")):
    return bytes([1, 1]) + mac


def opt_prefix(prefix="2001:db8::", plen=64, on_link=True, auto=True,
              valid=86400, preferred=14400):
    pflags = (0x80 if on_link else 0) | (0x40 if auto else 0)
    return (bytes([3, 4, plen, pflags]) + struct.pack("!I", valid) +
            struct.pack("!I", preferred) + b"\x00" * 4 +
            socket.inet_pton(socket.AF_INET6, prefix))


def opt_rdnss(servers, lifetime=600):
    body = bytes([25, 1 + 2 * len(servers), 0, 0]) + struct.pack("!I", lifetime)
    for s in servers:
        body += socket.inet_pton(socket.AF_INET6, s)
    return body


# ---- 1. Not an RA at all: too short, or wrong type. ----
check("too short is not an RA", L.parse_ra(bytes(10)) is None)
wrong_type = bytes([128, 0, 0, 0, 64, 0]) + bytes(10)
check("wrong ICMPv6 type is not an RA", L.parse_ra(wrong_type) is None)

# ---- 2. A bare RA with no options decodes the fixed header. ----
ra = L.parse_ra(header(lifetime=1800))
check("bare RA decodes", ra is not None, str(ra))
check("router lifetime read correctly", ra["router_lifetime"] == 1800, str(ra))
check("no options -> empty prefixes/rdnss",
      ra["prefixes"] == [] and ra["rdnss"] == [], str(ra))

# ---- 3. M/O flags are read from the flags byte. ----
ra = L.parse_ra(header(managed=True, other_config=False))
check("managed flag set", ra["managed"] is True and ra["other_config"] is False, str(ra))
ra = L.parse_ra(header(managed=False, other_config=True))
check("other-config flag set", ra["managed"] is False and ra["other_config"] is True, str(ra))

# ---- 4. Source link-layer address option. ----
ra = L.parse_ra(header() + opt_slla())
check("source link-layer address decodes",
      ra["source_link_layer"] == "aa:bb:cc:11:22:33", str(ra))

# ---- 5. Prefix information option. ----
ra = L.parse_ra(header() + opt_prefix())
check("exactly one prefix decoded", len(ra["prefixes"]) == 1, str(ra))
p = ra["prefixes"][0] if ra["prefixes"] else {}
check("prefix carries CIDR", p.get("prefix") == "2001:db8::/64", str(p))
check("prefix carries on-link/autonomous flags",
      p.get("on_link") is True and p.get("autonomous") is True, str(p))
check("prefix carries lifetimes",
      p.get("valid_lifetime") == 86400 and p.get("preferred_lifetime") == 14400, str(p))

# ---- 6. RDNSS option, the DNS-hijack-relevant one, with two servers. ----
ra = L.parse_ra(header() + opt_rdnss(["2001:db8::53", "2001:db8::54"], lifetime=300))
check("both RDNSS servers decoded", len(ra["rdnss"]) == 2, str(ra))
check("RDNSS server addresses correct",
      {d["server"] for d in ra["rdnss"]} == {"2001:db8::53", "2001:db8::54"}, str(ra))
check("RDNSS lifetime carried", all(d["lifetime"] == 300 for d in ra["rdnss"]), str(ra))

# ---- 7. Multiple options together, in the order a real RA sends them. ----
combo = header() + opt_slla() + opt_prefix() + opt_rdnss(["2001:db8::53"])
ra = L.parse_ra(combo)
check("combo RA decodes all three options",
      ra["source_link_layer"] == "aa:bb:cc:11:22:33" and
      len(ra["prefixes"]) == 1 and len(ra["rdnss"]) == 1, str(ra))

# ---- 8. A truncated/malformed option list stops cleanly instead of crashing. ----
truncated = header() + opt_slla() + bytes([3, 4]) + b"\x00" * 3   # claims 32B, has 5
ra = L.parse_ra(truncated)
check("truncated trailing option -> no crash, earlier options kept",
      ra is not None and ra["source_link_layer"] == "aa:bb:cc:11:22:33", str(ra))

# ---- 9. A zero-length option (would spin forever if not guarded) stops the walk. ----
zero_len = header() + bytes([3, 0]) + opt_slla()
ra = L.parse_ra(zero_len)
check("zero-length option -> walk stops, no crash, no hang", ra is not None, str(ra))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
