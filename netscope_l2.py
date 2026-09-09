# -*- coding: utf-8 -*-
"""
Link-layer and ICMP decoding — turning the rows that said nothing into rows
that say something.

A real capture on a switched network is full of two kinds of packet the
earlier decoders gave up on: ICMP shown as bare `type=3 code=3`, and frames
that are not IP, IPv6 or ARP at all, which fell through to protocol OTHER with
`?` for both addresses. On one ten-minute capture that was well over half the
rows — visually present, informationally empty.

Neither needs deep parsing. ICMP just needs its numbers named, and the
link-layer frames need identifying by ethertype or LLC SAP, which is a lookup
and a handful of fields.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------

ICMP4_TYPES = {
    0: "Echo reply", 3: "Destination unreachable", 4: "Source quench",
    5: "Redirect", 8: "Echo request (ping)", 9: "Router advertisement",
    10: "Router solicitation", 11: "Time exceeded", 12: "Parameter problem",
    13: "Timestamp request", 14: "Timestamp reply",
    15: "Information request", 16: "Information reply",
    17: "Address mask request", 18: "Address mask reply", 30: "Traceroute",
}

ICMP4_CODES = {
    3: {0: "network unreachable", 1: "host unreachable",
        2: "protocol unreachable", 3: "port unreachable",
        4: "fragmentation needed but DF set", 5: "source route failed",
        6: "destination network unknown", 7: "destination host unknown",
        9: "network administratively prohibited",
        10: "host administratively prohibited",
        11: "network unreachable for this ToS",
        12: "host unreachable for this ToS",
        13: "communication administratively prohibited"},
    5: {0: "redirect for the network", 1: "redirect for the host",
        2: "redirect for ToS and network", 3: "redirect for ToS and host"},
    11: {0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded"},
    12: {0: "pointer indicates the error", 1: "missing a required option",
         2: "bad length"},
}

ICMP6_TYPES = {
    1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
    4: "Parameter problem", 128: "Echo request (ping)", 129: "Echo reply",
    130: "Multicast listener query", 131: "Multicast listener report",
    132: "Multicast listener done", 133: "Router solicitation",
    134: "Router advertisement", 135: "Neighbour solicitation",
    136: "Neighbour advertisement", 137: "Redirect",
    141: "Inverse neighbour solicitation",
    142: "Inverse neighbour advertisement",
    143: "Multicast listener report v2",
}

ICMP6_CODES = {
    1: {0: "no route to destination", 1: "administratively prohibited",
        2: "beyond scope of source address", 3: "address unreachable",
        4: "port unreachable", 5: "source address failed policy",
        6: "route rejected"},
    3: {0: "hop limit exceeded in transit",
        1: "fragment reassembly time exceeded"},
    4: {0: "erroneous header field", 1: "unrecognised next header",
        2: "unrecognised option"},
}


def describe_icmp(itype, icode, v6=False):
    """'Destination unreachable · port unreachable' instead of type=3 code=3."""
    types = ICMP6_TYPES if v6 else ICMP4_TYPES
    codes = ICMP6_CODES if v6 else ICMP4_CODES
    name = types.get(itype, "Type %d" % itype)
    detail = codes.get(itype, {}).get(icode)
    if detail:
        return f"{name} · {detail}"
    if icode:
        return f"{name} · code {icode}"
    return name


# ---------------------------------------------------------------------------
# Link layer
# ---------------------------------------------------------------------------

ETHERTYPES = {
    0x0800: ("IPv4", None), 0x0806: ("ARP", None), 0x86DD: ("IPv6", None),
    0x8100: ("VLAN", "802.1Q tagged"), 0x88A8: ("VLAN", "802.1ad QinQ"),
    0x88CC: ("LLDP", "Link Layer Discovery Protocol"),
    0x88E1: ("HomePlug", "HomePlug AV"),
    0x888E: ("EAPOL", "802.1X authentication"),
    0x8863: ("PPPoE", "discovery"), 0x8864: ("PPPoE", "session"),
    0x0842: ("WoL", "Wake-on-LAN magic packet"),
    0x8035: ("RARP", "Reverse ARP"),
    0x88F7: ("PTP", "Precision Time Protocol"),
    0x8809: ("LACP", "link aggregation / slow protocols"),
    0x22EA: ("SRP", "Stream Reservation Protocol"),
    0x9000: ("Loop", "Ethernet configuration test"),
}

# LLC service access points, for the 802.3 frames that carry no ethertype.
LLC_SAPS = {
    0x42: ("STP", "Spanning Tree"),
    0xE0: ("IPX", "Novell IPX"),
    0xF0: ("NetBIOS", "NetBIOS over LLC"),
    0xFE: ("OSI", "OSI network layer"),
    0xAA: ("SNAP", None),
}

STP_TYPES = {0x00: "configuration BPDU", 0x80: "topology change notification"}

# Multicast MACs worth naming on sight.
KNOWN_MACS = {
    "01:80:c2:00:00:00": "STP bridge group",
    "01:80:c2:00:00:03": "802.1X PAE",
    "01:80:c2:00:00:0e": "LLDP nearest bridge",
    "01:00:0c:cc:cc:cc": "Cisco CDP/VTP",
    "01:00:0c:cc:cc:cd": "Cisco PVST+",
    "01:00:5e:00:00:01": "all IPv4 hosts",
    "01:00:5e:00:00:02": "all IPv4 routers",
    "01:00:5e:00:00:fb": "mDNS",
    "01:00:5e:7f:ff:fa": "SSDP",
    "ff:ff:ff:ff:ff:ff": "broadcast",
}


def mac_label(mac):
    if not mac:
        return ""
    m = mac.lower()
    known = KNOWN_MACS.get(m)
    return f"{mac} ({known})" if known else mac


def is_multicast_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except Exception:
        return False


def _stp_info(body: bytes):
    try:
        if len(body) < 35:
            return "Spanning Tree"
        bpdu_type = body[4]
        kind = STP_TYPES.get(bpdu_type, "type 0x%02x" % bpdu_type)
        if bpdu_type == 0x00 and len(body) >= 35:
            root = ":".join("%02x" % b for b in body[6:14])
            cost = struct.unpack("!I", body[13:17])[0] if len(body) >= 17 else 0
            return f"Spanning Tree · {kind} · root {root} cost {cost}"
        return f"Spanning Tree · {kind}"
    except Exception:
        return "Spanning Tree"


def describe_frame(pkt, raw: bytes):
    """
    Identify a frame that is not IPv4/IPv6/ARP.

    Returns (proto, info, src, dst) or None if we still cannot place it — in
    which case the caller at least has MAC addresses rather than '?'.
    """
    src = dst = ""
    try:
        from scapy.layers.l2 import Ether, Dot3, LLC, SNAP
        eth = pkt.getlayer(Ether) or pkt.getlayer(Dot3)
        if eth is not None:
            src = getattr(eth, "src", "") or ""
            dst = getattr(eth, "dst", "") or ""
    except Exception:
        eth = None

    # Fall back to reading the header off the wire if scapy gave us nothing.
    if not src and len(raw) >= 14:
        dst = ":".join("%02x" % b for b in raw[0:6])
        src = ":".join("%02x" % b for b in raw[6:12])

    if len(raw) < 14:
        return None

    field = struct.unpack("!H", raw[12:14])[0]

    # <= 1500 means it is a length, not an ethertype: an 802.3 frame with LLC.
    if field <= 1500:
        if len(raw) < 17:
            return ("LLC", "802.3 frame", src, dst)
        dsap, ssap, ctrl = raw[14], raw[15], raw[16]
        name, detail = LLC_SAPS.get(dsap, ("LLC", "DSAP 0x%02x" % dsap))
        if dsap == 0x42:
            return ("STP", _stp_info(raw[17:]), src, dst)
        if dsap == 0xAA and len(raw) >= 22:
            oui = raw[17:20]
            pid = struct.unpack("!H", raw[20:22])[0]
            if oui == b"\x00\x00\x0c" and pid == 0x2000:
                return ("CDP", "Cisco Discovery Protocol", src, dst)
            if oui == b"\x00\x00\x0c" and pid == 0x2004:
                return ("DTP", "Cisco Dynamic Trunking", src, dst)
            return ("SNAP", "OUI %s protocol 0x%04x" % (oui.hex(), pid), src, dst)
        return (name, detail or ("SSAP 0x%02x" % ssap), src, dst)

    known = ETHERTYPES.get(field)
    if known:
        proto, detail = known
        if proto in ("IPv4", "IPv6", "ARP"):
            return None                        # handled by the main decoder
        if proto == "LLDP":
            return ("LLDP", "Link Layer Discovery · " + mac_label(dst), src, dst)
        if proto == "WoL":
            return ("WoL", "Wake-on-LAN magic packet", src, dst)
        return (proto, detail or proto, src, dst)

    return ("OTHER", "ethertype 0x%04x" % field, src, dst)


# ---------------------------------------------------------------------------
# Who owns a packet that no socket can claim
# ---------------------------------------------------------------------------

KERNEL_PROTOS = {"ICMP", "ICMPv6", "IGMP"}
LINK_PROTOS = {"ARP", "STP", "LLDP", "CDP", "DTP", "LLC", "SNAP", "EAPOL",
               "VLAN", "PPPoE", "RARP", "PTP", "LACP", "WoL", "SRP", "Loop",
               "HomePlug", "OSI", "IPX", "NetBIOS"}


def owner_label(proto, dst_mac="", dst_ip=""):
    """
    A truthful stand-in when no process owns the packet.

    Most of what used to show as '-' has no owning process at all: ARP and
    spanning tree are generated below the socket layer, ICMP comes from the
    kernel stack, and broadcast arrives unsolicited. Saying so is more use
    than a dash, and it separates "nothing to attribute" from "we failed to
    attribute", which is the number actually worth improving.
    """
    if proto in KERNEL_PROTOS:
        return "(kernel)"
    if proto in LINK_PROTOS:
        return "(link layer)"
    if dst_mac and (dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
                    or is_multicast_mac(dst_mac)):
        return "(broadcast)"
    if dst_ip.startswith(("224.", "239.", "255.")) or dst_ip.startswith("ff0"):
        return "(broadcast)"
    return "(no socket)"


UNOWNED = {"(kernel)", "(link layer)", "(broadcast)", "(no socket)", "-"}
