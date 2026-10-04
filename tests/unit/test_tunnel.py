import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_tunnel as TN

fails = []
def check(n, c, extra=""):
    print(("PASS  " + n) if c else ("FAIL  " + n + "  -- " + str(extra)))
    if not c: fails.append(n)

# ---- which adapters are tunnels ----------------------------------------------
for name, desc, want in [
        ("Ethernet", "Intel(R) Ethernet Connection I219-V", False),
        ("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", False),
        ("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", False),
        ("PIA", "PIA OpenVPN WinTUN Adapter", True),
        ("Local Area Connection", "TAP-Windows Adapter V9", True),
        ("WireGuard Tunnel", "", True),
        ("Tailscale", "Tailscale Tunnel", True)]:
    check(f"{name} / {desc or '-'} -> {want}", TN.is_tunnel(name, desc) is want)
check("a user-supplied name is honoured",
      TN.is_tunnel("Ethernet 3", "Acme Gizmo", extra=["gizmo"]))

# ---- what is skipped ----------------------------------------------------------
def rec(iface, process="-", dport=443, sport=50000, out=True, transport="udp"):
    return {"iface": iface, "process": process, "dport": dport, "sport": sport,
            "dir": "out" if out else "in", "transport": transport}

f = TN.TunnelFilter(describe=lambda n: {"PIA": "PIA OpenVPN WinTUN Adapter"}.get(n, "Intel Ethernet"))
outer = rec("Ethernet", "openvpn.exe", dport=1194)
check("nothing is skipped before a tunnel has carried traffic", not f.skip(outer, now=100))
check("a packet on the tunnel adapter is kept", not f.skip(rec("PIA", "chrome.exe"), now=101))
check("...and then its outer copy is skipped", f.skip(outer, now=102))
check("an inbound outer copy is skipped too",
      f.skip(rec("Ethernet", "-", sport=51820, out=False), now=102))
check("a VPN client's process is skipped on any port",
      f.skip(rec("Ethernet", "NordVPN.exe", dport=443, transport="tcp"), now=102))
check("split-tunnelled traffic on the physical adapter is kept",
      not f.skip(rec("Ethernet", "chrome.exe", dport=443, transport="tcp"), now=102))
check("a port that only looks like a VPN's, on the wrong transport, is kept",
      not f.skip(rec("Ethernet", "x.exe", dport=1194, transport="icmp"), now=102))
check("when the tunnel goes quiet, the outer copy is counted again",
      not f.skip(outer, now=101 + TN.ACTIVE_FOR + 5))
check("skips are counted", f.skipped == 3, f.skipped)

off = TN.TunnelFilter(describe=lambda n: "WinTUN", enabled=False)
off.skip(rec("PIA"), now=1)
check("disabled: nothing is ever skipped", not off.skip(outer, now=2))

bad = TN.TunnelFilter(describe=lambda n: 1 / 0)
check("a failing description lookup does not raise", bad.skip(outer, now=1) is False)

sys.exit(1 if fails else 0)
