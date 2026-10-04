"""
Keeping a VPN's traffic out of the history twice.

With a VPN up, every byte is on the wire twice: the real conversation on the
tunnel adapter (attributed to the program that made it), and the same data
encrypted inside the tunnel on the physical adapter (attributed to the VPN
client, or to nothing). Both are real packets and both belong in the packet
list, but the history is a record of what programs used, and counting both
roughly doubles the machine total and invents a second heavy "program".

`TunnelFilter.skip()` says whether a packet is that outer copy, so the history
can leave it out. It is deliberately narrow: only a packet on a non-tunnel
adapter, while a tunnel adapter is carrying traffic, that looks like the
tunnel's own transport (a VPN port, or a VPN client's process). Split-tunnelled
traffic on the physical adapter is real usage and is kept.
"""
from __future__ import annotations

import re
import time

# Adapter names/descriptions that are tunnels. Matched against both, since the
# dropdown shows descriptions while capture is by name.
TUNNEL_ADAPTER = re.compile(
    r"wintun|wireguard|nordlynx|tap-windows|\btap\b|\btun\b|openvpn|\bvpn\b|"
    r"tailscale|zerotier|anyconnect|globalprotect|pangp|fortinet|forticlient|"
    r"protonvpn|mullvad|\bpia\b|private internet access|cloudflare warp|"
    r"expressvpn|surfshark|windscribe", re.I)

# What a VPN's own transport looks like on the physical adapter.
VPN_PORTS = {500, 1194, 1701, 1723, 4500, 51820}
VPN_PROCESS = re.compile(
    r"openvpn|wireguard|tailscale|nordvpn|nordlynx|protonvpn|mullvad|expressvpn|"
    r"surfshark|windscribe|vpnagent|vpnui|globalprotect|pangps|forti|warp-svc|"
    r"pia-|piavpn|\bvpn", re.I)

# A tunnel adapter counts as "up" if it carried a packet this recently.
ACTIVE_FOR = 60.0


def is_tunnel(name, description="", extra=()):
    text = f"{name or ''} {description or ''}".lower()
    if any(e and e.lower() in text for e in extra):
        return True
    return bool(TUNNEL_ADAPTER.search(text))


class TunnelFilter:
    def __init__(self, describe=None, extra=(), enabled=True):
        # describe(name) -> description, looked up lazily; may be None.
        self._describe = describe
        self.extra = [e for e in (extra or []) if isinstance(e, str)]
        self.enabled = enabled
        self._is = {}               # adapter name -> bool
        self._last = {}             # tunnel adapter -> last packet time
        self.skipped = 0

    def tunnel(self, name):
        v = self._is.get(name)
        if v is None:
            desc = ""
            if self._describe:
                try:
                    desc = self._describe(name) or ""
                except Exception:
                    desc = ""
            v = self._is[name] = is_tunnel(name, desc, self.extra)
        return v

    def skip(self, rec, now=None):
        """True when `rec` is the encrypted outer copy of tunnelled traffic."""
        if not self.enabled:
            return False
        now = time.time() if now is None else now
        iface = rec.get("iface") or ""
        if self.tunnel(iface):
            self._last[iface] = now
            return False
        if not any(now - t < ACTIVE_FOR for t in self._last.values()):
            return False
        out = rec.get("dir") == "out"
        port = rec.get("dport") if out else rec.get("sport")
        if (rec.get("transport") in ("tcp", "udp") and port in VPN_PORTS) \
                or VPN_PROCESS.search(rec.get("process") or ""):
            self.skipped += 1
            return True
        return False
