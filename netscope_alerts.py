# -*- coding: utf-8 -*-
"""
Alert rules — the part that tells you something happened without being asked.

Two families:

*Change* rules notice things that are new: a process using the network for the
first time, a host you have never contacted before, a program crossing a
bandwidth threshold.

*Insecure transport* rules notice things that should not be happening at all:
credentials in the clear, protocols with no encryption, certificates that are
expired or self-signed, DNS going somewhere unexpected.

Every alert is deduplicated by (rule, subject) so one misbehaving connection
does not produce ten thousand identical rows; repeats bump a counter instead.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import threading
import time
from collections import OrderedDict, deque

try:
    from cryptography import x509
    X509_OK = True
except Exception:  # pragma: no cover
    X509_OK = False

MAX_ALERTS = 500
TOAST_MIN_INTERVAL = 6.0        # seconds between desktop notifications

INFO, WARN, HIGH = "info", "warn", "high"

SCAN_WINDOW_SECS = 20.0     # how far back a burst is measured
SCAN_PORT_THRESHOLD = 12   # distinct ports/pairs in the window before it's a scan
# Destinations whose fan-out is ordinary: one web page pulls from dozens of
# hosts on 443 within seconds, which is exactly the shape of a scan.
SCAN_OUT_IGNORE_PORTS = {80, 443}
# How long an outbound UDP (peer, local port) is remembered, so the replies
# coming back to it are recognised as replies rather than probes.
UDP_REPLY_TTL = 120.0
UDP_SENT_MAX = 5000

# Ports whose traffic is unencrypted by definition.
CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP",
    512: "rexec", 513: "rlogin", 514: "rsh", 69: "TFTP",
}

CRED_PATTERNS = [
    # (regex, protocol label, what it caught)
    (re.compile(rb"^USER\s+(\S+)", re.I | re.M), "FTP/POP3", "username"),
    (re.compile(rb"^PASS\s+(\S+)", re.I | re.M), "FTP/POP3", "password"),
    # IMAP commands carry a client tag ("a1 LOGIN rob hunter2"), so allow it.
    (re.compile(rb"^\S{0,12}\s*LOGIN\s+(\S+)\s+(\S+)", re.I | re.M), "IMAP", "credentials"),
    (re.compile(rb"^AUTH\s+LOGIN", re.I | re.M), "SMTP", "auth exchange"),
]

PASSWORD_FIELD = re.compile(
    rb"(^|[&?\r\n])(password|passwd|pwd|pass|user_pass|pw)=([^&\s]{1,64})", re.I)


# What each rule actually compares. An alert that only says what happened
# leaves you reading the source to find out why it fired — which is exactly
# what happened the first time one of these surprised someone.
RULE_WHY = {
    "new_process": "Fires the first time a program uses the network. With "
                   "history attached, 'first time' means first time ever, not "
                   "first time since launch.",
    "new_host": "Fires the first time this machine contacts a remote host. Off "
                "by default — on a busy machine it is very chatty.",
    "threshold": "Fires when one program crosses the bandwidth threshold set "
                 "below, counted per program since NetScope started.",
    "cleartext_creds": "Fires when something that looks like a username, "
                       "password or auth exchange crosses the wire with no "
                       "encryption around it.",
    "cleartext_proto": "Fires on protocols that carry no encryption by "
                       "definition — FTP, Telnet, POP3, IMAP, TFTP and "
                       "friends — regardless of what they are carrying.",
    "cert_problems": "Fires on a TLS certificate that is expired, not yet "
                     "valid, or self-signed.",
    "dns_resolver": "Fires when DNS goes to a server this machine is not "
                    "configured to use. Counted per interface, and checked "
                    "against the resolvers the OS reports, so a second "
                    "adapter's own resolver is not suspicious.",
    "port_scan": "Fires when one remote host tries to open connections to "
                 "many distinct local ports in a short window — the "
                 "signature of a port scan, not of any legitimate protocol. "
                 "Only connection attempts count (a TCP SYN, or UDP that is "
                 "not a reply to something this machine sent), so replies to "
                 "your own traffic never look like probes. Also fires the "
                 "other direction: one local process opening connections to "
                 "many distinct host/port pairs at once, which is what a "
                 "worm or a scanner looks like from here. Web ports (80, 443) "
                 "are left out of that count — a single page load reaches "
                 "dozens of hosts on them.",
    "dhcp_rogue_server": "Fires when a DHCP OFFER or ACK arrives from a "
                         "server this machine has not seen answering before. "
                         "Anyone on the same broadcast domain can run a "
                         "second DHCP server, and a client that takes a "
                         "lease from it can be handed a rogue gateway or DNS "
                         "server without anything else on the wire looking "
                         "unusual.",
    "arp_spoof": "Fires when the MAC address answering for an IP this "
                 "machine has already seen changes. That is how ARP cache "
                 "poisoning — the usual way to sit in the middle of a LAN "
                 "conversation — looks on the wire, though a NIC swap, a VM "
                 "restarting with a new virtual MAC, or a DHCP lease moving "
                 "to a different device can cause the same thing "
                 "legitimately.",
    "rogue_ra": "Fires when an IPv6 Router Advertisement arrives from a "
               "router this machine has not seen on this adapter before. A "
               "fake RA can redirect IPv6 traffic through an attacker's "
               "machine or push a rogue DNS server via RDNSS without "
               "touching DHCP at all — but a second router kept for "
               "failover, or a new ISP gateway after a router swap, "
               "triggers this too.",
}


def _now():
    return time.time()


# ---------------------------------------------------------------------------
# What the operating system thinks your resolvers are
# ---------------------------------------------------------------------------
#
# The DNS rule used to be purely statistical: count destination addresses,
# complain about the minority one. That is wrong on any machine with more than
# one live adapter, which since v1.4.0 is the normal case here — Windows'
# smart multi-homed name resolution deliberately sends the same query out
# every interface, each to its own configured resolver, so a laptop on Wi-Fi
# and Ethernet at once tripped the rule forever.
#
# Asking the OS which resolvers are *configured* turns a guess into a fact: a
# server in that list is expected by definition, however rarely it is used, and
# a server outside it is worth a look however ordinary it seems.

DNS_REFRESH = 300.0        # seconds between re-reads; config changes are rare

_PS_DNS = (
    "@(Get-DnsClientServerAddress -AddressFamily IPv4 |"
    " Select-Object InterfaceAlias,ServerAddresses) |"
    " ConvertTo-Json -Compress -Depth 3"
)


def configured_resolvers():
    """
    Return (all_servers, by_interface) as read from the OS, or (None, None)
    if it cannot be determined — the caller then falls back to statistics.

    by_interface is keyed on the OS's name for the adapter, which usually but
    not always matches the capture interface name, so the flat set is what the
    rule actually leans on.
    """
    if os.name == "nt":
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_DNS],
                timeout=20, capture_output=True, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            data = json.loads((p.stdout or "").strip() or "null")
        except Exception:
            return None, None
        if data is None:
            return None, None
        if isinstance(data, dict):          # a single adapter is not an array
            data = [data]
        by_iface, everything = {}, set()
        for row in data:
            if not isinstance(row, dict):
                continue
            servers = row.get("ServerAddresses") or []
            if isinstance(servers, str):
                servers = [servers]
            servers = [s for s in servers if s]
            if not servers:
                continue                    # adapters with no resolver tell us nothing
            by_iface[str(row.get("InterfaceAlias") or "")] = set(servers)
            everything.update(servers)
        return (everything, by_iface) if everything else (None, None)

    # POSIX — for the headless build. resolv.conf is the whole story unless
    # systemd-resolved is stubbing, in which case 127.0.0.53 is the honest
    # answer for what this machine queries.
    try:
        found = set()
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        found.add(parts[1])
        return (found, {"": found}) if found else (None, None)
    except Exception:
        return None, None


class DesktopNotifier:
    """
    Windows toast notifications, driven through PowerShell's WinRT bindings.

    No extra packages: Windows 10 and 11 both have the toast API available to
    PowerShell, and borrowing PowerShell's own AppId means the notification is
    attributable and shows in Action Center. Failures are silent by design —
    a monitoring tool should not fall over because a toast did not render.
    """

    APPID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

    def __init__(self, enabled=False):
        self.enabled = enabled
        self.available = None
        self._last = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _ps_quote(s):
        return str(s).replace("'", "''")[:200]

    def notify(self, title, message):
        import os
        if not self.enabled or os.name != "nt":
            return
        with self._lock:
            if _now() - self._last < TOAST_MIN_INTERVAL:
                return
            self._last = _now()
        threading.Thread(target=self._send, args=(title, message),
                         daemon=True, name="toast").start()

    def _send(self, title, message):
        script = (
            "[void][Windows.UI.Notifications.ToastNotificationManager,"
            "Windows.UI.Notifications,ContentType=WindowsRuntime];"
            "[void][Windows.UI.Notifications.ToastNotification,"
            "Windows.UI.Notifications,ContentType=WindowsRuntime];"
            "[void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,"
            "ContentType=WindowsRuntime];"
            "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            "$n=$t.GetElementsByTagName('text');"
            f"$n.Item(0).AppendChild($t.CreateTextNode('{self._ps_quote(title)}'))|Out-Null;"
            f"$n.Item(1).AppendChild($t.CreateTextNode('{self._ps_quote(message)}'))|Out-Null;"
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
            f"'{self.APPID}').Show("
            "[Windows.UI.Notifications.ToastNotification]::new($t))"
        )
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=12, capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.available = True
        except Exception:
            self.available = False


class AlertEngine:
    def __init__(self, notifier: DesktopNotifier = None, history=None):
        self._lock = threading.Lock()
        self._alerts = OrderedDict()      # key -> alert
        self._next = 0
        self.notifier = notifier or DesktopNotifier(enabled=False)
        # With history attached, "first seen" means the first time ever rather
        # than the first time since launch — which is what makes the rule
        # worth having.
        self.history = history

        self.seen_processes = set()
        self.seen_hosts = set()
        # Per interface, so one adapter's normal resolver is never judged
        # against another's: {iface: {server: count}}.
        self.resolvers = {}
        self.dns_configured = None      # set of servers the OS is set to use
        self.dns_by_iface = {}
        self._dns_read = 0.0
        self.process_bytes = {}
        self._threshold_fired = set()
        self._scan_inbound = {}     # remote peer -> deque[(ts, dport)]
        self._scan_outbound = {}    # process -> deque[(ts, (peer, dport))]
        self._udp_sent = {}         # (peer, local port) -> last outbound ts
        self.seen_dhcp_servers = set()
        # (iface, ip) -> mac last seen claiming it, so a later ARP claiming
        # the same IP with a different MAC can be told apart from the first
        # sighting. Per adapter, same reasoning as the flow key: a VPN or a
        # second NIC can legitimately show the same private IP twice.
        self.arp_bindings = {}
        # iface -> set of router IPv6 addresses seen advertising themselves.
        self.seen_routers = {}
        # Muted (rule, subject) pairs -> expiry timestamp, or None for
        # indefinitely. Turning a whole rule off is the only control that
        # existed, and it is the wrong grain: a rule is usually right to look
        # and wrong about one subject. Silencing the rule to silence the
        # subject means going blind to everything else it would have caught.
        self.mutes = {}

        # Rule switches, all flippable from the dashboard.
        self.rules = {
            "new_process": True,
            "new_host": False,          # chatty on a busy machine; opt in
            "threshold": True,
            "cleartext_creds": True,
            "cleartext_proto": True,
            "cert_problems": True,
            "dns_resolver": True,
            "port_scan": True,
            "dhcp_rogue_server": True,
            "arp_spoof": True,
            "rogue_ra": True,
        }
        self.threshold_mb = 500
        # Rule switches, the threshold and the toast toggle used to live only
        # in memory. Anyone running this from a logon task had their tuning
        # silently reset at every reboot — the one place it matters most,
        # because that is exactly the setup you stop watching by hand.
        self._settings_sink = None
        # Give the machine a moment to settle before "first seen" means anything.
        self.warmup_until = _now() + 5.0
        self.started = _now()
        # On a brand-new history database everything is "new". That first run
        # records a baseline instead of alerting on every program at once.
        self.baselining = bool(history is not None and
                               getattr(history, "was_empty", False))

        # Read the OS resolver list off the capture path — PowerShell takes
        # the better part of a second to start and this must never block a
        # packet.
        self.refresh_dns_config(background=True)

    # -- persistence ---------------------------------------------------------

    def attach_settings(self, load, save):
        """
        Hand the engine somewhere to keep its configuration.

        Injected rather than imported so the alert rules stay testable without
        a settings file, and so a --no-history run simply has nowhere to write
        instead of needing a special case at every call site.
        """
        self._settings_sink = save
        try:
            stored = load() or {}
        except Exception:
            return
        for k, v in (stored.get("alert_rules") or {}).items():
            if k in self.rules:
                self.rules[k] = bool(v)
        try:
            if stored.get("alert_threshold_mb"):
                self.threshold_mb = max(1, int(stored["alert_threshold_mb"]))
        except (TypeError, ValueError):
            pass
        if "alert_toasts" in stored:
            self.notifier.enabled = bool(stored["alert_toasts"])
        for m in stored.get("alert_mutes") or []:
            try:
                self.mutes[(m["rule"], m["subject"])] = m.get("until")
            except (TypeError, KeyError):
                pass
        self._drop_expired_mutes()

    def _persist(self, key, value):
        if self._settings_sink is None:
            return
        try:
            self._settings_sink(key, value)
        except Exception:
            pass                    # settings are a convenience, never load-bearing

    def save_config(self):
        self._persist("alert_rules", dict(self.rules))
        self._persist("alert_threshold_mb", int(self.threshold_mb))
        self._persist("alert_toasts", bool(self.notifier.enabled))

    # -- OS resolver configuration ------------------------------------------

    def refresh_dns_config(self, background=False):
        """Re-read the machine's configured resolvers. Never raises."""
        if background:
            threading.Thread(target=self.refresh_dns_config, daemon=True,
                             name="dnscfg").start()
            return
        self._dns_read = _now()
        try:
            everything, by_iface = configured_resolvers()
        except Exception:
            everything, by_iface = None, None
        if everything:
            self.dns_configured = everything
            self.dns_by_iface = by_iface or {}

    def _maybe_refresh_dns(self):
        if _now() - self._dns_read > DNS_REFRESH:
            self.refresh_dns_config(background=True)

    # -- muting --------------------------------------------------------------

    @staticmethod
    def subject_of(key):
        """
        The thing an alert is about, as a string.

        Rules key themselves on tuples of varying shape — ("dns_alt", iface,
        server), a process name, a host. The last element is the subject in
        every case, which is what someone means by "this one is fine".
        """
        if isinstance(key, tuple):
            return str(key[-1])
        return str(key)

    def _drop_expired_mutes(self):
        now = _now()
        for k, until in list(self.mutes.items()):
            if until is not None and until <= now:
                self.mutes.pop(k, None)

    def is_muted(self, rule, subject):
        until = self.mutes.get((rule, subject), False)
        if until is False:
            return False
        if until is not None and until <= _now():
            self.mutes.pop((rule, subject), None)
            return False
        return True

    def mute(self, rule, subject, minutes=None):
        """Silence one subject of one rule. minutes=None means indefinitely."""
        until = (_now() + minutes * 60.0) if minutes else None
        self.mutes[(rule, str(subject))] = until
        with self._lock:
            # Clear what is already on screen for that subject, otherwise
            # muting appears to do nothing until the alert ages out.
            for k, a in list(self._alerts.items()):
                if a["rule"] == rule and self.subject_of(k) == str(subject):
                    self._alerts.pop(k, None)
        self._save_mutes()
        return until

    def unmute(self, rule, subject):
        self.mutes.pop((rule, str(subject)), None)
        self._save_mutes()

    def list_mutes(self):
        self._drop_expired_mutes()
        return [{"rule": r, "subject": s, "until": u}
                for (r, s), u in sorted(self.mutes.items())]

    def _save_mutes(self):
        self._persist("alert_mutes", self.list_mutes())

    def dismiss(self, alert_id):
        """Drop one alert without touching the rest."""
        with self._lock:
            for k, a in list(self._alerts.items()):
                if a["id"] == alert_id:
                    self._alerts.pop(k, None)
                    return True
        return False

    # -- alert plumbing -----------------------------------------------------

    def _fire(self, key, severity, rule, title, detail, rec=None):
        if self.is_muted(rule, self.subject_of(key)):
            return None
        with self._lock:
            existing = self._alerts.get(key)
            if existing:
                existing["count"] += 1
                existing["last"] = _now()
                return None
            self._next += 1
            alert = {
                "id": self._next,
                "ts": _now(),
                "last": _now(),
                "count": 1,
                "severity": severity,
                "rule": rule,
                # What this alert is about, so the dashboard can offer to mute
                # this one subject rather than the whole rule.
                "subject": self.subject_of(key),
                "title": title,
                "detail": detail,
                "process": (rec or {}).get("process", ""),
                "peer": (rec or {}).get("remote", ""),
                "seq": (rec or {}).get("seq"),
                "stream": (rec or {}).get("stream"),
            }
            self._alerts[key] = alert
            while len(self._alerts) > MAX_ALERTS:
                self._alerts.popitem(last=False)
        if self.history is not None:
            self.history.record_alert(alert)
        if severity in (WARN, HIGH):
            self.notifier.notify(f"NetScope: {title}", detail)
        return alert

    def list(self):
        with self._lock:
            return list(reversed(self._alerts.values()))

    def counts(self):
        with self._lock:
            out = {"total": len(self._alerts), "high": 0, "warn": 0, "info": 0}
            for a in self._alerts.values():
                out[a["severity"]] += 1
            return out

    def clear(self):
        with self._lock:
            self._alerts.clear()
        self.seen_processes.clear()
        self.seen_hosts.clear()
        self.process_bytes.clear()
        self._threshold_fired.clear()
        self._scan_inbound.clear()
        self._scan_outbound.clear()
        self._udp_sent.clear()
        self.resolvers.clear()
        self.seen_dhcp_servers.clear()
        self.arp_bindings.clear()
        self.seen_routers.clear()
        # Mutes deliberately survive: Clear means "I have read these", not
        # "forget everything I told you to ignore".
        self.warmup_until = _now() + 5.0
        # Clearing alerts is also the natural moment to re-read the OS config:
        # it is usually what you do after changing something.
        self.refresh_dns_config(background=True)

    # -- the rules ----------------------------------------------------------

    def inspect(self, rec, payload: bytes):
        """Run every enabled rule over one packet. Cheap checks first."""
        try:
            self._change_rules(rec)
            if payload:
                self._transport_rules(rec, payload)
            self._dns_rule(rec)
            self._scan_rule(rec)
            self._dhcp_rule(rec)
            self._arp_rule(rec)
            self._ra_rule(rec)
        except Exception:
            pass

    def _change_rules(self, rec):
        proc = rec.get("process") or "-"
        size = rec.get("length", 0)

        if proc != "-":
            if self.rules["new_process"] and proc not in self.seen_processes:
                self.seen_processes.add(proc)
                ever = (self.history.known_process(proc)
                        if self.history is not None else True)
                if not ever and self.baselining:
                    self.history.note_process(proc)   # record, stay quiet
                elif not ever:
                    # Genuinely never seen before on this machine — worth a
                    # warning rather than a note.
                    self.history.note_process(proc)
                    self._fire(("new_process", proc), WARN, "new_process",
                               "New program on the network",
                               f"{proc} has never used the network on this "
                               f"machine before (now talking to "
                               f"{rec.get('rhost') or rec.get('remote','')})", rec)
                elif _now() > self.warmup_until:
                    self._fire(("new_process", proc), INFO, "new_process",
                               "Program started using the network",
                               f"{proc} used the network for the first time "
                               f"this session ({rec.get('remote','')})", rec)
            else:
                self.seen_processes.add(proc)

            total = self.process_bytes.get(proc, 0) + size
            self.process_bytes[proc] = total
            if self.rules["threshold"]:
                limit = self.threshold_mb * 1024 * 1024
                if total > limit and proc not in self._threshold_fired:
                    self._threshold_fired.add(proc)
                    self._fire(("threshold", proc), WARN, "threshold",
                               "Bandwidth threshold crossed",
                               f"{proc} has moved over {self.threshold_mb} MB "
                               f"this session", rec)

        if self.rules["new_host"] and rec.get("dir") == "out":
            host = rec.get("rhost") or rec.get("remote")
            if host and host not in self.seen_hosts:
                self.seen_hosts.add(host)
                ever = (self.history.known_host(host)
                        if self.history is not None else True)
                if not ever and self.baselining:
                    self.history.note_host(host)      # record, stay quiet
                elif not ever:
                    self.history.note_host(host)
                    self._fire(("new_host", host), WARN, "new_host",
                               "First contact with a host",
                               f"{proc} connected to {host} — this machine has "
                               f"never contacted it before", rec)
                elif _now() > self.warmup_until:
                    self._fire(("new_host", host), INFO, "new_host",
                               "Host contacted again",
                               f"{proc} connected to {host}, first time this "
                               f"session", rec)
            elif host:
                self.seen_hosts.add(host)

    def _transport_rules(self, rec, payload):
        sport, dport = rec.get("sport"), rec.get("dport")
        ports = {p for p in (sport, dport) if p}
        proc = rec.get("process", "-")
        peer = rec.get("remote", "")

        # 1. Protocols with no encryption at all.
        if self.rules["cleartext_proto"]:
            for port in ports & set(CLEARTEXT_PORTS):
                name = CLEARTEXT_PORTS[port]
                self._fire(("cleartext", name, peer), WARN, "cleartext_proto",
                           f"Unencrypted {name}",
                           f"{proc} is talking {name} to {peer} in the clear — "
                           f"anything sent over it is readable on the wire", rec)

        if not self.rules["cleartext_creds"]:
            return

        head = payload[:2048]

        # 2. HTTP Basic auth — the password is base64, which is not encryption.
        m = re.search(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", head, re.I)
        if m and (ports & {80, 8080, 8000}):
            try:
                user = base64.b64decode(m.group(1)).split(b":")[0].decode(
                    "latin-1", "replace")
            except (binascii.Error, ValueError):
                user = "?"
            self._fire(("basic_auth", user, peer), HIGH, "cleartext_creds",
                       "Password sent in the clear",
                       f"{proc} sent HTTP Basic credentials for '{user}' to "
                       f"{peer} over unencrypted HTTP", rec)

        # 3. A login form posted over plain HTTP.
        if 80 in ports and head[:5] in (b"POST ", b"PUT /"):
            pm = PASSWORD_FIELD.search(head)
            if pm:
                field = pm.group(2).decode("latin-1", "replace")
                self._fire(("form_pw", peer), HIGH, "cleartext_creds",
                           "Password field posted over HTTP",
                           f"{proc} posted a '{field}' field to {peer} without "
                           f"TLS — the value is visible on the wire", rec)

        # 4. Mail and file-transfer logins.
        if ports & {21, 110, 143, 25, 587}:
            for pattern, proto, what in CRED_PATTERNS:
                cm = pattern.search(head)
                if cm:
                    self._fire(("mailcred", proto, what, peer), HIGH,
                               "cleartext_creds",
                               f"Unencrypted {proto} {what}",
                               f"{proc} sent {proto} {what} to {peer} in "
                               f"plaintext", rec)
                    break

        # 5. Certificate problems, where the certificate is visible at all.
        if self.rules["cert_problems"] and X509_OK and 443 in ports:
            self._cert_rule(rec, payload, peer, proc)

    def _cert_rule(self, rec, payload, peer, proc):
        """
        Inspect a server certificate.

        Only possible on TLS 1.2 and below — TLS 1.3 encrypts the Certificate
        message, so on a modern connection there is nothing here to look at.
        Also only sees certificates small enough to land in a single segment.
        """
        if len(payload) < 20 or payload[0] != 0x16:
            return
        if payload[5] != 0x0B:                    # handshake type 11: Certificate
            return
        try:
            list_len = int.from_bytes(payload[9:12], "big")
            cert_len = int.from_bytes(payload[12:15], "big")
            if cert_len <= 0 or cert_len > list_len or 15 + cert_len > len(payload):
                return                            # spans segments; skip quietly
            der = payload[15:15 + cert_len]
            cert = x509.load_der_x509_certificate(der)
        except Exception:
            return

        try:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            import datetime
            now = datetime.datetime.now(getattr(not_after, "tzinfo", None))
            days = (not_after - now).days
        except Exception:
            return

        if days < 0:
            self._fire(("cert_expired", peer), HIGH, "cert_problems",
                       "Expired certificate",
                       f"{peer} presented a certificate that expired "
                       f"{abs(days)} days ago ({subject[:80]})", rec)
        elif days < 14:
            self._fire(("cert_expiring", peer), WARN, "cert_problems",
                       "Certificate expiring soon",
                       f"{peer} has a certificate expiring in {days} days "
                       f"({subject[:80]})", rec)
        if issuer == subject:
            self._fire(("cert_selfsigned", peer), WARN, "cert_problems",
                       "Self-signed certificate",
                       f"{peer} presented a self-signed certificate "
                       f"({subject[:80]})", rec)
        try:
            algo = cert.signature_hash_algorithm.name
            if algo in ("md5", "sha1"):
                self._fire(("cert_weak", peer), WARN, "cert_problems",
                           "Weak certificate signature",
                           f"{peer} uses a {algo.upper()}-signed certificate", rec)
        except Exception:
            pass

    def _dns_rule(self, rec):
        """
        Flag DNS going somewhere the machine is not configured to send it.

        Counting is per interface. A multi-homed machine has one resolver per
        adapter and queries all of them by design; judging every adapter
        against a single machine-wide favourite made that normal arrangement
        look like an incident. The interface is also the first thing you want
        to know when an alert does fire, so it goes in the message.
        """
        if not self.rules["dns_resolver"] or rec.get("proto") != "DNS":
            return
        if rec.get("dir") != "out":
            return
        server = rec.get("remote")
        if not server:
            return
        self._maybe_refresh_dns()

        iface = rec.get("iface") or ""
        seen = self.resolvers.setdefault(iface, {})
        seen[server] = seen.get(server, 0) + 1

        where = f" on {iface}" if iface else ""
        proc = rec.get("process") or "-"

        # Preferred path: the OS told us what it is configured to use, so a
        # server outside that list is a fact rather than an inference — and a
        # configured secondary resolver stops being an alert.
        if self.dns_configured:
            if server in self.dns_configured:
                return
            if seen[server] < 3:
                return              # a stray packet is not a pattern
            expected = self.dns_by_iface.get(iface)
            expected = (", ".join(sorted(expected)) if expected
                        else ", ".join(sorted(self.dns_configured)))
            self._fire(("dns_alt", iface, server), WARN, "dns_resolver",
                       "DNS to an unconfigured resolver",
                       f"{proc} is querying {server}{where}, which is not a "
                       f"resolver this machine is set to use (configured: "
                       f"{expected})", rec)
            return

        # Fallback: no OS answer, so fall back to statistics — but per
        # interface, which is the part that was wrong before.
        if len(seen) < 2:
            return
        primary = max(seen, key=seen.get)
        if seen[primary] < 20 or server == primary:
            return
        if seen[server] > 3:
            self._fire(("dns_alt", iface, server), WARN, "dns_resolver",
                       "DNS to an unexpected resolver",
                       f"{proc} is querying {server}{where}, while most DNS "
                       f"on that interface goes to {primary}", rec)

    def _scan_rule(self, rec):
        """
        Flag a burst of distinct ports touched in a short window, in either
        direction: a remote host probing many local ports (an inbound scan),
        or a local process reaching out to many distinct host/port pairs at
        once (a scan or worm-like fan-out). Each burst fires once — the
        window is cleared on fire rather than left to alert again on every
        packet that follows.

        Only connection *attempts* count. Counting every packet made replies
        look like probes: each DNS answer from the router arrives on a fresh
        random local port, so a dozen lookups read as a port scan from the
        router, and one page load reaching a dozen CDN hosts read as a worm.
        """
        transport = rec.get("transport")
        now = rec.get("ts") or _now()
        inbound = rec.get("dir") == "in"
        peer = rec.get("remote") or rec.get("rhost")
        if transport == "udp" and not inbound and peer and rec.get("sport"):
            # Remembered even with the rule off, so switching it on later
            # does not mistake replies already in flight for probes.
            self._note_udp_sent(peer, rec["sport"], now)

        if not self.rules["port_scan"]:
            return
        dport = rec.get("dport")
        if not dport or transport not in ("tcp", "udp"):
            return
        if transport == "tcp":
            flags = ((rec.get("decoded") or {}).get("tcp") or {}).get("flags") or ""
            if "S" not in flags or "A" in flags:
                return              # not an opening SYN (or flags unknown)
        elif inbound:
            last = self._udp_sent.get((peer, dport))
            if last is not None and now - last <= UDP_REPLY_TTL:
                return              # a reply to something this machine sent

        if inbound:
            if not peer:
                return
            win = self._scan_inbound.setdefault(peer, deque())
            win.append((now, dport))
            self._prune_window(win, now)
            distinct = {p for _, p in win}
            if len(distinct) >= SCAN_PORT_THRESHOLD:
                self._fire(("port_scan_in", peer), HIGH, "port_scan",
                           f"Possible port scan from {peer}",
                           f"{peer} has touched {len(distinct)} distinct "
                           f"ports on this machine in the last "
                           f"{int(SCAN_WINDOW_SECS)}s", rec)
                win.clear()
        else:
            proc = rec.get("process") or "-"
            if proc == "-" or not peer or dport in SCAN_OUT_IGNORE_PORTS:
                return
            win = self._scan_outbound.setdefault(proc, deque())
            win.append((now, (peer, dport)))
            self._prune_window(win, now)
            distinct = {pair for _, pair in win}
            if len(distinct) >= SCAN_PORT_THRESHOLD:
                self._fire(("port_scan_out", proc), HIGH, "port_scan",
                           f"{proc} is contacting many hosts/ports at once",
                           f"{proc} has reached {len(distinct)} distinct "
                           f"host/port pairs in the last "
                           f"{int(SCAN_WINDOW_SECS)}s — unusual unless this "
                           f"is a scanner you run on purpose", rec)
                win.clear()

    def _note_udp_sent(self, peer, sport, now):
        self._udp_sent[(peer, sport)] = now
        if len(self._udp_sent) > UDP_SENT_MAX:
            for k, ts in list(self._udp_sent.items()):
                if now - ts > UDP_REPLY_TTL:
                    del self._udp_sent[k]
            # Still full of live entries: drop the oldest half rather than
            # grow without bound. Worst case a reply is counted as a probe.
            if len(self._udp_sent) > UDP_SENT_MAX:
                keep = sorted(self._udp_sent.items(), key=lambda kv: kv[1])
                self._udp_sent = dict(keep[len(keep) // 2:])

    @staticmethod
    def _prune_window(win, now):
        while win and now - win[0][0] > SCAN_WINDOW_SECS:
            win.popleft()

    def _dhcp_rule(self, rec):
        """
        Flag a DHCP server this machine has not seen answering before.

        The first server ever seen becomes the baseline rather than an alert
        — otherwise the very first lease on a fresh install would fire this
        on the router doing its ordinary job. Every server after that is
        either the same one again or a second one that should not exist on a
        normal network.
        """
        if not self.rules["dhcp_rogue_server"]:
            return
        dhcp = (rec.get("decoded") or {}).get("dhcp")
        if not dhcp or dhcp.get("msg_type") not in ("OFFER", "ACK"):
            return
        server = dhcp.get("server_id")
        if not server or server in self.seen_dhcp_servers:
            return
        first = not self.seen_dhcp_servers
        self.seen_dhcp_servers.add(server)
        if first:
            return
        self._fire(("dhcp_server", server), HIGH, "dhcp_rogue_server",
                   "Unexpected DHCP server",
                   f"{server} answered a DHCP request — this machine has "
                   f"seen leases from {len(self.seen_dhcp_servers) - 1} other "
                   f"server(s) before now. A second DHCP server on this "
                   f"network can hand out a rogue gateway or DNS server.", rec)

    def _arp_rule(self, rec):
        """
        Flag a MAC address change for an IP this machine has already seen
        claimed on this adapter.

        The first sighting of (iface, ip) becomes the baseline rather than an
        alert, same reasoning as the DHCP rule: otherwise the very first ARP
        packet for every host on the network would fire this. Tracked per
        adapter, not just per IP, because a VPN or a second NIC can put the
        same private address on two interfaces at once without anything
        being wrong.
        """
        if not self.rules["arp_spoof"]:
            return
        arp = (rec.get("decoded") or {}).get("arp")
        if not arp:
            return
        ip = arp.get("sender_ip")
        mac = arp.get("sender_mac")
        if not ip or not mac or ip == "0.0.0.0":
            return
        key = (rec.get("iface") or "", ip)
        seen = self.arp_bindings.get(key)
        if seen is None:
            self.arp_bindings[key] = mac
            return
        if seen == mac:
            return
        self.arp_bindings[key] = mac
        self._fire(("arp_spoof", key[0], ip), HIGH, "arp_spoof",
                   "ARP binding changed",
                   f"{ip} was at {seen}, is now claimed by {mac} — this is "
                   f"how ARP cache poisoning (a man-in-the-middle on this "
                   f"LAN) looks on the wire. Could also be a NIC swap, a VM "
                   f"restarting with a new MAC, or a device getting a new "
                   f"one from DHCP.", rec)

    def _ra_rule(self, rec):
        """
        Flag an IPv6 Router Advertisement from a router this machine has not
        seen on this adapter before.

        Same "first sighting is the baseline" shape as the DHCP and ARP
        rules, and tracked per adapter for the same reason as ARP: two NICs
        on two networks each have their own legitimate router, and without
        the adapter in the key a second interface would look like a rogue
        one from the first packet it ever sends.
        """
        if not self.rules["rogue_ra"]:
            return
        ra = (rec.get("decoded") or {}).get("ra")
        if not ra:
            return
        router = ra.get("router")
        if not router:
            return
        iface = rec.get("iface") or ""
        routers = self.seen_routers.setdefault(iface, set())
        if router in routers:
            return
        first = not routers
        routers.add(router)
        if first:
            return
        detail = f"{router} is advertising itself as a router — this " \
                 f"machine has seen {len(routers) - 1} other router(s) " \
                 f"on this adapter before now."
        if ra.get("rdnss"):
            servers = ", ".join(d["server"] for d in ra["rdnss"])
            detail += f" It is also pushing DNS servers via RDNSS: {servers}."
        detail += (" A second router on this network can redirect IPv6 "
                   "traffic through itself, or a legitimate second router "
                   "kept for failover can look like this too.")
        self._fire(("rogue_ra", iface, router), HIGH, "rogue_ra",
                   "Unexpected IPv6 router", detail, rec)
