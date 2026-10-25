# -*- coding: utf-8 -*-
"""
Blocking a host or a program, by way of Windows Firewall.

NetScope captures a copy of each packet through Npcap and cannot drop the
original, so a block has to be made by the OS. Each block becomes one or two
firewall rules named ``NetScope-block-<id>-out`` / ``-in``. The list lives in
the settings file and is checked against the firewall when shown, so a rule
someone deleted in wf.msc reads "missing" instead of "blocked", and a rule
whose entry was lost (a wiped settings file) is listed as unknown instead of
staying in force unseen.

Nothing here parses ``netsh`` text, which is localized: it only looks at exit
codes, and reads rule names back through PowerShell, whose output is not.

A firewall rule only stops new connections. One already open when the rule
goes in keeps working, so a block also ends the matching open TCP connections
(``drop_connections``). Windows can only do that for IPv4 TCP; anything else
stops when it next opens a connection.

The firewall knows addresses, not names, so a block by host name is a rule on
the addresses the name has been seen to have, kept up to date from the DNS
answers NetScope captures (``Blocker.note_dns``).
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time

try:
    import psutil
except Exception:
    psutil = None

IS_WINDOWS = os.name == "nt"

RULE_PREFIX = "NetScope-block-"
RULE_RE = re.compile(r"^" + re.escape(RULE_PREFIX) + r"([0-9a-f]{8})-(out|in)$")
ID_RE = re.compile(r"^[0-9a-f]{8}$")
MAX_BLOCKS = 200
VERIFY_TTL = 15.0
# Addresses one name block may collect. A CDN name can rotate through
# hundreds; past this the rule stops growing, and the Blocked list says so.
MAX_NAME_IPS = 256
NAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")

# Blocking one of these cuts off Windows itself, not one program: svchost
# hosts dozens of services, and the rest are the session and security core.
PROTECTED_PROGRAMS = {
    "svchost.exe", "system", "lsass.exe", "services.exe", "wininit.exe",
    "csrss.exe", "winlogon.exe", "smss.exe", "(system)",
}


class BlockError(Exception):
    """A refusal that is worth showing to the person who asked."""


def clean_name(text):
    """A lower-case host name with no trailing dot, or BlockError."""
    n = str(text or "").strip().rstrip(".").lower()
    is_ip = True
    try:
        ipaddress.ip_address(n.split("%")[0])
    except ValueError:
        is_ip = False
    if is_ip:
        raise BlockError("That is an address; block it as a host.")
    if not NAME_RE.match(n):
        raise BlockError("That is not a host name.")
    return n


def direction(entry):
    """in, out or both. Entries from before 1.35 have no `dir`: a program
    block was outbound, a host block both ways unless it named a port."""
    d = entry.get("dir")
    if d in ("in", "out", "both"):
        return d
    if entry.get("kind") == "program" or entry.get("port"):
        return "out"
    return "both"


def _port(v):
    try:
        p = int(v)
    except (TypeError, ValueError):
        p = 0
    if not 1 <= p <= 65535:
        raise BlockError("That is not a port number.")
    return p


def _proto(v):
    return "UDP" if str(v).upper() == "UDP" else "TCP"


# -- ending open connections ---------------------------------------------------

def connections_to_drop(entry, conns, exe_of):
    """
    The open connections a new block should end.

    conns   dicts with pid, status, lport, rip, rport: IPv4 TCP only, the one
            kind Windows lets anyone end from outside the program
    exe_of  pid -> that process's exe path, or ""

    A connection is inbound when its local port is one something here listens
    on; an inbound-only block leaves this machine's own connections alone, and
    an outbound one (every program block before 1.35) leaves its servers alone.
    """
    listening = {c["lport"] for c in conns if c["status"] == "LISTEN"}
    d, kind = direction(entry), entry.get("kind")
    proto, port, lport = entry.get("proto", "TCP"), entry.get("port"), entry.get("lport")
    if (port or lport) and proto != "TCP":
        return []
    ips = set(entry.get("ips") or ()) if kind == "name" else {entry.get("target")}
    target = os.path.normcase(entry.get("target") or "")
    out = []
    for c in conns:
        if c["status"] in ("LISTEN", "TIME_WAIT", "CLOSE", "NONE") or not c.get("rip"):
            continue
        inbound = c["lport"] in listening
        if (d == "in" and not inbound) or (d == "out" and inbound):
            continue
        if (port and c["rport"] != port) or (lport and c["lport"] != lport):
            continue
        if kind == "program":
            if os.path.normcase(exe_of(c["pid"]) or "") != target:
                continue
        elif c["rip"] not in ips:
            continue
        out.append(c)
    return out


def _delete_tcb(c):
    import ctypes

    class MIB_TCPROW(ctypes.Structure):
        _fields_ = [("dwState", ctypes.c_ulong), ("dwLocalAddr", ctypes.c_ulong),
                    ("dwLocalPort", ctypes.c_ulong), ("dwRemoteAddr", ctypes.c_ulong),
                    ("dwRemotePort", ctypes.c_ulong)]
    # Addresses and ports are in network byte order inside the DWORDs.
    addr = lambda ip: struct.unpack("<L", socket.inet_aton(ip))[0]
    row = MIB_TCPROW(12,   # MIB_TCP_STATE_DELETE_TCB
                     addr(c["lip"]), socket.htons(c["lport"]),
                     addr(c["rip"]), socket.htons(c["rport"]))
    return ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row)) == 0


def drop_connections(entry):
    """End the open IPv4 TCP connections a new block covers; how many."""
    if not IS_WINDOWS or psutil is None:
        return 0
    conns = []
    for c in psutil.net_connections(kind="tcp4"):
        if c.laddr:
            conns.append({"pid": c.pid, "status": c.status, "lip": c.laddr.ip,
                          "lport": c.laddr.port, "rip": c.raddr.ip if c.raddr else "",
                          "rport": c.raddr.port if c.raddr else 0})
    exes = {}

    def exe_of(pid):
        if pid not in exes:
            try:
                exes[pid] = psutil.Process(pid).exe()
            except Exception:
                exes[pid] = ""
        return exes[pid]
    n = 0
    for c in connections_to_drop(entry, conns, exe_of):
        try:
            n += bool(_delete_tcb(c))
        except Exception:
            pass
    return n


def _default_run(cmd):
    from netscope_tray import _run
    return _run(cmd)


def clean_address(text, local_ips=()):
    """A canonical, blockable IP string, or BlockError."""
    try:
        ip = ipaddress.ip_address(str(text or "").split("%")[0].strip())
    except ValueError:
        raise BlockError("That is not an IP address.")
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise BlockError("Loopback, wildcard and multicast addresses can't be blocked.")
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if str(ip) in {str(x).split("%")[0] for x in local_ips}:
        raise BlockError("That is one of this machine's own addresses.")
    return str(ip)


class Blocker:
    def __init__(self, load, save, run=None, available=None, local_ips=None,
                 own_exes=None, program_path=None, name_path=None, name_ips=None,
                 drop=None, background=True):
        """
        load/save   settings accessors (netscope_history.load_settings / save_setting)
        run         command runner: list -> (exit code, output). Injected by tests
                    and by demo mode, which must never touch the real firewall.
        available   callable -> bool: can rules be written (Windows + admin)?
        local_ips   callable -> addresses of this machine
        program_path  callable pid -> full path of that process's exe, or ""
        name_path   callable name -> the one exe path every running process of
                    that name shares, or "" when there are none or several
        name_ips    callable host name -> addresses it is known to have now
        drop        callable entry -> how many open connections it ended
        background  apply DNS-learned addresses on a thread of their own (tests
                    pass False and get them applied inside note_dns)
        """
        self._load, self._save = load, save
        self._run = run or _default_run
        self._available = available or (lambda: IS_WINDOWS)
        self._local_ips = local_ips or (lambda: ())
        self._own = {os.path.normcase(p) for p in (own_exes or [sys.executable])}
        self._program_path = program_path or (lambda pid: "")
        self._name_path = name_path or (lambda name: "")
        self._name_ips = name_ips or (lambda name: ())
        self._drop = drop or drop_connections
        self._background = background
        self._lock = threading.RLock()
        self._name_targets = None           # names with a block, for note_dns
        self._pending = {}                  # name -> addresses waiting to be added
        self._wake = None
        self._verified = (0.0, {})          # (when, {rule name: exists})
        self._orphans = (0.0, [])           # (when, [ids found in the firewall])

    # -- settings ------------------------------------------------------------

    @property
    def enabled(self):
        return bool(self._load().get("blocking_enabled"))

    def set_enabled(self, on):
        self._save("blocking_enabled", bool(on))

    def available(self):
        try:
            return bool(self._available())
        except Exception:
            return False

    def entries(self):
        v = self._load().get("blocks")
        return [e for e in v if isinstance(e, dict) and ID_RE.match(str(e.get("id", "")))] \
            if isinstance(v, list) else []

    def count(self):
        return len(self.entries())

    # -- rules ---------------------------------------------------------------

    @staticmethod
    def rule_names(entry):
        base = RULE_PREFIX + entry["id"]
        return {"both": [base + "-out", base + "-in"], "out": [base + "-out"],
                "in": [base + "-in"]}[direction(entry)]

    def _add_cmd(self, entry, name):
        d = "in" if name.endswith("-in") else "out"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + name,
               "dir=" + d, "action=block", "enable=yes", "profile=any"]
        if entry["kind"] == "program":
            cmd.append("program=" + entry["target"])
        elif entry["kind"] == "name":
            cmd.append("remoteip=" + ",".join(entry["ips"]))
        else:
            cmd.append("remoteip=" + entry["target"])
        # A remote port only makes sense outbound (on the way in, the remote
        # end's port is whatever it picked), a local one only inbound.
        if entry.get("port"):
            cmd += ["protocol=" + entry.get("proto", "TCP"),
                    "remoteport=" + str(entry["port"])]
        elif entry.get("lport"):
            cmd += ["protocol=" + entry.get("proto", "TCP"),
                    "localport=" + str(entry["lport"])]
        return cmd

    def _delete(self, name):
        return self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                          "name=" + name])

    def _exists(self, name):
        return self._run(["netsh", "advfirewall", "firewall", "show", "rule",
                          "name=" + name])[0] == 0

    # -- adding --------------------------------------------------------------

    def _check_allowed(self):
        if not self.available():
            raise BlockError("Blocking needs Windows and administrator rights.")
        if not self.enabled:
            raise BlockError("Blocking is switched off. Turn it on in the Blocked list first.")
        if self.count() >= MAX_BLOCKS:
            raise BlockError("The block list is full (%d)." % MAX_BLOCKS)

    def block_host(self, address, port=None, proto=None, dir=None, lport=None):
        """
        Both directions by default, or `dir` in/out. A remote `port` makes it
        outbound to that port only; a local `lport`, inbound to that port only.
        """
        self._check_allowed()
        addr = clean_address(address, self._local_ips())
        if port and lport:
            raise BlockError("A block is scoped to a remote port or a local one, not both.")
        entry = {"kind": "host", "target": addr,
                 "dir": dir if dir in ("in", "out") else "both"}
        if port:
            entry.update(port=_port(port), proto=_proto(proto), dir="out")
        elif lport:
            entry.update(lport=_port(lport), proto=_proto(proto), dir="in")
        return self._add(entry)

    def block_name(self, name):
        """
        Every address a host name has, both ways. It starts with the ones
        known now and gains each new one a captured DNS answer gives it.
        """
        self._check_allowed()
        name = clean_name(name)
        ips = []
        for raw in self._name_ips(name):
            try:
                ip = clean_address(raw, self._local_ips())
            except BlockError:
                continue
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise BlockError("NetScope hasn't seen an address for %s yet, so there "
                             "is nothing to put in a rule. Try again once it has "
                             "been looked up." % name)
        return self._add({"kind": "name", "target": name, "dir": "both",
                          "ips": ips[:MAX_NAME_IPS], "capped": len(ips) > MAX_NAME_IPS})

    def block_program(self, pid=None, name=None, dir=None, lport=None, proto=None):
        """
        By pid, or failing that by name: the path is looked up here, never taken
        from the page. A name only counts when every running process of that
        name is the same file; the timeline knows a program only by its name.
        Outbound unless `dir` is "in"; a local `lport` makes it inbound to that
        port only.
        """
        self._check_allowed()
        path = self._program_path(int(pid)) if pid else ""
        # Windows reuses pids. One from an alert can be minutes old and by now
        # belong to something else entirely, so it only counts while it is
        # still the program it was reported as.
        if path and name and os.path.basename(path).lower() != str(name).lower():
            path = ""
        if not path and name:
            path = self._name_path(str(name))
            if not path:
                raise BlockError("Can't tell which %s you mean: it isn't running and "
                                 "NetScope hasn't seen where its file is, or several "
                                 "different programs share that name. Block it from an "
                                 "open connection while it is running." % name)
        if not path or not os.path.isabs(path):
            raise BlockError("Could not find that program's file. It may have exited.")
        name = os.path.basename(path)
        if name.lower() in PROTECTED_PROGRAMS:
            raise BlockError("%s is part of Windows; blocking it would cut off "
                             "more than one program." % name)
        if os.path.normcase(path) in self._own:
            raise BlockError("That is NetScope itself.")
        entry = {"kind": "program", "target": path, "name": name,
                 "dir": "in" if dir == "in" or lport else "out"}
        if lport:
            entry.update(lport=_port(lport), proto=_proto(proto))
        return self._add(entry)

    @staticmethod
    def _same(a, b):
        return (all(a.get(k) == b.get(k) for k in ("kind", "target", "port", "lport"))
                and direction(a) == direction(b))

    def _add(self, entry):
        with self._lock:
            for e in self.entries():
                if self._same(e, entry):
                    raise BlockError("Already blocked.")
            entry["id"] = secrets.token_hex(4)
            entry["added"] = int(time.time())
            done = []
            for name in self.rule_names(entry):
                code, out = self._run(self._add_cmd(entry, name))
                if code != 0:
                    # Half a block is worse than none: it would read as active.
                    for n in done:
                        self._delete(n)
                    raise BlockError("Windows Firewall refused the rule: "
                                     + (out or "exit %s" % code)[:200])
                done.append(name)
            self._save("blocks", self.entries() + [entry])
            self._verified = (0.0, {})
            self._name_targets = None
        # The rule only stops what starts after it; end what is already open.
        try:
            dropped = int(self._drop(entry) or 0)
        except Exception:
            dropped = 0
        return dict(entry, dropped=dropped)

    # -- following a name's addresses ------------------------------------------

    def note_dns(self, answers):
        """
        Captured DNS answers. Runs for every DNS response, so it does nothing
        until a name is blocked, and the firewall is changed off this thread.
        CNAMEs are followed: www.example.com is often a CNAME to a CDN name,
        and the A record that matters is the CDN's.
        """
        targets = self._name_targets
        if targets is None:
            targets = self._name_targets = {e["target"] for e in self.entries()
                                            if e.get("kind") == "name"}
        if not targets or not answers:
            return
        norm = lambda n: str(n or "").rstrip(".").lower()
        found = {}
        for t in targets:
            names, grew = {t}, True
            while grew:
                grew = False
                for a in answers:
                    if a.get("type") == "CNAME" and norm(a.get("name")) in names \
                            and norm(a.get("data")) not in names:
                        names.add(norm(a.get("data")))
                        grew = True
            ips = {a["data"] for a in answers
                   if a.get("type") in ("A", "AAAA") and a.get("data")
                   and norm(a.get("name")) in names}
            if ips:
                found[t] = ips
        if not found:
            return
        with self._lock:
            for t, ips in found.items():
                self._pending.setdefault(t, set()).update(ips)
        if not self._background:
            self.apply_pending()
            return
        if self._wake is None:
            self._wake = threading.Event()
            threading.Thread(target=self._follow_loop, daemon=True,
                             name="block-follow").start()
        self._wake.set()

    def _follow_loop(self):
        while True:
            self._wake.wait()
            self._wake.clear()
            try:
                self.apply_pending()
            except Exception:
                pass

    def apply_pending(self):
        """Add the addresses note_dns found to their names' rules."""
        with self._lock:
            pending, self._pending = self._pending, {}
            if not pending:
                return
            entries, changed = self.entries(), False
            for e in entries:
                new = pending.get(e["target"]) if e.get("kind") == "name" else None
                if not new:
                    continue
                ips = list(e.get("ips") or [])
                for raw in sorted(new):
                    try:
                        ip = clean_address(raw, self._local_ips())
                    except BlockError:
                        continue
                    if ip in ips:
                        continue
                    if len(ips) >= MAX_NAME_IPS:
                        if not e.get("capped"):
                            e["capped"] = changed = True
                        break
                    ips.append(ip)
                if len(ips) == len(e.get("ips") or []):
                    continue
                ok = all(self._run(["netsh", "advfirewall", "firewall", "set", "rule",
                                    "name=" + n, "new", "remoteip=" + ",".join(ips)])[0] == 0
                         for n in self.rule_names(e))
                if ok:
                    e["ips"] = ips
                    changed = True
            if changed:
                self._save("blocks", entries)

    # -- removing ------------------------------------------------------------

    def unblock(self, ident):
        """
        Remove a block by id. Always tries both rule names, so an entry whose
        record was lost can still be removed once it shows up as unknown.
        """
        if not ID_RE.match(str(ident or "")):
            raise BlockError("Unknown block.")
        with self._lock:
            for suffix in ("-out", "-in"):
                name = RULE_PREFIX + ident + suffix
                code, out = self._delete(name)
                # A delete that fails because the rule is already gone is a
                # success; one that fails with the rule still there is not.
                if code != 0 and self._exists(name):
                    raise BlockError("Windows Firewall would not remove it: "
                                     + (out or "exit %s" % code)[:200])
            gone = [e for e in self.entries() if e["id"] == ident]
            self._save("blocks", [e for e in self.entries() if e["id"] != ident])
            self._verified = (0.0, {})
            self._name_targets = None
            self._orphans = (0.0, [])
            return gone[0] if gone else None

    # -- showing -------------------------------------------------------------

    def _read_orphans(self):
        when, ids = self._orphans
        if time.time() - when < VERIFY_TTL * 4:
            return ids
        code, out = self._run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetFirewallRule -DisplayName '%s*' -ErrorAction SilentlyContinue"
            " | ForEach-Object { $_.DisplayName }" % RULE_PREFIX])
        found = []
        if code == 0:
            for line in out.splitlines():
                m = RULE_RE.match(line.strip())
                if m and m.group(1) not in found:
                    found.append(m.group(1))
        self._orphans = (time.time(), found)
        return found

    def listing(self):
        """Entries with a state: active, missing (rule gone), or unknown (no record)."""
        with self._lock:
            entries = self.entries()
            if not self.available():
                return [dict(e, state="unverified") for e in entries]
            when, seen = self._verified
            if time.time() - when > VERIFY_TTL:
                seen = {}
                for e in entries:
                    for n in self.rule_names(e):
                        seen[n] = self._exists(n)
                self._verified = (time.time(), seen)
            out = []
            for e in entries:
                ok = all(seen.get(n) for n in self.rule_names(e))
                out.append(dict(e, state="active" if ok else "missing"))
            known = {e["id"] for e in entries}
            for ident in self._read_orphans():
                if ident not in known:
                    out.append({"id": ident, "kind": "unknown", "target": "",
                                "state": "unknown", "added": 0})
            return out
