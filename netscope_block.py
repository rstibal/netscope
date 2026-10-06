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
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import sys
import threading
import time

IS_WINDOWS = os.name == "nt"

RULE_PREFIX = "NetScope-block-"
RULE_RE = re.compile(r"^" + re.escape(RULE_PREFIX) + r"([0-9a-f]{8})-(out|in)$")
ID_RE = re.compile(r"^[0-9a-f]{8}$")
MAX_BLOCKS = 200
VERIFY_TTL = 15.0

# Blocking one of these cuts off Windows itself, not one program: svchost
# hosts dozens of services, and the rest are the session and security core.
PROTECTED_PROGRAMS = {
    "svchost.exe", "system", "lsass.exe", "services.exe", "wininit.exe",
    "csrss.exe", "winlogon.exe", "smss.exe", "(system)",
}


class BlockError(Exception):
    """A refusal that is worth showing to the person who asked."""


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
                 own_exes=None, program_path=None, name_path=None):
        """
        load/save   settings accessors (netscope_history.load_settings / save_setting)
        run         command runner: list -> (exit code, output). Injected by tests
                    and by demo mode, which must never touch the real firewall.
        available   callable -> bool: can rules be written (Windows + admin)?
        local_ips   callable -> addresses of this machine
        program_path  callable pid -> full path of that process's exe, or ""
        name_path   callable name -> the one exe path every running process of
                    that name shares, or "" when there are none or several
        """
        self._load, self._save = load, save
        self._run = run or _default_run
        self._available = available or (lambda: IS_WINDOWS)
        self._local_ips = local_ips or (lambda: ())
        self._own = {os.path.normcase(p) for p in (own_exes or [sys.executable])}
        self._program_path = program_path or (lambda pid: "")
        self._name_path = name_path or (lambda name: "")
        self._lock = threading.RLock()
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
        # A rule scoped to a remote port only makes sense outbound: on the way
        # in, the remote end's port is whatever it picked.
        if entry["kind"] == "host" and not entry.get("port"):
            return [base + "-out", base + "-in"]
        return [base + "-out"]

    def _add_cmd(self, entry, name):
        d = "in" if name.endswith("-in") else "out"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + name,
               "dir=" + d, "action=block", "enable=yes", "profile=any"]
        if entry["kind"] == "program":
            cmd.append("program=" + entry["target"])
        else:
            cmd.append("remoteip=" + entry["target"])
            if entry.get("port"):
                cmd += ["protocol=" + entry.get("proto", "TCP"),
                        "remoteport=" + str(entry["port"])]
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

    def block_host(self, address, port=None, proto=None):
        self._check_allowed()
        addr = clean_address(address, self._local_ips())
        entry = {"kind": "host", "target": addr}
        if port:
            p = int(port)
            if not 1 <= p <= 65535:
                raise BlockError("That is not a port number.")
            entry["port"] = p
            entry["proto"] = "UDP" if str(proto).upper() == "UDP" else "TCP"
        return self._add(entry)

    def block_program(self, pid=None, name=None):
        """
        By pid, or failing that by name: the path is looked up here, never taken
        from the page. A name only counts when every running process of that
        name is the same file; the timeline knows a program only by its name.
        """
        self._check_allowed()
        path = self._program_path(int(pid)) if pid else ""
        if not path and name:
            path = self._name_path(str(name))
            if not path:
                raise BlockError("Can't tell which %s you mean: it isn't running, or "
                                 "several different programs share that name. Block it "
                                 "from an open connection instead." % name)
        if not path or not os.path.isabs(path):
            raise BlockError("Could not find that program's file. It may have exited.")
        name = os.path.basename(path)
        if name.lower() in PROTECTED_PROGRAMS:
            raise BlockError("%s is part of Windows; blocking it would cut off "
                             "more than one program." % name)
        if os.path.normcase(path) in self._own:
            raise BlockError("That is NetScope itself.")
        return self._add({"kind": "program", "target": path, "name": name})

    def _add(self, entry):
        with self._lock:
            for e in self.entries():
                if all(e.get(k) == entry.get(k) for k in ("kind", "target", "port")):
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
            return dict(entry)

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
