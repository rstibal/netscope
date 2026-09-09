# -*- coding: utf-8 -*-
"""
SMB2 decoding — the part that makes Windows file-share traffic readable.

Windows signs SMB by default but does not encrypt it, so filenames travel in
plaintext UTF-16. This module pulls them out: share paths from TREE_CONNECT,
filenames from CREATE, and byte counts from READ/WRITE correlated back to the
file they belong to.

Only handles messages that fit inside a single TCP segment, which in practice
covers CREATE/TREE_CONNECT/READ/WRITE request headers — they are small. A
READ response carrying 64 KB of file data is recognised but not reassembled;
that is the stream tracker's job.
"""

from __future__ import annotations

import struct

NBSS_SESSION_MESSAGE = 0x00
SMB2_MAGIC = b"\xfeSMB"
SMB2_TRANSFORM_MAGIC = b"\xfdSMB"   # encrypted message
SMB1_MAGIC = b"\xffSMB"

SMB2_HEADER_LEN = 64
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

COMMANDS = {
    0x00: "NEGOTIATE", 0x01: "SESSION_SETUP", 0x02: "LOGOFF",
    0x03: "TREE_CONNECT", 0x04: "TREE_DISCONNECT", 0x05: "CREATE",
    0x06: "CLOSE", 0x07: "FLUSH", 0x08: "READ", 0x09: "WRITE",
    0x0A: "LOCK", 0x0B: "IOCTL", 0x0C: "CANCEL", 0x0D: "ECHO",
    0x0E: "QUERY_DIRECTORY", 0x0F: "CHANGE_NOTIFY", 0x10: "QUERY_INFO",
    0x11: "SET_INFO", 0x12: "OPLOCK_BREAK",
}

STATUS = {
    0x00000000: "SUCCESS",
    0x00000103: "PENDING",
    0x80000005: "BUFFER_OVERFLOW",
    0xC0000016: "MORE_PROCESSING_REQUIRED",
    0xC0000022: "ACCESS_DENIED",
    0xC0000034: "OBJECT_NAME_NOT_FOUND",
    0xC000003A: "OBJECT_PATH_NOT_FOUND",
    0xC0000035: "OBJECT_NAME_COLLISION",
    0xC000006D: "LOGON_FAILURE",
    0xC00000BA: "FILE_IS_A_DIRECTORY",
    0xC0000010: "INVALID_DEVICE_REQUEST",
}

DISPOSITION = {
    0: "supersede", 1: "open", 2: "create", 3: "open-or-create",
    4: "overwrite", 5: "overwrite-or-create",
}

# DesiredAccess bits worth naming
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
DELETE = 0x00010000

MAX_TRACK = 4096          # cap on each correlation dict


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _utf16(b, off, length):
    if length <= 0 or off < 0 or off + length > len(b):
        return ""
    try:
        return b[off:off + length].decode("utf-16-le", "replace")
    except Exception:
        return ""


def _trim(d):
    """Keep the correlation dicts from growing without bound."""
    if len(d) > MAX_TRACK:
        for k in list(d)[: len(d) - MAX_TRACK // 2]:
            d.pop(k, None)


class SmbTracker:
    """Decodes SMB2 and remembers enough state to name files in READ/WRITE."""

    def __init__(self):
        self.tree = {}      # (session, tree)      -> share path
        self.pending = {}   # (session, messageid) -> filename requested
        self.files = {}     # (session, fileid)    -> filename

    # -- public ------------------------------------------------------------

    def parse(self, payload: bytes):
        """Return a dict describing the SMB traffic in one TCP payload."""
        if len(payload) < 8:
            return None

        msgs = []
        pos = 0
        # A segment can hold several NetBIOS session messages back to back.
        while pos + 4 <= len(payload) and len(msgs) < 8:
            if payload[pos] != NBSS_SESSION_MESSAGE:
                break
            nb_len = int.from_bytes(payload[pos + 1:pos + 4], "big")
            body = payload[pos + 4:pos + 4 + nb_len]
            if not body:
                break
            msgs.extend(self._parse_nbss_body(body))
            pos += 4 + nb_len
            if nb_len == 0:
                break

        if not msgs:
            # Some captures hand us the SMB header with no NetBIOS wrapper.
            if payload[:4] in (SMB2_MAGIC, SMB2_TRANSFORM_MAGIC, SMB1_MAGIC):
                msgs = self._parse_nbss_body(payload)

        if not msgs:
            return None
        return {"messages": msgs, "summary": self._summarise(msgs)}

    # -- internals ---------------------------------------------------------

    def _parse_nbss_body(self, body: bytes):
        if body[:4] == SMB1_MAGIC:
            return [{"dialect": "SMB1", "command": "(legacy SMB1)",
                     "response": False, "note": "SMB1 — not decoded"}]
        if body[:4] == SMB2_TRANSFORM_MAGIC:
            return [{"dialect": "SMB3", "command": "ENCRYPTED",
                     "response": False,
                     "note": "SMB3 encryption is on — contents are not readable"}]
        if body[:4] != SMB2_MAGIC:
            return []

        out = []
        off = 0
        # Compounded requests chain through NextCommand.
        while off + SMB2_HEADER_LEN <= len(body) and len(out) < 8:
            m = self._parse_one(body, off)
            if not m:
                break
            out.append(m)
            nxt = m.pop("_next", 0)
            if not nxt:
                break
            off += nxt
        return out

    def _parse_one(self, b: bytes, off: int):
        try:
            cmd = _u16(b, off + 12)
            flags = _u32(b, off + 16)
            nxt = _u32(b, off + 20)
            msgid = _u64(b, off + 24)
            tree = _u32(b, off + 36)
            session = _u64(b, off + 40)
            status = _u32(b, off + 8)
        except Exception:
            return None

        is_resp = bool(flags & SMB2_FLAGS_SERVER_TO_REDIR)
        m = {
            "dialect": "SMB2",
            "command": COMMANDS.get(cmd, "0x%02X" % cmd),
            "response": is_resp,
            "_next": nxt,
        }
        if is_resp:
            m["status"] = STATUS.get(status, "0x%08X" % status)

        body_off = off + SMB2_HEADER_LEN
        share = self.tree.get((session, tree))
        if share:
            m["share"] = share

        try:
            if cmd == 0x03 and not is_resp:          # TREE_CONNECT request
                path = _utf16(b, off + _u16(b, body_off + 4), _u16(b, body_off + 6))
                if path:
                    m["path"] = path
                    self.pending[("tree", session, msgid)] = path
                    _trim(self.pending)

            elif cmd == 0x03 and is_resp:            # TREE_CONNECT response
                path = self.pending.pop(("tree", session, msgid), None)
                if path:
                    self.tree[(session, tree)] = path
                    _trim(self.tree)
                    m["share"] = path

            elif cmd == 0x05 and not is_resp:        # CREATE request
                access = _u32(b, body_off + 24)
                disp = _u32(b, body_off + 36)
                name = _utf16(b, off + _u16(b, body_off + 44), _u16(b, body_off + 46))
                m["filename"] = name
                m["disposition"] = DISPOSITION.get(disp, str(disp))
                ops = []
                if access & FILE_WRITE_DATA:
                    ops.append("write")
                if access & FILE_APPEND_DATA:
                    ops.append("append")
                if access & FILE_READ_DATA:
                    ops.append("read")
                if access & DELETE:
                    ops.append("delete")
                m["access"] = "+".join(ops) if ops else "metadata"
                self.pending[(session, msgid)] = self._full(share, name)
                _trim(self.pending)

            elif cmd == 0x05 and is_resp:            # CREATE response
                name = self.pending.pop((session, msgid), None)
                fid = b[body_off + 64:body_off + 80]
                if name and len(fid) == 16:
                    self.files[(session, fid)] = name
                    _trim(self.files)
                    m["filename"] = name
                if len(b) >= body_off + 56:
                    m["size"] = _u64(b, body_off + 48)

            elif cmd == 0x08 and not is_resp:        # READ request
                m["length"] = _u32(b, body_off + 4)
                m["offset"] = _u64(b, body_off + 8)
                m["filename"] = self.files.get((session, b[body_off + 16:body_off + 32]), "")

            elif cmd == 0x08 and is_resp:            # READ response
                m["length"] = _u32(b, body_off + 4)

            elif cmd == 0x09 and not is_resp:        # WRITE request
                m["length"] = _u32(b, body_off + 4)
                m["offset"] = _u64(b, body_off + 8)
                m["filename"] = self.files.get((session, b[body_off + 16:body_off + 32]), "")

            elif cmd == 0x09 and is_resp:            # WRITE response
                m["length"] = _u32(b, body_off + 4)   # Count

            elif cmd == 0x06 and not is_resp:        # CLOSE request
                fid = b[body_off + 8:body_off + 24]
                m["filename"] = self.files.pop((session, fid), "")

            elif cmd == 0x0E and not is_resp:        # QUERY_DIRECTORY request
                pat = _utf16(b, off + _u16(b, body_off + 24), _u16(b, body_off + 26))
                if pat:
                    m["pattern"] = pat

            elif cmd == 0x01 and not is_resp:        # SESSION_SETUP
                m["note"] = "authenticating"
        except Exception:
            pass

        return m

    @staticmethod
    def _full(share, name):
        if not name:
            return share or ""
        if share:
            return share.rstrip("\\") + "\\" + name
        return name

    @staticmethod
    def _summarise(msgs):
        """One-line description for the packet list's Info column."""
        parts = []
        for m in msgs:
            c = m.get("command", "?")
            tag = "«" if m.get("response") else "»"
            if c == "ENCRYPTED":
                parts.append("encrypted (SMB3)")
                continue
            if c == "CREATE" and m.get("filename"):
                verb = m.get("access", "")
                parts.append(f"{tag} CREATE {m['filename']}"
                             + (f"  [{verb}]" if verb and not m.get("response") else ""))
            elif c in ("READ", "WRITE"):
                bits = f"{tag} {c}"
                if m.get("length"):
                    bits += f" {m['length']:,}B"
                if m.get("filename"):
                    bits += f"  {m['filename']}"
                parts.append(bits)
            elif c == "TREE_CONNECT" and m.get("path"):
                parts.append(f"{tag} TREE_CONNECT {m['path']}")
            elif c == "QUERY_DIRECTORY" and m.get("pattern"):
                parts.append(f"{tag} DIR {m.get('share','')}\\{m['pattern']}")
            elif c == "CLOSE" and m.get("filename"):
                parts.append(f"{tag} CLOSE {m['filename']}")
            else:
                parts.append(f"{tag} {c}")
            st = m.get("status")
            if st and st not in ("SUCCESS", "PENDING"):
                parts[-1] += f"  [{st}]"
        return "   ".join(parts[:3])
