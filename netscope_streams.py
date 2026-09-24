# -*- coding: utf-8 -*-
"""
TCP stream reassembly and file extraction.

Two jobs:

1. Put the packets of a connection back in order so you can read the exchange
   as one conversation instead of a thousand fragments.
2. Walk the reassembled HTTP in that conversation and pull out whole
   transferred files — images, PDFs, whatever — with their real names.

Both only work on unencrypted traffic. A TLS stream reassembles fine but its
contents are ciphertext, and there is nothing to extract.
"""

from __future__ import annotations

import gzip
import os
import re
import threading
import time
import zlib
from collections import OrderedDict

# Caps, so a big download can't eat the machine.
MAX_STREAMS = 400
MAX_STREAM_BYTES = 8 * 1024 * 1024      # per direction, per stream
MAX_OBJECTS = 300
MAX_OBJECT_BYTES = 96 * 1024 * 1024     # total across all extracted files
MAX_SINGLE_OBJECT = 32 * 1024 * 1024

TEXTUAL = re.compile(
    rb"^(text/|application/(json|xml|javascript|x-www-form-urlencoded))", re.I)

EXT_BY_TYPE = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/webp": ".webp", "image/svg+xml": ".svg", "image/x-icon": ".ico",
    "application/pdf": ".pdf", "application/zip": ".zip",
    "application/json": ".json", "application/javascript": ".js",
    "text/html": ".html", "text/css": ".css", "text/plain": ".txt",
    "text/csv": ".csv", "application/xml": ".xml", "text/xml": ".xml",
    "video/mp4": ".mp4", "audio/mpeg": ".mp3",
    "application/octet-stream": ".bin",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str, fallback: str = "object") -> str:
    name = os.path.basename((name or "").split("?")[0].split("#")[0])
    name = SAFE_NAME.sub("_", name).strip("._")
    return name[:120] or fallback


# ---------------------------------------------------------------------------
# Reassembly
# ---------------------------------------------------------------------------


class TCPStream:
    """One TCP connection, both directions, held as sequence-indexed segments."""

    def __init__(self, sid, a, b, ts):
        self.id = sid
        self.a = a              # (ip, port) of the side seen first — the client
        self.b = b
        self.first_ts = ts
        self.last_ts = ts
        self.process = "-"
        self.hint = ""          # HTTP / TLS / SMB / FTP / FTP-DATA / ...
        self.host = ""          # SNI or HTTP Host, once we see one
        self.ftp_meta = None    # {"name", "direction"} for an FTP-DATA stream
        self.closed = False
        self.segs = [{}, {}]
        self.times = [{}, {}]
        self.isn = [None, None]
        self.bytes = [0, 0]
        self.packets = [0, 0]
        self.truncated = [False, False]
        self.objects_emitted = 0
        # Emitted so far, per direction. Uploads and downloads are each in a
        # stable order within their own kind, but not relative to each other:
        # an upload that turns up later lands ahead of downloads already seen.
        self.emitted = {"upload": 0, "download": 0}
        self.dirty = False

    # -- ingest ------------------------------------------------------------

    def add(self, d, seq, data, ts):
        self.last_ts = ts
        self.packets[d] += 1
        if not data:
            return
        if self.isn[d] is None:
            self.isn[d] = seq
        if self.bytes[d] >= MAX_STREAM_BYTES:
            self.truncated[d] = True
            return
        prev = self.segs[d].get(seq)
        if prev is not None and len(prev) >= len(data):
            return                      # duplicate or shorter retransmit
        if prev is None:
            self.bytes[d] += len(data)
        else:
            self.bytes[d] += len(data) - len(prev)
        self.segs[d][seq] = data
        self.times[d].setdefault(seq, ts)
        self.dirty = True

    # -- reading ------------------------------------------------------------

    def interleaved(self, cap=1024 * 1024):
        """
        Both directions merged back into arrival order, as alternating blocks.

        This is what makes a connection readable top to bottom: request, then
        response, then the next request — instead of one side's bytes followed
        by the other's.
        """
        events = []
        for d in (0, 1):
            for seq, data in self.segs[d].items():
                events.append((self.times[d].get(seq, 0.0), d, seq, data))
        events.sort(key=lambda e: (e[0], e[1], e[2]))

        blocks = []
        seen = [set(), set()]
        total = 0
        clipped = False
        for _ts, d, seq, data in events:
            if seq in seen[d]:
                continue                       # retransmit
            seen[d].add(seq)
            if total + len(data) > cap:
                data = data[: max(0, cap - total)]
                clipped = True
            if not data:
                break
            if blocks and blocks[-1][0] == d:
                blocks[-1][1] += data
            else:
                blocks.append([d, bytearray(data)])
            total += len(data)
            if clipped:
                break
        return [(d, bytes(b)) for d, b in blocks], clipped

    # -- output ------------------------------------------------------------

    def assemble(self, d):
        """Return (bytes, gap_count). Overlaps are trimmed, holes are counted."""
        segs = self.segs[d]
        if not segs:
            return b"", 0
        out = bytearray()
        gaps = 0
        expected = self.isn[d]
        for seq in sorted(segs):
            data = segs[seq]
            end = seq + len(data)
            if end <= expected:
                continue                        # already covered
            if seq > expected:
                gaps += 1
                expected = seq                  # hole: skip ahead
            skip = expected - seq
            if skip > 0:
                data = data[skip:]
            out += data
            expected = end
        return bytes(out), gaps

    def summary(self):
        return {
            "id": self.id,
            "client": f"{self.a[0]}:{self.a[1]}",
            "server": f"{self.b[0]}:{self.b[1]}",
            "process": self.process,
            "hint": self.hint,
            "host": self.host,
            "bytes_c2s": self.bytes[0],
            "bytes_s2c": self.bytes[1],
            "packets": self.packets[0] + self.packets[1],
            "first": self.first_ts,
            "last": self.last_ts,
            "closed": self.closed,
            "truncated": self.truncated[0] or self.truncated[1],
        }


class StreamTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._streams = OrderedDict()   # key -> TCPStream
        self._by_id = {}
        self._next = 0

    def observe(self, src, sport, dst, dport, seq, data, ts, process, flags="",
                hint="", host="", ftp_meta=None):
        """Record one TCP segment. Returns the stream id."""
        key = frozenset(((src, sport), (dst, dport)))
        with self._lock:
            st = self._streams.get(key)
            if st is None:
                # SYN without ACK marks the true client; otherwise first seen wins.
                self._next += 1
                st = TCPStream(self._next, (src, sport), (dst, dport), ts)
                self._streams[key] = st
                self._by_id[st.id] = st
                while len(self._streams) > MAX_STREAMS:
                    _, old = self._streams.popitem(last=False)
                    self._by_id.pop(old.id, None)
            else:
                self._streams.move_to_end(key)

            d = 0 if (src, sport) == st.a else 1
            st.add(d, seq, data, ts)
            if process and process != "-" and st.process == "-":
                st.process = process
            if hint and not st.hint:
                st.hint = hint
            if host and not st.host:
                st.host = host
            if ftp_meta and not st.ftp_meta:
                st.ftp_meta = ftp_meta
            if ("F" in flags or "R" in flags) and not st.closed:
                st.closed = True
                # A FIN usually carries no data, so add() never marks the
                # stream dirty for it — and closing is the very event an FTP
                # data connection waits on. Without this, a transfer that the
                # scanner had already looked at once was never looked at again.
                st.dirty = True
            return st.id

    def get(self, sid):
        with self._lock:
            return self._by_id.get(sid)

    def list(self, limit=200):
        with self._lock:
            items = list(self._streams.values())
        items.sort(key=lambda s: s.last_ts, reverse=True)
        return [s.summary() for s in items[:limit]]

    def dirty_streams(self):
        with self._lock:
            return [s for s in self._streams.values() if s.dirty]

    def clear(self):
        with self._lock:
            self._streams.clear()
            self._by_id.clear()
            self._next = 0


# ---------------------------------------------------------------------------
# HTTP parsing over a reassembled stream
# ---------------------------------------------------------------------------


def _headers(block: bytes):
    out = {}
    for line in block.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            out[k.decode("latin-1", "replace").strip().lower()] = \
                v.decode("latin-1", "replace").strip()
    return out


def _first_line(block: bytes):
    return block.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def _decode_chunked(buf: bytes, pos: int):
    """Return (body, new_pos) or (None, pos) if the chunked body is incomplete."""
    body = bytearray()
    while True:
        nl = buf.find(b"\r\n", pos)
        if nl < 0:
            return None, pos
        try:
            size = int(buf[pos:nl].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return None, pos
        pos = nl + 2
        if size == 0:
            end = buf.find(b"\r\n", pos)
            return bytes(body), (end + 2 if end >= 0 else len(buf))
        if pos + size + 2 > len(buf):
            return None, pos
        body += buf[pos:pos + size]
        pos += size + 2
        if len(body) > MAX_SINGLE_OBJECT:
            return bytes(body), pos


def _decompress(data: bytes, encoding: str):
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc or "x-gzip" in enc:
            return gzip.decompress(data)
        if "deflate" in enc:
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -15)
        if "br" in enc:
            try:
                import brotli  # optional
                return brotli.decompress(data)
            except Exception:
                return data
    except Exception:
        return data
    return data


def parse_requests(buf: bytes):
    """List the HTTP requests in the client→server direction."""
    reqs = []
    pos = 0
    pat = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) ", re.M)
    while pos < len(buf) and len(reqs) < 200:
        m = pat.search(buf, pos)
        if not m:
            break
        head_end = buf.find(b"\r\n\r\n", m.start())
        if head_end < 0:
            break
        head = buf[m.start():head_end]
        h = _headers(head)
        line = _first_line(head)
        parts = line.split(" ")
        body_start = head_end + 4
        try:
            clen = max(0, int(h.get("content-length", 0) or 0))
        except ValueError:
            clen = 0
        if clen and body_start + clen > len(buf):
            break                   # body still arriving; pick it up next pass
        body = buf[body_start:body_start + clen] if clen else b""
        reqs.append({
            "method": parts[0] if parts else "",
            "path": parts[1] if len(parts) > 1 else "",
            "headers": h,
            "body": body,
        })
        pos = body_start + clen if clen else body_start
    return reqs


def parse_responses(buf: bytes, start_at: int = 0):
    """
    Walk HTTP responses in the server→client direction.

    Yields (status_line, headers, body, end_pos). Stops at the first response
    whose body has not fully arrived, so a download still in flight is simply
    picked up on the next pass.
    """
    pos = start_at
    while pos < len(buf):
        idx = buf.find(b"HTTP/1.", pos)
        if idx < 0:
            return
        head_end = buf.find(b"\r\n\r\n", idx)
        if head_end < 0:
            return
        head = buf[idx:head_end]
        h = _headers(head)
        line = _first_line(head)
        body_start = head_end + 4

        te = h.get("transfer-encoding", "").lower()
        if "chunked" in te:
            body, newpos = _decode_chunked(buf, body_start)
            if body is None:
                return                       # still arriving
        elif "content-length" in h:
            try:
                clen = int(h["content-length"])
            except ValueError:
                return
            if body_start + clen > len(buf):
                return                       # still arriving
            body = buf[body_start:body_start + clen]
            newpos = body_start + clen
        else:
            status = line.split(" ")[1] if len(line.split(" ")) > 1 else ""
            if status in ("204", "304") or line.startswith("HTTP/1.1 1"):
                body, newpos = b"", body_start
            else:
                # No length and no chunking: the body runs to end of stream.
                body, newpos = buf[body_start:], len(buf)
        yield line, h, body, newpos
        pos = newpos if newpos > pos else pos + 1


def _multipart_files(body: bytes, ctype: str):
    """Pull uploaded files out of a multipart/form-data request body."""
    m = re.search(r'boundary="?([^";]+)"?', ctype or "", re.I)
    if not m:
        return []
    sep = b"--" + m.group(1).encode("latin-1", "replace")
    out = []
    for part in body.split(sep):
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        disp = ""
        ptype = "application/octet-stream"
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"content-disposition:"):
                disp = line.decode("latin-1", "replace")
            elif low.startswith(b"content-type:"):
                ptype = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
        fm = re.search(r'filename="([^"]*)"', disp)
        if not fm or not fm.group(1):
            continue
        out.append((fm.group(1), ptype, data.rstrip(b"\r\n-")))
    return out


def extract_objects(stream: TCPStream):
    """
    Extract complete transferred files from one reassembled stream.

    Returns a list of dicts, uploads first. Within each direction the order is
    stable across repeated calls on a growing stream, which is what lets the
    scanner emit each file once — but only within a direction: an upload that
    completes later is inserted ahead of every download, so callers must count
    the two separately (see ObjectScanner.scan_once).
    """
    c2s, _ = stream.assemble(0)
    s2c, _ = stream.assemble(1)
    if not s2c and not c2s:
        return []

    reqs = parse_requests(c2s)
    objs = []

    # Uploads first — they belong to the requests, in order.
    for r in reqs:
        ctype = r["headers"].get("content-type", "")
        if r["body"] and "multipart/form-data" in ctype.lower():
            for name, ptype, data in _multipart_files(r["body"], ctype):
                objs.append({
                    "name": safe_filename(name, "upload"),
                    "ctype": ptype.split(";")[0].strip() or "application/octet-stream",
                    "size": len(data),
                    "data": data,
                    "direction": "upload",
                    "url": r["headers"].get("host", "") + r["path"],
                })

    # Then downloads, matched to requests positionally (HTTP/1.1 keep-alive
    # guarantees responses come back in request order).
    for i, (line, h, body, _end) in enumerate(parse_responses(s2c)):
        if not body:
            continue
        ctype = h.get("content-type", "application/octet-stream").split(";")[0].strip()
        body = _decompress(body, h.get("content-encoding", ""))
        if len(body) > MAX_SINGLE_OBJECT:
            body = body[:MAX_SINGLE_OBJECT]

        name = ""
        cd = h.get("content-disposition", "")
        fm = re.search(r'filename\*?="?([^";]+)"?', cd)
        if fm:
            name = fm.group(1)
        req = reqs[i] if i < len(reqs) else None
        if not name and req:
            name = os.path.basename(req["path"].split("?")[0])
        if not name:
            name = "object-%d" % (i + 1)
        if "." not in name:
            name += EXT_BY_TYPE.get(ctype, "")

        host = (req["headers"].get("host", "") if req else "") or stream.host
        objs.append({
            "name": safe_filename(name, "object"),
            "ctype": ctype,
            "size": len(body),
            "data": body,
            "direction": "download",
            "url": host + (req["path"] if req else ""),
            "status": line,
        })
    return objs


def _ftp_sending_side(stream, meta):
    """
    Which direction of a data connection carries the file (0: a->b, 1: b->a).

    Not simply "server to client": stream.a is whoever was seen first, which
    is whoever opened the connection — and in active mode (PORT/EPRT) that is
    the FTP *server* connecting out, so assuming direction 1 read the empty
    side. The correlator says which endpoint it armed and whether that end
    sends or receives; when that endpoint cannot be matched (an address
    written differently, say), the side that actually carried bytes wins.
    """
    ep, role = meta.get("endpoint"), meta.get("role")
    a, b = getattr(stream, "a", None), getattr(stream, "b", None)
    if ep and role in ("sender", "receiver") and tuple(ep) in (a, b):
        sender_is_a = (tuple(ep) == a) == (role == "sender")
        return 0 if sender_is_a else 1
    return 0 if len(stream.assemble(0)[0]) > len(stream.assemble(1)[0]) else 1


def extract_ftp_object(stream: TCPStream):
    """
    An FTP data connection carries nothing but the transferred file — unlike
    HTTP there is no request/response framing inside it, so the whole stream
    *is* the file, named from whatever the control channel negotiated.

    Downloads only: uploads are never armed by FTPCorrelator (see
    netscope_ftp.py), so meta["direction"] is always "download" here, but the
    check stays as the contract in case that changes.

    Callers must wait for stream.closed before calling this: there is no
    length header to say when the file is complete, only the connection
    closing.
    """
    meta = stream.ftp_meta
    if not meta or meta.get("direction") != "download":
        return None
    data, _gaps = stream.assemble(_ftp_sending_side(stream, meta))
    if not data:
        return None
    if len(data) > MAX_SINGLE_OBJECT:
        data = data[:MAX_SINGLE_OBJECT]
    name = safe_filename(meta.get("name", ""), "ftp-download")
    return {
        "name": name,
        "ctype": "application/octet-stream",
        "size": len(data),
        "data": data,
        "direction": "download",
        "url": meta.get("name", ""),
    }


# ---------------------------------------------------------------------------
# Object store + background scanner
# ---------------------------------------------------------------------------


class ObjectStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._objs = OrderedDict()
        self._next = 0
        self.total_bytes = 0

    def add(self, obj, stream):
        with self._lock:
            self._next += 1
            oid = self._next
            rec = {
                "id": oid,
                "name": obj["name"],
                "ctype": obj["ctype"],
                "size": obj["size"],
                "direction": obj["direction"],
                "url": obj.get("url", ""),
                "stream": stream.id,
                "process": stream.process,
                "peer": f"{stream.b[0]}:{stream.b[1]}",
                "ts": time.time(),
                "textual": bool(TEXTUAL.match(obj["ctype"].encode())),
                "_data": obj["data"],
            }
            self._objs[oid] = rec
            self.total_bytes += rec["size"]
            while len(self._objs) > MAX_OBJECTS or self.total_bytes > MAX_OBJECT_BYTES:
                _, old = self._objs.popitem(last=False)
                self.total_bytes -= old["size"]
            return oid

    def list(self):
        with self._lock:
            return [{k: v for k, v in o.items() if k != "_data"}
                    for o in reversed(self._objs.values())]

    def get(self, oid):
        with self._lock:
            return self._objs.get(oid)

    def clear(self):
        with self._lock:
            self._objs.clear()
            self.total_bytes = 0


class ObjectScanner(threading.Thread):
    """Periodically re-parses streams that grew, emitting newly completed files."""

    def __init__(self, tracker: StreamTracker, store: ObjectStore, interval=3.0):
        super().__init__(daemon=True, name="object-scanner")
        self.tracker = tracker
        self.store = store
        self.interval = interval
        self._stop = threading.Event()
        self.enabled = True
        self.errors = 0

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.wait(self.interval):
            if self.enabled:
                self.scan_once()

    def scan_once(self):
        """One pass over the streams that changed. Split out so it is testable."""
        for st in self.tracker.dirty_streams():
            try:
                st.dirty = False
                if st.hint == "FTP-DATA":
                    # Unlike HTTP, a data connection carries no length
                    # header — it signals "done" by closing, so extracting
                    # any earlier would ship a truncated file.
                    if not st.objects_emitted and st.closed:
                        obj = extract_ftp_object(st)
                        if obj:
                            self.store.add(obj, st)
                            st.objects_emitted = 1
                    continue
                if st.hint == "TLS" or not st.bytes[1]:
                    continue            # nothing extractable
                objs = extract_objects(st)
                for kind in ("upload", "download"):
                    mine = [o for o in objs if o["direction"] == kind]
                    for obj in mine[st.emitted[kind]:]:
                        self.store.add(obj, st)
                    st.emitted[kind] = len(mine)
                st.objects_emitted = sum(st.emitted.values())
            except Exception:
                self.errors += 1
