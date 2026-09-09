# -*- coding: utf-8 -*-
"""
QUIC / HTTP-3 decoding, including SNI recovery from the Initial packet.

A large share of modern traffic is QUIC over UDP/443, which without decoding
shows up as anonymous UDP and hides the destination hostname. QUIC's Initial
packet is "encrypted" with keys derived from a published salt and the client's
own connection ID, so anyone watching the wire can decrypt it — the protection
exists to stop middleboxes ossifying the handshake, not to keep it secret.
That means the ClientHello, and therefore the SNI, is recoverable.

Steps: strip header protection with AES-ECB over a sample of the ciphertext,
decrypt the payload with AES-128-GCM, walk the QUIC frames for CRYPTO data,
reassemble it, and parse the TLS ClientHello inside.

Needs the `cryptography` package for AES. Without it the module still labels
QUIC packets and reports version, type and connection IDs — it just cannot
recover hostnames.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import threading
import time
from collections import OrderedDict

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
    CRYPTO_ERROR = None
except Exception as exc:  # pragma: no cover
    CRYPTO_OK = False
    CRYPTO_ERROR = str(exc)

# RFC 9001 §5.2 (v1) and RFC 9369 §3.3.1 (v2).
SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

VERSION_V1 = 0x00000001
VERSION_V2 = 0x6B3343CF

# Draft versions still seen in the wild, decoded as v1 for labelling only.
KNOWN_VERSIONS = {
    0x00000000: "Version Negotiation",
    VERSION_V1: "v1",
    VERSION_V2: "v2",
    0xFF00001D: "draft-29",
    0xFF00001B: "draft-27",
    0x51303530: "gQUIC Q050",
    0x51303436: "gQUIC Q046",
}

# Long-header packet types differ between v1 and v2 (RFC 9369 deliberately
# permutes them so a v2 Initial isn't mistaken for a v1 one).
TYPES_V1 = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
TYPES_V2 = {1: "Initial", 2: "0-RTT", 3: "Handshake", 0: "Retry"}

QUIC_PORTS = (443, 80, 8443, 4433)


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) with the TLS 1.3 label scheme — stdlib only
# ---------------------------------------------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# QUIC variable-length integers (RFC 9000 §16)
# ---------------------------------------------------------------------------


def read_varint(b: bytes, pos: int):
    if pos >= len(b):
        return None, pos
    length = 1 << (b[pos] >> 6)
    if pos + length > len(b):
        return None, pos
    value = b[pos] & 0x3F
    for i in range(1, length):
        value = (value << 8) | b[pos + i]
    return value, pos + length


# ---------------------------------------------------------------------------
# TLS ClientHello -> SNI. Shared with the TLS-over-TCP decoder in netscope.py.
# ---------------------------------------------------------------------------


def sni_from_client_hello(hs: bytes):
    """Extract server_name from a TLS ClientHello handshake body."""
    try:
        pos = 4 + 2 + 32                      # type+len, version, random
        pos += 1 + hs[pos]                    # legacy_session_id
        cs_len = struct.unpack("!H", hs[pos:pos + 2])[0]
        pos += 2 + cs_len                     # cipher_suites
        pos += 1 + hs[pos]                    # compression_methods
        if pos + 2 > len(hs):
            return None
        ext_total = struct.unpack("!H", hs[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(hs))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", hs[pos:pos + 4])
            body = hs[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 0x0000 and len(body) >= 5:
                name_len = struct.unpack("!H", body[3:5])[0]
                raw = body[5:5 + name_len]
                try:
                    return raw.rstrip(b".").decode("idna")
                except Exception:
                    return raw.decode("utf-8", "replace")
        return None
    except Exception:
        return None


def alpn_from_client_hello(hs: bytes):
    """Extract the ALPN list — this is how you tell h3 from hq or doq."""
    try:
        pos = 4 + 2 + 32
        pos += 1 + hs[pos]
        pos += 2 + struct.unpack("!H", hs[pos:pos + 2])[0]
        pos += 1 + hs[pos]
        ext_total = struct.unpack("!H", hs[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(hs))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", hs[pos:pos + 4])
            body = hs[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 0x0010 and len(body) >= 2:
                out, p = [], 2
                while p < len(body):
                    ln = body[p]
                    out.append(body[p + 1:p + 1 + ln].decode("latin-1", "replace"))
                    p += 1 + ln
                return out
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Frame walking
# ---------------------------------------------------------------------------


def _skip_ack(pt: bytes, pos: int):
    for _ in range(2):                       # largest acked, ack delay
        v, pos = read_varint(pt, pos)
        if v is None:
            return None
    count, pos = read_varint(pt, pos)
    if count is None:
        return None
    v, pos = read_varint(pt, pos)            # first ack range
    if v is None:
        return None
    for _ in range(min(count, 64)):
        for _ in range(2):                   # gap, range length
            v, pos = read_varint(pt, pos)
            if v is None:
                return None
    return pos


def crypto_chunks(pt: bytes):
    """Collect CRYPTO frame payloads out of a decrypted QUIC packet.

    Returns {stream_offset: bytes} rather than a joined buffer, because a
    ClientHello routinely spans several Initial packets and the caller has to
    stitch the pieces together across them.
    """
    chunks = {}
    pos = 0
    while pos < len(pt):
        ftype = pt[pos]
        pos += 1
        if ftype == 0x00 or ftype == 0x01:   # PADDING, PING
            continue
        if ftype in (0x02, 0x03):            # ACK
            nxt = _skip_ack(pt, pos)
            if nxt is None:
                break
            pos = nxt
            continue
        if ftype == 0x06:                    # CRYPTO
            offset, pos = read_varint(pt, pos)
            length, pos = read_varint(pt, pos)
            if offset is None or length is None or pos + length > len(pt):
                break
            chunks[offset] = pt[pos:pos + length]
            pos += length
            continue
        break                                # anything else: stop, safely
    return chunks


def join_chunks(chunks):
    """Contiguous bytes from offset 0, stopping at the first hole."""
    if not chunks or 0 not in chunks:
        return b""
    out = bytearray()
    for off in sorted(chunks):
        if off > len(out):
            break                            # hole — the rest is unusable
        out[off:off + len(chunks[off])] = chunks[off]
    return bytes(out)


def handshake_complete(buf: bytes):
    """Is `buf` a whole TLS handshake message? (type + 3-byte length + body)"""
    if len(buf) < 4:
        return False
    return len(buf) >= 4 + int.from_bytes(buf[1:4], "big")


class InitialReassembler:
    """
    Stitches a ClientHello back together across QUIC Initial packets.

    Chrome's ClientHello does not fit in one Initial — its post-quantum key
    share pushes it to two or three kilobytes, so it arrives as two or three
    packets carrying successive CRYPTO offsets under the same connection ID.
    Parsing a single packet yields a truncated ClientHello whose extension
    list runs off the end before reaching server_name, which is exactly how
    the hostname went missing against real browsers while every synthetic
    test passed.
    """

    def __init__(self, max_conns=512, ttl=30.0):
        self._conns = OrderedDict()          # dcid -> {"chunks": {}, "ts": t, "done": bool}
        self.max_conns = max_conns
        self.ttl = ttl
        self._lock = threading.Lock()

    def feed(self, dcid: bytes, chunks: dict):
        """
        Add this packet's CRYPTO fragments.

        Returns (handshake_bytes, is_new) — handshake_bytes only once the
        message is whole, is_new False if this connection already produced it.
        """
        if not chunks:
            return None, False
        now = time.time()
        with self._lock:
            entry = self._conns.get(dcid)
            if entry is None:
                entry = self._conns[dcid] = {"chunks": {}, "ts": now, "done": False}
                self._prune(now)
            else:
                self._conns.move_to_end(dcid)
            entry["ts"] = now
            if entry["done"]:
                return None, False
            entry["chunks"].update(chunks)
            buf = join_chunks(entry["chunks"])
            if buf and handshake_complete(buf):
                entry["done"] = True
                return buf, True
            return None, False

    def pending(self, dcid: bytes):
        with self._lock:
            e = self._conns.get(dcid)
            return bool(e and not e["done"] and e["chunks"])

    def _prune(self, now):
        while len(self._conns) > self.max_conns:
            self._conns.popitem(last=False)
        for k in [k for k, v in self._conns.items() if now - v["ts"] > self.ttl]:
            self._conns.pop(k, None)


# A default instance, so parse_quic works standalone; the capture engine
# passes its own so two engines never share reassembly state.
_default_reassembler = InitialReassembler()


# ---------------------------------------------------------------------------
# The decoder proper
# ---------------------------------------------------------------------------


def _initial_keys(version: int, dcid: bytes):
    salt = SALT_V2 if version == VERSION_V2 else SALT_V1
    prefix = b"quicv2 " if version == VERSION_V2 else b"quic "
    initial = _hkdf_extract(salt, dcid)
    client = _hkdf_expand_label(initial, b"client in", 32)
    return (_hkdf_expand_label(client, prefix + b"key", 16),
            _hkdf_expand_label(client, prefix + b"iv", 12),
            _hkdf_expand_label(client, prefix + b"hp", 16))


def _decrypt_initial(data: bytes, version: int, dcid: bytes, after_cids: int):
    """Undo header protection and AEAD on a client Initial packet."""
    token_len, pos = read_varint(data, after_cids)
    if token_len is None:
        return None
    pos += token_len
    length, pos = read_varint(data, pos)
    if length is None:
        return None
    pn_offset = pos
    if pn_offset + length > len(data) or pn_offset + 20 > len(data):
        return None                          # truncated capture

    key, iv, hp = _initial_keys(version, dcid)

    sample = data[pn_offset + 4:pn_offset + 20]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()

    first = data[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(data[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    packet_number = int.from_bytes(pn_bytes, "big")

    header = bytes([first]) + data[1:pn_offset] + pn_bytes
    ciphertext = data[pn_offset + pn_len:pn_offset + length]
    if len(ciphertext) < 16:
        return None

    nonce = bytearray(iv)
    pn_full = packet_number.to_bytes(8, "big")
    for i in range(8):
        nonce[4 + i] ^= pn_full[i]

    try:
        return AESGCM(key).decrypt(bytes(nonce), ciphertext, header)
    except Exception:
        return None                          # not a client Initial, or v-mismatch


def parse_quic(payload: bytes, sport=None, dport=None, reassembler=None):
    """
    Decode a UDP payload as QUIC. Returns a dict, or None if it isn't QUIC.

    Only client Initial packets yield a hostname — that is the only one whose
    keys are derivable from the wire. A ClientHello spanning several Initials
    reports the hostname on the packet that completes it, the way Wireshark
    attributes a reassembled message to its last fragment.
    """
    if reassembler is None:
        reassembler = _default_reassembler
    if len(payload) < 5:
        return None

    on_quic_port = (sport in QUIC_PORTS) or (dport in QUIC_PORTS)
    long_header = bool(payload[0] & 0x80)
    fixed_bit = bool(payload[0] & 0x40)

    if long_header:
        version = struct.unpack("!I", payload[1:5])[0]
        known = version in KNOWN_VERSIONS
        if not known and not on_quic_port:
            return None
        pos = 5
        if pos >= len(payload):
            return None
        dcil = payload[pos]
        pos += 1
        if dcil > 20 or pos + dcil > len(payload):
            return None
        dcid = payload[pos:pos + dcil]
        pos += dcil
        if pos >= len(payload):
            return None
        scil = payload[pos]
        pos += 1
        if scil > 20 or pos + scil > len(payload):
            return None
        scid = payload[pos:pos + scil]
        pos += scil

        types = TYPES_V2 if version == VERSION_V2 else TYPES_V1
        ptype = ("Version Negotiation" if version == 0
                 else types.get((payload[0] & 0x30) >> 4, "?"))

        info = {
            "header": "long",
            "version": KNOWN_VERSIONS.get(version, "0x%08x" % version),
            "type": ptype,
            "dcid": dcid.hex(),
            "scid": scid.hex(),
        }

        if ptype == "Initial" and version in (VERSION_V1, VERSION_V2) and CRYPTO_OK:
            plain = _decrypt_initial(payload, version, dcid, pos)
            if plain:
                info["decrypted"] = True
                chunks = crypto_chunks(plain)
                whole, fresh = reassembler.feed(dcid, chunks)
                if whole and fresh and whole[0] == 0x01:      # ClientHello
                    sni = sni_from_client_hello(whole)
                    if sni:
                        info["sni"] = sni
                    alpn = alpn_from_client_hello(whole)
                    if alpn:
                        info["alpn"] = alpn
                        info["h3"] = any(a.startswith("h3") for a in alpn)
                    info["ch_bytes"] = len(whole)
                    if len(chunks) and max(chunks) > 0:
                        info["reassembled"] = True
                elif not whole and reassembler.pending(dcid):
                    info["partial"] = True
                    info["note"] = ("ClientHello continues in another packet — "
                                    "the hostname appears on the one that "
                                    "completes it")
        elif ptype == "Initial" and not CRYPTO_OK:
            info["note"] = "install the 'cryptography' package to recover hostnames"
        return info

    # Short header: 1-RTT application data. The connection ID length is not on
    # the wire, so there is nothing to read beyond the form itself.
    if fixed_bit and on_quic_port:
        return {"header": "short", "type": "1-RTT", "version": "", "dcid": "", "scid": ""}
    return None


def write_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def build_client_hello(sni: str, alpn=("h3",), pad_to=0) -> bytes:
    """
    A minimal but well-formed TLS 1.3 ClientHello carrying SNI and ALPN.

    `pad_to` inflates it with a padding extension, the way a post-quantum key
    share does in a real browser — which is what pushes it past one packet.
    """
    import os as _os
    name = sni.encode("idna")
    sni_ext = (b"\x00\x00" + struct.pack("!H", len(name) + 5) +
               struct.pack("!H", len(name) + 3) + b"\x00" +
               struct.pack("!H", len(name)) + name)

    protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_ext = (b"\x00\x10" + struct.pack("!H", len(protos) + 2) +
                struct.pack("!H", len(protos)) + protos)

    versions = b"\x02\x03\x04"                       # list len 2, TLS 1.3
    ver_ext = b"\x00\x2b" + struct.pack("!H", len(versions)) + versions

    exts = sni_ext + alpn_ext + ver_ext
    if pad_to:
        # RFC 7685 padding extension, standing in for a big key share. Placed
        # last so server_name still sits early — exactly the layout that made
        # single-packet parsing look like it worked.
        need = max(0, pad_to - len(exts) - 90)
        exts += b"\x00\x15" + struct.pack("!H", need) + b"\x00" * need
    body = (b"\x03\x03" + _os.urandom(32) +
            b"\x20" + _os.urandom(32) +               # legacy session id
            b"\x00\x02\x13\x01" +                     # cipher suites
            b"\x01\x00" +                             # compression
            struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def build_client_initial(dcid: bytes, scid: bytes, sni: str, alpn=("h3",),
                         version=VERSION_V1, pad_to=1200,
                         crypto=None, crypto_offset=0):
    """
    Construct a genuine, decryptable client Initial packet.

    Used by the demo mode to produce realistic QUIC traffic, and it exercises
    the same key schedule the decoder uses — if the two disagree, the
    round-trip test fails loudly. Pass `crypto`/`crypto_offset` to place an
    arbitrary CRYPTO fragment, which is how a split ClientHello is built.
    """
    if not CRYPTO_OK:
        return None
    ch = build_client_hello(sni, alpn) if crypto is None else crypto
    frames = bytearray(b"\x06" + write_varint(crypto_offset) +
                       write_varint(len(ch)) + ch)

    pn_len = 4
    fixed = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1   # +1 for empty token
    overhead = fixed + 4 + pn_len + 16                  # 4 = length varint (worst case)
    if len(frames) + overhead < pad_to:
        frames += b"\x00" * (pad_to - len(frames) - overhead)

    plaintext = bytes(frames)
    length_field = pn_len + len(plaintext) + 16
    type_bits = 1 if version == VERSION_V2 else 0

    header = bytearray()
    header.append(0xC0 | (type_bits << 4) | (pn_len - 1))
    header += struct.pack("!I", version)
    header.append(len(dcid)); header += dcid
    header.append(len(scid)); header += scid
    header += write_varint(0)                            # token length
    header += write_varint(length_field)
    pn_offset = len(header)
    header += (0).to_bytes(pn_len, "big")                # packet number 0

    key, iv, hp = _initial_keys(version, dcid)
    ct = AESGCM(key).encrypt(bytes(iv), plaintext, bytes(header))

    packet = bytearray(header) + ct
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


def build_split_client_initials(dcid: bytes, scid: bytes, sni: str,
                                alpn=("h3",), size=2600, mtu=1200):
    """
    A ClientHello too large for one Initial, split across several — what a
    real browser sends. Returns the packets in order.
    """
    if not CRYPTO_OK:
        return []
    ch = build_client_hello(sni, alpn, pad_to=size)
    # Leave room for headers, the CRYPTO frame prologue and the AEAD tag.
    room = mtu - (1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 4 + 4 + 16) - 12
    out, offset = [], 0
    while offset < len(ch):
        piece = ch[offset:offset + room]
        out.append(build_client_initial(dcid, scid, sni, alpn, pad_to=mtu,
                                        crypto=piece, crypto_offset=offset))
        offset += len(piece)
    return out


def summarise(info: dict) -> str:
    """One-line description for the packet list."""
    if info["header"] == "short":
        return "1-RTT  application data (encrypted)"
    bits = [info["type"], info["version"]]
    if info.get("sni"):
        bits.append("→ " + info["sni"])
    if info.get("alpn"):
        bits.append("[" + ", ".join(info["alpn"][:3]) + "]")
    if info.get("reassembled"):
        bits.append("(ClientHello reassembled, %d B)" % info.get("ch_bytes", 0))
    elif info.get("partial"):
        bits.append("· ClientHello continues…")
    if info.get("dcid"):
        bits.append("dcid=" + info["dcid"][:16])
    if info.get("note") and not info.get("partial"):
        bits.append("· " + info["note"])
    return "  ".join(b for b in bits if b)
