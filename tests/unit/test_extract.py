"""
File extraction across repeated scanner passes.

Both bugs here only showed up on a *second* pass over a growing stream, which
is exactly what a single call to extract_objects() never exercises: the
scanner wakes every few seconds, so a real transfer is seen in pieces.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_streams as S

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

def rig():
    t = S.StreamTracker()
    store = S.ObjectStore()
    return t, store, S.ObjectScanner(t, store)

def names(store):
    return sorted(o["name"] for o in store.list())


# ---- 1. FTP data connection closed by a bare FIN, after a scan already ran.
t, store, sc = rig()
meta = {"name": "big.iso", "direction": "download"}
SRV, CLI = ("203.0.113.9", 50123), ("10.0.0.5", 52000)
t.observe(*CLI, *SRV, 100, b"", 0.0, "-", flags="S")
t.observe(*SRV, *CLI, 9000, b"A" * 1400, 0.1, "-", flags="PA",
          hint="FTP-DATA", ftp_meta=meta)
sc.scan_once()                                   # mid-transfer: nothing yet
check("nothing extracted while the transfer is still open", names(store) == [])
t.observe(*SRV, *CLI, 10400, b"B" * 600, 3.5, "-", flags="PA")
sc.scan_once()
t.observe(*SRV, *CLI, 11000, b"", 4.0, "-", flags="FA")   # no payload
sc.scan_once()
objs = store.list()
check("bare FIN after an earlier scan still triggers extraction",
      [o["name"] for o in objs] == ["big.iso"], str(objs))
check("the whole file is there", objs and objs[0]["size"] == 2000, str(objs))

# ---- 2. RST closes too.
t, store, sc = rig()
t.observe(*CLI, *SRV, 100, b"", 0.0, "-", flags="S")
t.observe(*SRV, *CLI, 9000, b"x" * 10, 0.1, "-", flags="PA",
          hint="FTP-DATA", ftp_meta={"name": "r.bin", "direction": "download"})
sc.scan_once()
t.observe(*SRV, *CLI, 9010, b"", 1.0, "-", flags="R")
sc.scan_once()
check("RST without payload also triggers extraction", names(store) == ["r.bin"])


# ---- HTTP keep-alive connection, growing between passes --------------------

class Conn:
    def __init__(self, t):
        self.t = t
        self.c, self.s = ("10.0.0.1", 40000), ("198.51.100.7", 80)
        self.cseq, self.sseq, self.ts = 1000, 500000, 0.0
    def c2s(self, b):
        self.ts += 0.01
        self.t.observe(*self.c, *self.s, self.cseq, b, self.ts, "chrome.exe")
        self.cseq += len(b)
    def s2c(self, b):
        self.ts += 0.01
        self.t.observe(*self.s, *self.c, self.sseq, b, self.ts, "chrome.exe")
        self.sseq += len(b)

def get(path):
    return b"GET " + path + b" HTTP/1.1\r\nHost: h.example\r\n\r\n"

def ok(body, ctype=b"text/plain"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype +
            b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

def upload_req(fname, data):
    part = (b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"" +
            fname + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n" +
            data + b"\r\n--B--\r\n")
    return (b"POST /up HTTP/1.1\r\nHost: h.example\r\n"
            b"Content-Type: multipart/form-data; boundary=B\r\n"
            b"Content-Length: " + str(len(part)).encode() + b"\r\n\r\n" + part)

# ---- 3. An upload arriving after a download: each file emitted exactly once.
t, store, sc = rig()
k = Conn(t)
k.c2s(get(b"/a.txt")); k.s2c(ok(b"aaa"))
sc.scan_once()
check("first pass emits the download", names(store) == ["a.txt"], str(names(store)))
k.c2s(upload_req(b"up.bin", b"DATA")); k.s2c(ok(b"stored"))
sc.scan_once()
got = [o["name"] for o in store.list()]
check("upload after a download is emitted",
      "up.bin" in got, str(got))
check("the earlier download is not emitted a second time",
      got.count("a.txt") == 1, str(got))
check("exactly three files: a.txt, up.bin, up.txt",
      sorted(got) == ["a.txt", "up.bin", "up.txt"], str(got))

# ---- 4. A second pass with nothing new emits nothing.
t.observe(*k.c, *k.s, k.cseq, b"", k.ts + 1, "chrome.exe", flags="A")
st = t.get(1); st.dirty = True
sc.scan_once()
check("an unchanged stream emits nothing new", len(store.list()) == 3,
      str([o["name"] for o in store.list()]))

# ---- 5. An upload whose body is still arriving is not emitted truncated.
t, store, sc = rig()
k = Conn(t)
req = upload_req(b"half.bin", b"0123456789" * 50)
k.c2s(req[:len(req) - 200])
k.s2c(b"HTTP/1.1 100 Continue\r\n\r\n")      # server bytes, so the scan runs
sc.scan_once()
check("partial upload body is not extracted yet", names(store) == [],
      str(names(store)))
k.c2s(req[len(req) - 200:])
sc.scan_once()
objs = store.list()
check("completed upload is extracted once, whole",
      [(o["name"], o["size"]) for o in objs] == [("half.bin", 500)],
      str([(o["name"], o["size"]) for o in objs]))

# ---- 6. A malformed Content-Length does not wedge the whole stream.
t, store, sc = rig()
k = Conn(t)
k.c2s(b"POST /x HTTP/1.1\r\nHost: h.example\r\nContent-Length: abc\r\n\r\n")
k.c2s(get(b"/after.txt")); k.s2c(ok(b"z")); k.s2c(ok(b"after"))
sc.scan_once()
check("bad Content-Length: later files on the connection still extract",
      "after.txt" in names(store) and sc.errors == 0,
      f"{names(store)} errors={sc.errors}")

# ---- FTP data connections, opened from either end ---------------------------
#
# The stream calls whoever it saw first "a". In passive mode that is the FTP
# client; in active mode the *server* opens the data connection, so the file
# flows a->b. Extraction used to always read b->a, which in active mode is
# the empty side.

import netscope_ftp as F

FCLI, FSRV = "10.0.0.5", "203.0.113.9"

def ftp_session(negotiation, retr, opener, opener_port, other, other_port,
                sender, payload=b"FILE-BYTES" * 100):
    """Negotiate over a control connection, then play the data connection
    out through the tracker the way CaptureEngine does, SYN first."""
    corr = F.FTPCorrelator()
    for line, to_server in negotiation + [(retr, True)]:
        if to_server:
            corr.observe_control(FCLI, 51000, FSRV, 21, line, True, 0.0)
        else:
            corr.observe_control(FSRV, 21, FCLI, 51000, line, False, 0.0)
    t, store, sc = rig()
    t.observe(opener, opener_port, other, other_port, 1, b"", 0.1, "-", flags="S")
    s_ip, s_port = (opener, opener_port) if sender == "opener" else (other, other_port)
    r_ip, r_port = (other, other_port) if sender == "opener" else (opener, opener_port)
    meta = corr.match_data(s_ip, s_port, r_ip, r_port)
    t.observe(s_ip, s_port, r_ip, r_port, 1000, payload, 0.2, "-", flags="PA",
              hint="FTP-DATA" if meta else "", ftp_meta=meta)
    t.observe(s_ip, s_port, r_ip, r_port, 1000 + len(payload), b"", 0.3, "-",
              flags="FA")
    sc.scan_once()
    return meta, store.list()

# ---- 7. Active mode (PORT): server connects out from port 20 and sends.
meta, objs = ftp_session([(b"PORT 10,0,0,5,195,80\r\n", True)], b"RETR act.bin\r\n",
                         FSRV, 20, FCLI, 195 * 256 + 80, sender="opener")
check("active-mode download is recognised", meta is not None, str(meta))
check("active-mode download is extracted with its bytes",
      [(o["name"], o["size"]) for o in objs] == [("act.bin", 1000)],
      str([(o["name"], o["size"]) for o in objs]))

# ---- 8. Active mode, extended form (EPRT).
meta, objs = ftp_session([(b"EPRT |1|10.0.0.5|50999|\r\n", True)], b"RETR eprt.bin\r\n",
                         FSRV, 20, FCLI, 50999, sender="opener")
check("EPRT download is extracted with its bytes",
      [(o["name"], o["size"]) for o in objs] == [("eprt.bin", 1000)],
      str([(o["name"], o["size"]) for o in objs]))

# ---- 9. Passive mode (PASV): client connects in, server sends back.
meta, objs = ftp_session([(b"PASV\r\n", True),
                          (b"227 Entering Passive Mode (203,0,113,9,200,54).\r\n", False)],
                         b"RETR pas.bin\r\n",
                         FCLI, 52000, FSRV, 200 * 256 + 54, sender="other")
check("passive-mode download is still extracted with its bytes",
      [(o["name"], o["size"]) for o in objs] == [("pas.bin", 1000)],
      str([(o["name"], o["size"]) for o in objs]))

# ---- 10. Passive mode, extended form (EPSV).
meta, objs = ftp_session([(b"EPSV\r\n", True),
                          (b"229 Entering Extended Passive Mode (|||50123|)\r\n", False)],
                         b"RETR epsv.bin\r\n",
                         FCLI, 52000, FSRV, 50123, sender="other")
check("EPSV download is extracted with its bytes",
      [(o["name"], o["size"]) for o in objs] == [("epsv.bin", 1000)],
      str([(o["name"], o["size"]) for o in objs]))

# ---- 11. Endpoint written differently from the stream's (e.g. IPv6
# spelling): falls back to whichever side actually carried bytes.
t, store, sc = rig()
odd = {"name": "odd.bin", "direction": "download",
       "endpoint": ("2001:0db8:0000:0000:0000:0000:0000:0005", 50999),
       "role": "receiver"}
t.observe("2001:db8::9", 20, "2001:db8::5", 50999, 1, b"", 0.1, "-", flags="S")
t.observe("2001:db8::9", 20, "2001:db8::5", 50999, 2, b"Z" * 300, 0.2, "-",
          flags="PA", hint="FTP-DATA", ftp_meta=odd)
t.observe("2001:db8::9", 20, "2001:db8::5", 50999, 302, b"", 0.3, "-", flags="FA")
sc.scan_once()
check("unmatched endpoint falls back to the side with the data",
      [(o["name"], o["size"]) for o in store.list()] == [("odd.bin", 300)],
      str([(o["name"], o["size"]) for o in store.list()]))

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
