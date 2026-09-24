import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_ftp as F
import netscope_streams as S

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)

CLIENT, SERVER = "10.0.0.5", "203.0.113.9"
CPORT, SPORT = 51000, 21

def corr():
    return F.FTPCorrelator()

# Cases 1-6 send RETR *before* the negotiation. Real clients do it the other
# way round (see the "RFC 959 order" section below); these stay as a check
# that the reverse order keeps working too.

# ---- 1. Passive mode: RETR then 227 PASV arms the negotiated data endpoint.
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR report.pdf\r\n", True, 0.0)
c.observe_control(SERVER, SPORT, CLIENT, CPORT,
                   b"227 Entering Passive Mode (203,0,113,9,200,54).\r\n", False, 0.0)
meta = c.match_data(SERVER, 200 * 256 + 54, CLIENT, 49999)
check("PASV arms (server_ip, data_port) and match_data finds it",
      meta == {"name": "report.pdf", "direction": "download",
              "endpoint": (SERVER, 200 * 256 + 54), "role": "sender"}, str(meta))

# ---- 2. Matching consumes the entry — a second data connection isn't mistaken for it.
meta2 = c.match_data(SERVER, 200 * 256 + 54, CLIENT, 49998)
check("match is consumed, not reusable", meta2 is None, str(meta2))

# ---- 3. Active mode (PORT): the client's own address/port is what gets armed.
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR archive.zip\r\n", True, 0.0)
c.observe_control(CLIENT, CPORT, SERVER, SPORT,
                   b"PORT 10,0,0,5,195,80\r\n", True, 0.0)
meta = c.match_data(SERVER, 40000, CLIENT, 195 * 256 + 80)
check("PORT arms the client's negotiated address",
      meta == {"name": "archive.zip", "direction": "download",
              "endpoint": (CLIENT, 195 * 256 + 80), "role": "receiver"}, str(meta))

# ---- 4. PASV/PORT with no preceding RETR arms nothing (e.g. a STOR upload).
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"STOR upload.bin\r\n", True, 0.0)
c.observe_control(SERVER, SPORT, CLIENT, CPORT,
                   b"227 Entering Passive Mode (203,0,113,9,7,231).\r\n", False, 0.0)
meta = c.match_data(SERVER, 7 * 256 + 231, CLIENT, 49997)
check("STOR (upload) is never armed", meta is None, str(meta))

# ---- 5. An unmatched negotiation expires after its TTL.
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR old.txt\r\n", True, 0.0)
c.observe_control(SERVER, SPORT, CLIENT, CPORT,
                   b"227 Entering Passive Mode (203,0,113,9,1,1).\r\n", False, 0.0)
c.sweep(F.PENDING_TTL + F.SWEEP_INTERVAL + 1.0)
meta = c.match_data(SERVER, 1 * 256 + 1, CLIENT, 49996)
check("expired negotiation is forgotten", meta is None, str(meta))

# ---- 6. A second RETR on the same control connection overwrites the pending name.
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR first.txt\r\n", True, 0.0)
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR second.txt\r\n", True, 0.0)
c.observe_control(SERVER, SPORT, CLIENT, CPORT,
                   b"227 Entering Passive Mode (203,0,113,9,9,9).\r\n", False, 0.0)
meta = c.match_data(SERVER, 9 * 256 + 9, CLIENT, 49995)
check("later RETR on the same control conn wins", meta and meta["name"] == "second.txt", str(meta))

# ---- RFC 959 order: negotiate first, then RETR ------------------------------
#
# What every real client sends. The correlator used to only arm on a RETR it
# had already seen, so in a real session the first download was never
# recognised and each later one was labelled with the previous file's name.

def ctl(c, line, to_server=True):
    if to_server:
        c.observe_control(CLIENT, CPORT, SERVER, SPORT, line, True, 0.0)
    else:
        c.observe_control(SERVER, SPORT, CLIENT, CPORT, line, False, 0.0)

# ---- 11. PASV, 227, RETR — twice. Each download gets its own name.
c = corr()
got = []
for name, (p1, p2) in (("first.pdf", (200, 54)), ("second.pdf", (200, 55))):
    ctl(c, b"PASV\r\n")
    ctl(c, b"227 Entering Passive Mode (203,0,113,9,%d,%d).\r\n" % (p1, p2), False)
    ctl(c, b"RETR " + name.encode() + b"\r\n")
    got.append(c.match_data(CLIENT, 52000, SERVER, p1 * 256 + p2))
check("PASV then RETR arms the first download",
      got[0] == {"name": "first.pdf", "direction": "download",
                "endpoint": (SERVER, 200 * 256 + 54), "role": "sender"}, str(got[0]))
check("second download gets its own name, not the previous one",
      got[1] == {"name": "second.pdf", "direction": "download",
                "endpoint": (SERVER, 200 * 256 + 55), "role": "sender"}, str(got[1]))

# ---- 12. PORT then RETR (active mode).
c = corr()
ctl(c, b"PORT 10,0,0,5,195,81\r\n")
ctl(c, b"RETR data.csv\r\n")
meta = c.match_data(SERVER, 20, CLIENT, 195 * 256 + 81)
check("PORT then RETR arms the client's address",
      meta and meta["name"] == "data.csv", str(meta))

# ---- 13. PORT and RETR pipelined into one segment.
c = corr()
ctl(c, b"PORT 10,0,0,5,195,82\r\nRETR piped.bin\r\n")
meta = c.match_data(SERVER, 20, CLIENT, 195 * 256 + 82)
check("pipelined PORT+RETR in one segment",
      meta and meta["name"] == "piped.bin", str(meta))

# ---- 14. EPSV (what curl sends first): port only, on the replying server.
c = corr()
ctl(c, b"EPSV\r\n")
ctl(c, b"229 Entering Extended Passive Mode (|||50123|)\r\n", False)
ctl(c, b"RETR ext.iso\r\n")
meta = c.match_data(CLIENT, 52001, SERVER, 50123)
check("EPSV then RETR arms (server_ip, port)",
      meta and meta["name"] == "ext.iso", str(meta))

# ---- 15. EPRT, IPv6 form.
c = corr()
ctl(c, b"EPRT |2|2001:db8::5|50999|\r\n")
ctl(c, b"RETR v6.txt\r\n")
meta = c.match_data("2001:db8::9", 20, "2001:db8::5", 50999)
check("EPRT then RETR arms the client's address",
      meta and meta["name"] == "v6.txt", str(meta))

# ---- 16. A directory listing spends its negotiation; nothing is armed.
c = corr()
ctl(c, b"PASV\r\n")
ctl(c, b"227 Entering Passive Mode (203,0,113,9,10,1).\r\n", False)
ctl(c, b"LIST\r\n")
ctl(c, b"RETR late.txt\r\n")        # no fresh PASV: waits for one
meta = c.match_data(CLIENT, 52002, SERVER, 10 * 256 + 1)
check("LIST consumes the negotiation; a later RETR does not claim it",
      meta is None, str(meta))
ctl(c, b"PASV\r\n")
ctl(c, b"227 Entering Passive Mode (203,0,113,9,10,2).\r\n", False)
meta = c.match_data(CLIENT, 52003, SERVER, 10 * 256 + 2)
check("...and that RETR arms the next negotiation instead",
      meta and meta["name"] == "late.txt", str(meta))

# ---- 17. PASV then STOR (an upload) arms nothing, and leaves nothing behind.
c = corr()
ctl(c, b"PASV\r\n")
ctl(c, b"227 Entering Passive Mode (203,0,113,9,10,3).\r\n", False)
ctl(c, b"STOR up.bin\r\n")
meta = c.match_data(CLIENT, 52004, SERVER, 10 * 256 + 3)
check("PASV then STOR is never armed", meta is None, str(meta))
ctl(c, b"PASV\r\n")
ctl(c, b"227 Entering Passive Mode (203,0,113,9,10,4).\r\n", False)
meta = c.match_data(CLIENT, 52005, SERVER, 10 * 256 + 4)
check("a later unused PASV is not armed with a stale name", meta is None, str(meta))

# ---- 18. An unnamed negotiation expires too.
c = corr()
ctl(c, b"227 Entering Passive Mode (203,0,113,9,10,5).\r\n", False)
c.sweep(F.PENDING_TTL + F.SWEEP_INTERVAL + 1.0)
ctl(c, b"RETR afterwards.txt\r\n")
meta = c.match_data(CLIENT, 52006, SERVER, 10 * 256 + 5)
check("expired negotiation is not armed by a later RETR", meta is None, str(meta))

# ---- extract_ftp_object -----------------------------------------------------

class FakeStream:
    def __init__(self, ftp_meta, s2c=b""):
        self.ftp_meta = ftp_meta
        self._s2c = s2c
    def assemble(self, d):
        return (self._s2c, 0) if d == 1 else (b"", 0)

# ---- 7. No meta -> nothing to extract.
check("no ftp_meta -> None", S.extract_ftp_object(FakeStream(None)) is None)

# ---- 8. Complete download -> one object, server->client bytes, download direction.
st = FakeStream({"name": "report.pdf", "direction": "download"}, s2c=b"%PDF-1.4 fake bytes")
obj = S.extract_ftp_object(st)
check("download extracted with the negotiated name",
      obj is not None and obj["name"] == "report.pdf", str(obj))
check("download bytes come from server->client direction",
      obj["data"] == b"%PDF-1.4 fake bytes", str(obj))
check("direction is download", obj["direction"] == "download", str(obj))

# ---- 9. No bytes yet (transfer hasn't started) -> nothing to extract.
st_empty = FakeStream({"name": "report.pdf", "direction": "download"}, s2c=b"")
check("empty stream -> None", S.extract_ftp_object(st_empty) is None)

# ---- 10. An upload meta (should never occur, but the contract check must hold).
st_upload = FakeStream({"name": "x.bin", "direction": "upload"}, s2c=b"data")
check("upload direction is never extracted", S.extract_ftp_object(st_upload) is None)

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
