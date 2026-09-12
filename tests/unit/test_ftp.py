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

# ---- 1. Passive mode: RETR then 227 PASV arms the negotiated data endpoint.
c = corr()
c.observe_control(CLIENT, CPORT, SERVER, SPORT, b"RETR report.pdf\r\n", True, 0.0)
c.observe_control(SERVER, SPORT, CLIENT, CPORT,
                   b"227 Entering Passive Mode (203,0,113,9,200,54).\r\n", False, 0.0)
meta = c.match_data(SERVER, 200 * 256 + 54, CLIENT, 49999)
check("PASV arms (server_ip, data_port) and match_data finds it",
      meta == {"name": "report.pdf", "direction": "download"}, str(meta))

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
      meta == {"name": "archive.zip", "direction": "download"}, str(meta))

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
