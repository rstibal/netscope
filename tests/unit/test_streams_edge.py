import os, sys, zlib, gzip
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))
import netscope_streams as S

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + extra) if extra and not c else ""))
    if not c: fails.append(n)


# ---- multipart: the file's own trailing bytes survive ---------------------
def multipart(content):
    return (b"--B\r\nContent-Disposition: form-data; name=f; filename=\"a.txt\"\r\n"
            b"Content-Type: text/plain\r\n\r\n" + content + b"\r\n--B--\r\n")

for label, content in (("trailing newline", b"line one\nline two\n"),
                       ("trailing dashes", b"rule\n-----"),
                       ("trailing CRLF", b"windows\r\n")):
    got = S._multipart_files(multipart(content), "multipart/form-data; boundary=B")
    check("multipart keeps " + label, len(got) == 1 and got[0][2] == content,
          repr(got))

# ---- decompression is bounded ---------------------------------------------
S.MAX_SINGLE_OBJECT = 1000
bomb = gzip.compress(b"\0" * 1_000_000)
out = S._decompress(bomb, "gzip")
check("gzip bomb is cut at the object limit", len(out) <= 1001, str(len(out)))
check("small gzip still decodes", S._decompress(gzip.compress(b"hello"), "gzip") == b"hello")
check("zlib deflate decodes", S._decompress(zlib.compress(b"hi"), "deflate") == b"hi")
raw = zlib.compressobj(wbits=-15)
rawdef = raw.compress(b"raw") + raw.flush()
check("raw deflate decodes", S._decompress(rawdef, "deflate") == b"raw")

# ---- port reuse starts a new stream ----------------------------------------
t = S.StreamTracker()
a = t.observe("10.0.0.2", 50000, "93.184.216.34", 80, 100, b"GET / HTTP/1.1\r\n\r\n", 1.0, "x.exe", flags="PA")
t.observe("93.184.216.34", 80, "10.0.0.2", 50000, 900, b"", 1.1, "x.exe", flags="FA")
b = t.observe("10.0.0.2", 50000, "93.184.216.34", 80, 77777, b"", 2.0, "x.exe", flags="S")
check("SYN after close is a new stream", a != b)
check("both streams stay listed", {s["id"] for s in t.list()} == {a, b})
check("old stream still reachable by id", t.get(a) is not None and t.get(a).closed)
c = t.observe("93.184.216.34", 80, "10.0.0.2", 50000, 5, b"", 2.1, "x.exe", flags="SA")
check("SYN+ACK joins the new stream", c == b)
d = t.observe("10.0.0.2", 50000, "93.184.216.34", 80, 1, b"x", 3.0, "x.exe", flags="PA")
check("a retransmitted SYN does not split an open stream",
      t.observe("10.0.0.2", 50000, "93.184.216.34", 80, 77777, b"", 3.1, "x.exe", flags="S") == b)

sys.exit(1 if fails else 0)
