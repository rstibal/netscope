import os, sys, socket, json, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import run_tests as R

fails = []
def check(n, c, extra=""):
    print(("PASS  " if c else "FAIL  ") + n + (("  -- " + str(extra)) if extra and not c else ""))
    if not c: fails.append(n)

port = R.free_port()
proc, url = R.start_demo(port)
try:
    if not url:
        check("demo server started", False)
        sys.exit(1)
    tok = url.split("t=")[1]
    base = "http://127.0.0.1:%d" % port

    def get(path):
        try:
            with urllib.request.urlopen("%s%s%st=%s" % (base, path, "&" if "?" in path else "?", tok), timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:
            return type(e).__name__

    def raw(method, path, headers):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        req = "%s %s?t=%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s\r\n\r\n" % (
            method, path, tok, port, headers)
        s.sendall(req.encode())
        try:
            data = s.recv(200)
        except socket.timeout:
            data = b"TIMEOUT"
        s.close()
        return data

    check("good request still works", get("/api/state?since=0") == 200)
    check("non-numeric since is tolerated", get("/api/state?since=abc") == 200)
    check("non-numeric object id is a 400", get("/api/object?id=abc") == 400, get("/api/object?id=abc"))
    check("non-numeric preview id is a 400", get("/api/object_preview?id=x") == 400)

    r = raw("POST", "/api/control", "Content-Length: -1")
    check("negative Content-Length is refused, not waited on", r.startswith(b"HTTP/1.0 400") or r.startswith(b"HTTP/1.1 400"), r)
    r = raw("POST", "/api/control", "Content-Length: banana")
    check("non-numeric Content-Length is a 400", b" 400 " in r[:20], r)
    r = raw("POST", "/api/import", "Content-Length: 99999999999")
    check("an absurd import size is refused", b" 400 " in r[:20], r)
    r = raw("POST", "/api/control", "Content-Length: 5000000")
    check("an oversized control body is refused", b" 400 " in r[:20], r)

    # A JSON body that is not an object must not crash the route.
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    payload = b"[1,2,3]"
    s.sendall(("POST /api/control?t=%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: %d\r\n\r\n" % (tok, port, len(payload))).encode() + payload)
    r = s.recv(200); s.close()
    check("a JSON list body is handled", b" 200 " in r[:20], r)
    check("server is still healthy afterwards", get("/api/state?since=0") == 200)
finally:
    proc.terminate()
sys.exit(1 if fails else 0)
