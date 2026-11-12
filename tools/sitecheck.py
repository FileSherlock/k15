#!/usr/bin/env python3
"""sitecheck.py [quick]: the site an image was built with comes back as tools/pack.py made it.

Every path of $B/site.json is fetched over TLS (chain and name verified) and compared byte
for byte, head and body: on one connection, on fresh ones, with GET and with HEAD, from
clients that take small segments (so that the server cuts its records smaller), from one
that reads slowly (so that its window closes), from many at once. Then what is not a file:
unknown paths, queries, other methods (told no, and the connection closed), requests that
come in pieces or are too large, two requests at once, a client that closes its side or
goes away in the middle. Exit 0 if all of it holds.

Environment: B (build directory, default build), HOST and PORT (default 127.0.0.1:8443;
over tap: HOST=10.0.2.15 PORT=443), SRC (address to connect from), T (seconds to wait
for anything, default 20). With "quick" as argument: fewer fetches of the large file.
"""
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

B = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", os.environ.get("B", "build"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8443"))
SRC = os.environ.get("SRC")
T = float(os.environ.get("T", "20"))
NAME = open(os.path.join(B, "name")).read()
SITE = json.load(open(os.path.join(B, "site.json")))
QUICK = "quick" in sys.argv[1:]


def context():
    ca = os.path.join(B, "ca.pem")
    ctx = ssl.create_default_context(cafile=ca if os.path.getsize(ca) else None)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # see tools/load.py
    return ctx


class Conn:
    """A TLS client over a TCP socket we also hold: so a record can be sent in pieces."""

    def __init__(self, mss=None, rcvbuf=None):
        self.sock = socket.socket()
        if mss:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        if rcvbuf:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        if SRC:
            self.sock.bind((SRC, 0))
        self.sock.settimeout(T)
        self.sock.connect((HOST, PORT))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context().wrap_bio(self.inc, self.out, server_hostname=NAME)
        self.buf = b""
        self.eof = False
        self.pump(lambda: self.tls.do_handshake() or True)

    def pump(self, op):
        while True:
            try:
                res = op()
            except ssl.SSLWantReadError:
                res = None
            except ssl.SSLZeroReturnError:
                self.eof = True
                return b""
            data = self.out.read()
            if data:
                self.sock.sendall(data)
            if res is not None:
                return res
            got = self.sock.recv(65536)
            if not got:
                self.eof = True
                return b""
            self.inc.write(got)

    def send(self, raw, pieces=None, gap=0.05):
        """One record with these bytes; in several TCP segments if pieces says where to cut."""
        self.tls.write(raw)
        data = self.out.read()
        at = 0
        for cut in list(pieces or []) + [len(data)]:
            self.sock.sendall(data[at:cut])
            at = cut
            if at < len(data):
                time.sleep(gap)
        return len(data)

    def get(self, path, method="GET", extra=b""):
        self.send(method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n" + extra + b"\r\n")

    def more(self, pause=0):
        if pause:
            time.sleep(pause)
        got = self.pump(lambda: self.tls.read(65536))
        self.buf += got
        return bool(got)

    def response(self, head_only=False, pause=0):
        while b"\r\n\r\n" not in self.buf:
            if not self.more():
                raise ConnectionError("closed before a response's head was there: %r" % self.buf[:60])
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        head += b"\r\n\r\n"
        n = 0 if head_only else int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
        while len(self.buf) < n:
            if not self.more(pause):
                raise ConnectionError("closed in a body: %d of %d" % (len(self.buf), n))
        body, self.buf = self.buf[:n], self.buf[n:]
        return head, body

    def closed(self, wait=3):
        """True if the server ends the connection (and sends nothing more) within wait seconds."""
        self.sock.settimeout(wait)
        try:
            while self.more():
                pass
        except (OSError, ssl.SSLError) as e:
            return isinstance(e, ConnectionError)
        return not self.buf

    def close(self):
        self.sock.close()


def same(got, want):
    head, body = got
    return head == want["head"].encode("latin-1") and len(body) == want["length"] and \
        hashlib.sha256(body).hexdigest() == want["sha256"]


FAILED = []
ONLY = os.environ.get("ONLY")       # (for chasing one thing: only the checks whose name has this in it)


def check(name, fn):
    if ONLY and ONLY not in name:
        return
    t0 = time.time()
    try:
        ok = fn()
        why = ""
    except Exception as e:  # noqa: BLE001 (whatever goes wrong is a failure of this check)
        ok, why = False, " (%s: %s)" % (type(e).__name__, e)
    print("%s %s%s  [%.1f s]" % ("ok  " if ok else "FAIL", name, why, time.time() - t0), flush=True)
    if not ok:
        FAILED.append(name)


def main():
    paths = SITE["paths"]
    big = max(paths, key=lambda p: paths[p]["length"])
    small = [p for p in paths if paths[p]["length"] < 20000]
    nf = SITE["not_found"]

    def all_on_one(method):
        c = Conn()
        for p, want in paths.items():
            c.get(p, method)
            got = c.response(head_only=method == "HEAD")
            if method == "HEAD":
                if got[0] != want["head"].encode("latin-1"):
                    raise AssertionError("HEAD " + p)
            elif not same(got, want):
                raise AssertionError(p)
        c.get("/")                      # (and nothing was left over from the HEADs)
        ok = same(c.response(), paths["/"])
        c.close()
        return ok

    check(f"all {len(paths)} paths on one connection", lambda: all_on_one("GET"))
    check("the head of each, for HEAD", lambda: all_on_one("HEAD"))

    def fresh():
        for p in small:
            c = Conn()
            c.get(p)
            if not same(c.response(), paths[p]):
                raise AssertionError(p)
            c.close()
        return True

    check(f"{len(small)} of them on a connection each", fresh)

    def with_mss(mss):
        c = Conn(mss=mss)
        for p in small + ([] if QUICK and mss < 1000 else [big]):
            c.get(p)
            if not same(c.response(), paths[p]):
                raise AssertionError(p)
        c.close()
        return True

    for mss in (1300, 600, 300):
        check(f"to a client that takes segments of {mss} bytes", lambda mss=mss: with_mss(mss))

    def slow():
        c = Conn(rcvbuf=4096)
        c.get("/mid.bin" if "/mid.bin" in paths else big)
        time.sleep(1.5)                 # (its window closes; then it opens a little at a time)
        ok = same(c.response(pause=0.002), paths["/mid.bin" if "/mid.bin" in paths else big])
        c.get("/")
        ok &= same(c.response(), paths["/"])
        c.close()
        return ok

    check("to a client that reads slowly", slow)

    def many(n):
        res = []

        def one():
            try:
                c = Conn()
                for _ in range(2):
                    c.get(big)
                    res.append(same(c.response(), paths[big]))
                c.close()
            except Exception as e:  # noqa: BLE001
                res.append(repr(e))

        th = [threading.Thread(target=one) for _ in range(n)]
        for t in th:
            t.start()
        for t in th:
            t.join()
        if res != [True] * (2 * n):
            raise AssertionError([r for r in res if r is not True][:3])
        return True

    n = 4 if QUICK else 16
    for _ in range(int(os.environ.get("REPEAT", "1"))):
        check(f"the largest file ({paths[big]['length']} bytes) to {n} clients at once, twice each", lambda: many(n))

    def curl(suite):
        cmd = ["curl", "-s", "--max-time", str(int(4 * T)), "--connect-to", f"{NAME}:{PORT}:{HOST}:{PORT}", "--tls13-ciphers", suite]
        if SRC:
            cmd += ["--interface", SRC]
        ca = os.path.join(B, "ca.pem")
        if os.path.getsize(ca):
            cmd += ["--cacert", ca]
        out = subprocess.run(cmd + [f"https://{NAME}:{PORT}{big}"], capture_output=True).stdout
        return hashlib.sha256(out).hexdigest() == paths[big]["sha256"]

    for suite in ("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"):
        check(f"the largest file to curl with {suite}", lambda suite=suite: curl(suite))

    def unknown():
        c = Conn()
        ok = True
        for p in ("/nope", "/index.htm", "/docs/index.html/", "//", "/" + "x" * 300, "/.hidden", "/size"):
            c.get(p)
            ok &= same(c.response(), nf)
        c.get("/nope", "HEAD")
        ok &= c.response(head_only=True)[0] == nf["head"].encode("latin-1")
        c.get("/?a=1&b=2")
        ok &= same(c.response(), paths["/"])
        c.send(b"GET /\r\n\r\n")        # (no version: the path ends at the line's end)
        ok &= same(c.response(), paths["/"])
        if "/docs" in paths:            # a folder without its slash is sent to the one with
            c.get("/docs")
            head, _ = c.response()
            ok &= head.startswith(b"HTTP/1.1 301") and b"\r\nLocation: /docs/\r\n" in head
        c.close()
        return ok

    check("unknown paths, a query, a folder without its slash", unknown)

    def refused(method):
        c = Conn()
        c.get("/", method, b"Content-Length: 3\r\n")
        head, _ = c.response()
        ok = head == SITE["not_allowed"].encode("latin-1")
        c.send(b"abc")
        ok &= c.closed()
        c.close()
        return ok

    for method in ("POST", "OPTIONS", "DELETE"):
        check(f"{method} is told no, and the connection ends", lambda method=method: refused(method))

    def not_requests():
        c = Conn()
        for junk in (b"\r\n", b"Host: x\r\n\r\n", b"get / HTTP/1.1\r\n\r\n", b" GET / HTTP/1.1\r\n\r\n", b"\x00" * 40, b"G"):
            c.send(junk)
        c.get("/")
        ok = same(c.response(), paths["/"])
        c.close()
        return ok

    check("records that are no requests get no answer and do no harm", not_requests)

    # (two paths these ask for: the test site's, or on another site what there is)
    pg = "/docs/" if "/docs/" in paths else "/"
    fl = "/size/2500.bin" if "/size/2500.bin" in paths else big

    def pieces():
        c = Conn()
        req = b"GET " + pg.encode() + b" HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n"
        ok = True
        for cuts in ([3], [5], [6], [20], [1, 2, 3, 4, 5, 6, 7], [len(req) + 21]):
            c.tls.write(req)
            data = c.out.read()
            at = 0
            for cut in cuts + [len(data)]:
                c.sock.sendall(data[at:cut])
                at = cut
                time.sleep(0.03)
            ok &= same(c.response(), paths[pg])
        pad = b"X-Pad: " + b"p" * 2900 + b"\r\n"      # one that takes three segments
        c.get("/", extra=pad)
        ok &= same(c.response(), paths["/"])
        c.get(pg)
        ok &= same(c.response(), paths[pg])
        c.close()
        return ok

    check("a request that comes in pieces, and one of 3 KB", pieces)

    def too_large():
        c = Conn()
        c.get("/", extra=b"X-Pad: " + b"p" * 6000 + b"\r\n")
        return c.closed()

    check("a request of over 4 KB ends the connection", too_large)

    def two_at_once():
        c = Conn()
        c.tls.write(b"GET " + fl.encode() + b" HTTP/1.1\r\n\r\n")
        c.tls.write(b"GET " + pg.encode() + b" HTTP/1.1\r\n\r\n")
        c.sock.sendall(c.out.read())
        ok = same(c.response(), paths[fl]) and same(c.response(), paths[pg])
        c.close()
        return ok

    check("two requests at once are answered one after the other", two_at_once)

    def half_close():
        c = Conn()
        c.get(big)
        c.sock.shutdown(socket.SHUT_WR)
        ok = same(c.response(), paths[big])
        ok &= c.closed()
        c.close()
        return ok

    check("a client that closes its side after its request gets the file, then the end", half_close)

    def goes_away():
        for _ in range(8):
            c = Conn()
            c.get(big)
            c.more()
            c.close()                   # (with data unread: the client's side resets)
        c = Conn()
        c.get("/")
        return same(c.response(), paths["/"])

    check("clients that go away in the middle of a file", goes_away)

    # In an image built with KEYLIFE=n a connection's key seals 2^n records and no more
    # than one response beyond (in a real one n is 24: too many to wait for here)
    if os.environ.get("KEYLIFE"):
        def key_life():
            c = Conn()
            c.get(big)                  # (1,110 records at least)
            ok = same(c.response(), paths[big])
            c.get(big)                  # this one is still answered, in full,
            ok &= same(c.response(), paths[big])
            ok &= c.closed()            # and then the server ends the connection
            c2 = Conn()
            c2.get("/")
            return ok and same(c2.response(), paths["/"])

        check("a connection whose key has sealed its share of records is ended after the response in hand", key_life)
    check("and after all that, the page", lambda: fresh() or True)
    print("FAILED: " + "; ".join(FAILED) if FAILED else "all ok")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
