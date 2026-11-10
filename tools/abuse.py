#!/usr/bin/env python3
"""Hostile-client checks. QEMU must be serving on 127.0.0.1:$PORT. Exit 0 if all hold:

  1. forged, truncated and replayed records inside a real TLS connection are ignored, and
     the connection still serves the next real request (so they moved no sequence number)
  2. a ClientHello without an x25519 key share gets no working session
  3. junk instead of a ClientHello, and an oversized "ClientHello", do no harm
  4. after all of that a normal client is still served
  5. plain HTTP on port 80 (127.0.0.1:$HPORT): a request in pieces gets one response, two in
     one segment get two, bytes without an empty line get none

Uses Python's ssl with memory BIOs, so that raw bytes can be slipped into the TCP stream
between TLS records.
"""
import os
import socket
import ssl
import sys
import time

HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8443"))
HPORT = int(os.environ.get("HPORT", PORT + 1000))
BUILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", os.environ.get("B", "build"))
NAME = open(os.path.join(BUILD, "name")).read()
EXPECT = open(os.path.join(BUILD, "..", "www", "index.html"), "rb").read()
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def context(groups=None):
    ca = os.path.join(BUILD, "ca.pem")
    ctx = ssl.create_default_context(cafile=ca if os.path.getsize(ca) else None)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # see tools/load.py
    if groups:
        ctx.set_ecdh_curve(groups)
    return ctx


class Client:
    """A TLS client whose TCP stream we can also write to directly."""

    def __init__(self, ctx):
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self.inc, self.out, server_hostname=NAME)

    def pump(self, op):
        while True:
            try:
                res = op()
            except ssl.SSLWantReadError:
                res = None
            data = self.out.read()
            if data:
                self.sock.sendall(data)
            if res is not None:
                return res
            got = self.sock.recv(65536)
            if not got:
                raise ConnectionError("closed")
            self.inc.write(got)

    def handshake(self):
        self.pump(lambda: self.tls.do_handshake() or True)

    def fetch(self):
        self.pump(lambda: self.tls.write(REQ))
        buf = b""
        while not buf.endswith(EXPECT):
            buf += self.pump(lambda: self.tls.read(4096))
        return True

    def last_record(self):
        """Encrypt one request and return the record instead of sending it."""
        self.tls.write(REQ)
        return self.out.read()

    def close(self):
        self.sock.close()


def served(ctx=None):
    try:
        c = Client(ctx or context())
        c.handshake()
        ok = c.fetch()
        c.close()
        return ok
    except (OSError, ssl.SSLError):
        return False


def check(name, ok):
    print(("ok  " if ok else "FAIL"), name)
    return ok


def main():
    good = True
    good &= check("a normal client is served", served())

    # 1. junk records inside a real connection
    c = Client(context())
    c.handshake()
    good &= check("first request", c.fetch())
    c.sock.sendall(bytes([23, 3, 3, 0, 5]) + os.urandom(5))            # shorter than a tag
    c.sock.sendall(bytes([23, 3, 3, 0, 16]) + os.urandom(16))          # a tag and nothing else
    c.sock.sendall(bytes([23, 3, 3, 0, 60]) + os.urandom(60))          # forged request
    c.sock.sendall(bytes([21, 3, 3, 0, 2, 2, 40]))                     # plaintext alert
    good &= check("request after forged records", c.fetch())
    rec = c.last_record()
    # The replay goes out with the next real request behind it, in one segment (the server
    # can't take requests pipelined over several: our seq = their ack). No waiting for an
    # answer that must not come: the server answers in order and closes after our FIN, so
    # all it sends must be exactly two responses that decrypt in sequence.
    buf = b""
    try:
        c.sock.sendall(rec + rec + c.last_record())
        while buf.count(EXPECT) < 2:
            buf += c.pump(lambda: c.tls.read(4096))
        c.sock.shutdown(socket.SHUT_WR)
        while True:
            buf += c.pump(lambda: c.tls.read(4096))
    except ConnectionError:
        pass
    except (OSError, ssl.SSLError) as e:
        buf = b"error %r" % e
    good &= check("a replayed record gets no answer, the request after it does",
                  buf.count(EXPECT) == 2)
    c.close()

    # 2. no x25519 share
    good &= check("a client offering only P-256 gets no session", not served(context("prime256v1")))

    # 3. junk and oversized hellos
    for name, data in (("random bytes", os.urandom(3000)),
                       ("a 16 KB ClientHello record", bytes([22, 3, 1, 0x40, 0]) + os.urandom(9000)),
                       ("a ClientHello of zeros", bytes([22, 3, 1, 2, 0]) + bytes(512))):
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)      # the server answers a FIN with a FIN: once that
            s.settimeout(1)                 # is here, it has been through all of the junk
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()
        good &= check(f"still serving after {name}", served())

    # 5. port 80
    def plain(pieces, want):
        """Send the pieces one by one, then FIN; count the responses until the server's FIN."""
        s = socket.create_connection((HOST, HPORT), timeout=5)
        buf = b""
        try:
            for piece in pieces:
                s.sendall(piece)
                time.sleep(0.05)
            s.shutdown(socket.SHUT_WR)
            while got := s.recv(4096):
                buf += got
        except OSError as e:
            buf = b"error %r" % e
        s.close()
        return buf.count(EXPECT) == want and buf.count(b"HTTP/1.1 200") == want

    good &= check("port 80: a request gets a response", plain([REQ], 1))
    good &= check("port 80: a request in three pieces gets one", plain([REQ[:5], REQ[5:-2], REQ[-2:]], 1))
    good &= check("port 80: two requests at once get two", plain([REQ + REQ], 2))
    good &= check("port 80: bytes without an empty line get none", plain([os.urandom(64).replace(b"\n", b"x") * 40], 0))
    good &= check("port 80: still serving", plain([REQ], 1))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
