#!/usr/bin/env python3
"""Hostile-client checks. QEMU must be serving on 127.0.0.1:$PORT. Exit 0 if all hold:

  1. forged, truncated and replayed records inside a real TLS connection are ignored, and
     the connection still serves the next real request (so they moved no sequence number)
  2. a ClientHello without an x25519 key share gets no working session
  3. junk instead of a ClientHello, and an oversized "ClientHello", do no harm
  4. after all of that a normal client is still served

Uses Python's ssl with memory BIOs, so that raw bytes can be slipped into the TCP stream
between TLS records.
"""
import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8443"))
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
    c.sock.sendall(rec)
    c.sock.sendall(rec)                                                # replay of that request
    buf = b""
    try:
        while buf.count(EXPECT) < 1:
            buf += c.pump(lambda: c.tls.read(4096))
        c.sock.settimeout(1.5)
        try:
            while True:
                buf += c.pump(lambda: c.tls.read(4096))
        except (TimeoutError, socket.timeout):
            pass
    except (OSError, ssl.SSLError) as e:
        buf = b"error %r" % e
    good &= check("a replayed record gets no second answer", buf.count(EXPECT) == 1)
    c.sock.settimeout(5)
    good &= check("request after the replay", c.fetch())
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
            s.settimeout(1)
            s.recv(4096)
        except OSError:
            pass
        s.close()
        good &= check(f"still serving after {name}", served())
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
