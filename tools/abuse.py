#!/usr/bin/env python3
"""Hostile-client checks. QEMU must be serving on 127.0.0.1:$PORT. Exit 0 if all hold:

  1. forged, truncated and replayed records inside a real TLS connection are ignored, and
     the connection still serves the next real request (so they moved no sequence number)
  2. a ClientHello without an x25519 key share gets no working session, and one with bytes
     that look like the start of one in another extension is served all the same; a
     client that can't be served (no TLS 1.3, none of our cipher suites, no x25519, no
     share for it after being asked) gets a fatal alert that says why, and the end of
     the connection: nothing that only looks like an answer
  3. junk instead of a ClientHello, an oversized "ClientHello", and a real one cut short
     anywhere or with any of its lengths gone wrong, do no harm
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
P80 = open(os.path.join(BUILD, "page80.bin"), "rb").read()      # what port 80 says to every request
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


def client_hello():
    """The ClientHello this machine's TLS sends (the handshake message, without the record header)."""
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context().wrap_bio(inc, out, server_hostname=NAME)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    rec = out.read()
    assert rec[0] == 22 and rec[5] == 1 and int.from_bytes(rec[3:5], "big") == len(rec) - 5, "one record with a ClientHello"
    return rec[5:]


def lengths(hello):
    """(offset, size) of every length field in a ClientHello: the message's own, session id,
    cipher suites, compression methods, extensions, each extension, and inside the key
    share extension the list and each share."""
    out = [(1, 3)]
    p = 38
    out.append((p, 1))
    p += 1 + hello[p]
    out.append((p, 2))
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    out.append((p, 1))
    p += 1 + hello[p]
    out.append((p, 2))
    p += 2
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        out.append((p + 2, 2))
        if kind == 51:
            out.append((p + 4, 2))
            q = p + 6
            while q + 4 <= p + 4 + n:
                out.append((q + 2, 2))
                q += 4 + int.from_bytes(hello[q + 2:q + 4], "big")
        p += 4 + n
    assert p == len(hello), "a ClientHello as we know them"
    return out


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

    # 2b. The four bytes that introduce an x25519 key share (group 29, 32 bytes long) in an
    # extension that comes before the key shares. The share was once looked for by those
    # bytes alone; a client's other key shares are a kilobyte of random-looking bytes these
    # days, and had them once in two million handshakes (the server then took the wrong
    # 32 bytes for the key, and the client could not read the answer).
    decoy = context()
    decoy.set_alpn_protocols(["\x00\x1d\x00 " + "k" * 32])
    good &= check("the key share is found behind an extension that looks like its start", served(decoy))

    # 2c. A ClientHello without an x25519 share is asked for another one (HelloRetryRequest).
    # What comes instead must do no harm: the same again, junk, nothing but the
    # ChangeCipherSpec records clients put in front of a second ClientHello.
    hello = client_hello()
    p = 38
    p += 1 + hello[p]
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    p += 1 + hello[p] + 2
    shareless = bytearray(hello)
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        if kind == 51:
            q = p + 6
            while q + 4 <= p + 4 + n:
                if hello[q:q + 2] == b"\x00\x1d":
                    shareless[q:q + 2] = b"\x01\x00"        # (a group we don't have)
                q += 4 + int.from_bytes(hello[q + 2:q + 4], "big")
        p += 4 + n
    shareless = bytes([22, 3, 1]) + len(shareless).to_bytes(2, "big") + bytes(shareless)
    ccs = bytes([20, 3, 3, 0, 1, 1])
    asked = True
    for second in (shareless, ccs + shareless, os.urandom(600), ccs * 500, bytes([22, 3, 3, 0, 0]), b""):
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(shareless)
            got = s.recv(4096)
            asked &= got[:1] == b"\x16" and got[11:43] == bytes.fromhex(
                "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
            s.sendall(second)
            s.shutdown(socket.SHUT_WR)
            s.settimeout(1)
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()
    good &= check("a ClientHello without an x25519 share is asked for another", asked)
    good &= check("still serving after six that sent something else instead", served())

    # 2d. Clients we can't serve: each gets seven bytes, a fatal alert with the reason, and
    # then the connection's end.
    def said(first, second=None):
        """What the server sends for these records, up to its closing the connection."""
        s = socket.create_connection((HOST, PORT), timeout=5)
        got = b""
        try:
            s.sendall(first)
            if second is not None:
                got = s.recv(4096)                  # (the HelloRetryRequest)
                s.sendall(second)
                got = b""
            while True:
                more = s.recv(4096)
                if not more:
                    break
                got += more
        except OSError as e:
            got += b" %r" % e
        s.close()
        return got

    def record(body):
        return bytes([22, 3, 1]) + len(body).to_bytes(2, "big") + bytes(body)

    PROTOCOL_VERSION, HANDSHAKE_FAILURE = bytes.fromhex("15030300020246"), bytes.fromhex("15030300020228")
    old = context()
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = old.wrap_bio(inc, out, server_hostname=NAME)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    good &= check("a client without TLS 1.3 is told \"protocol version\", and that is all",
                  said(out.read()) == PROTOCOL_VERSION)
    other = bytearray(hello)                    # our two cipher suites become one we don't have
    p = 38
    p += 1 + hello[p]
    for q in range(p + 2, p + 2 + int.from_bytes(hello[p:p + 2], "big"), 2):
        if hello[q:q + 2] in (b"\x13\x01", b"\x13\x03"):
            other[q:q + 2] = b"\x13\x02"
    good &= check("one that names none of our cipher suites is told \"handshake failure\"",
                  said(record(other)) == HANDSHAKE_FAILURE)

    # Which of our two a client gets: AES-128-GCM (13 01) if it names it, unless ChaCha20-
    # Poly1305 (13 03) is the first suite of TLS 1.3 (13 xx) it names. What else stands
    # in its list (a made-up suite in front, as browsers put one: GREASE; suites of TLS
    # 1.2) is not its first.
    def chosen(suites):
        """The cipher suite in the ServerHello for this machine's ClientHello with these suites."""
        p = 38 + 1 + hello[38]
        body = hello[:p] + len(suites).to_bytes(2, "big") + suites + hello[p + 2 + int.from_bytes(hello[p:p + 2], "big"):]
        body = body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:]
        s = socket.create_connection((HOST, PORT), timeout=5)
        got = b""
        try:
            s.sendall(record(body))
            while len(got) < 5 + 4 + 2 + 32 + 1 + hello[38] + 2:
                more = s.recv(4096)
                if not more:
                    break
                got += more
        except OSError:
            pass
        s.close()
        at = 5 + 4 + 2 + 32 + 1 + hello[38]
        return got[at:at + 2].hex() if got[:1] == b"\x16" and got[5:6] == b"\x02" else got[:7].hex()

    for name, suites, want in (
            ("OpenSSL's order (AES-256, ChaCha20, AES-128)", "130213031301", "1301"),
            ("a browser's (a made-up suite, AES-128, AES-256, ChaCha20)", "0a0a130113021303", "1301"),
            ("ChaCha20 first", "13031301", "1303"),
            ("a made-up suite, then ChaCha20, then AES-128", "3a3a130313021301", "1303"),
            ("suites of TLS 1.2 and a made-up one, then ChaCha20, then AES-128", "c02bcca9fafa13031301", "1303"),
            ("another suite of TLS 1.3 first, then ChaCha20, then AES-128", "130413031301", "1301"),
            ("AES-256 and ChaCha20, no AES-128", "13021303", "1303"),
            ("AES-128 last of many", "c02bc02fcca9cca8130213041305009c1301", "1301")):
        good &= check(f"a client that names {name} gets {'AES-128-GCM' if want == '1301' else 'ChaCha20-Poly1305'}",
                      chosen(bytes.fromhex(suites)) == want)
    groupless = bytearray(shareless[5:])        # x25519 is not among its groups either
    p = 38
    p += 1 + hello[p]
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    p += 1 + hello[p] + 2
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        if kind == 10:
            for q in range(p + 6, p + 4 + n, 2):
                if hello[q:q + 2] == b"\x00\x1d":
                    groupless[q:q + 2] = b"\x01\x00"
        p += 4 + n
    good &= check("one that has no x25519 is told \"handshake failure\"",
                  said(record(groupless)) == HANDSHAKE_FAILURE)
    good &= check("one that was asked for an x25519 share and sent none is told \"handshake failure\"",
                  said(shareless, ccs + shareless) == HANDSHAKE_FAILURE)
    good &= check("junk in a handshake record is told \"protocol version\"",
                  said(record(os.urandom(300))) == PROTOCOL_VERSION)
    good &= check("and a normal client is served after them", served())

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

    # 3b. A real ClientHello, cut short at every length, and with each of its lengths in
    # turn at its largest: the server walks it to find the key share, and must not walk
    # out of it. (A fault resets the machine: nothing would be served after that.)
    hello = client_hello()
    variants = [hello[:n] for n in range(1, len(hello))]
    for at, size in lengths(hello):
        variants.append(hello[:at] + b"\xff" * size + hello[at + size:])
        variants.append(hello[:at] + b"\x00" * size + hello[at + size:])
    for body in variants:
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(bytes([22, 3, 1]) + len(body).to_bytes(2, "big") + body)
        except OSError:
            pass
        s.close()
        time.sleep(0.002)   # (QEMU takes connections one at a time: faster than this, one in 20 waits a second)
    good &= check(f"still serving after {len(variants)} ClientHellos cut short or with a length gone wrong", served())
    good &= check("and the one they were made from is served", served())

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
        return buf == P80 * want

    good &= check("port 80: a request gets a response", plain([REQ], 1))
    good &= check("port 80: a request in three pieces gets one", plain([REQ[:5], REQ[5:-2], REQ[-2:]], 1))
    good &= check("port 80: two requests at once get two", plain([REQ + REQ], 2))
    good &= check("port 80: bytes without an empty line get none", plain([os.urandom(64).replace(b"\n", b"x") * 40], 0))
    good &= check("port 80: still serving", plain([REQ], 1))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
