#!/usr/bin/env python3
"""pack.py SITE_DIR OUT_DIR: a folder of files becomes what the image serves.

Every file is turned into the complete HTTP response it will be sent as (status line,
headers, body), so the server has nothing to compose: it looks a request's path up and
sends the bytes it finds (for HEAD, their first part). The paths are found through a
hash table. What the server knows of all this is in OUT_DIR/site.bin, which ends the image:

  the path table   2^k slots of (FNV-1a hash of the path, where its record is; 0: empty),
                   probed linearly from hash & (2^k - 1); at most half full
  the responses    16 bytes each: where its bytes are, how many, how many of them are the
                   head, flags (1: the connection is closed after it)
  path records     which response (a word), the path's length (a word), the path
  the bytes

(all offsets from the start of site.bin) and in OUT_DIR/site.inc, the handful of numbers
the code is assembled with. Paths are what a browser sends: percent-encoded where a URL
must be, compared byte for byte, without the query. A directory with an index.html is
served at its name with a slash, and without the slash it redirects there. 404.html, if
there is one, is what unknown paths get (with status 404).

For the tests OUT_DIR/site.json says what each path must return, and OUT_DIR/page80.bin
is what port 80 says to every request.

Environment: P80 = page (port 80 answers every request with the response for "/", the
default) or redirect (with a redirect to https://NAME/, NAME from OUT_DIR/name);
CACHE = seconds a browser may keep a file (default 600, empty: no such header);
HSTS = seconds for Strict-Transport-Security (default: no such header);
HEADERS = further header lines for every file, separated by newlines or by ";;".
"""
import hashlib
import json
import mimetypes
import os
import sys
from urllib.parse import quote

TYPES = {
    ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".json": "application/json",
    ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
    ".xml": "application/xml", ".svg": "image/svg+xml", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    ".avif": "image/avif", ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
    ".ttf": "font/ttf", ".pdf": "application/pdf", ".wasm": "application/wasm",
    ".webmanifest": "application/manifest+json", ".mp4": "video/mp4", ".webm": "video/webm",
    ".mp3": "audio/mpeg", ".zip": "application/zip", ".gz": "application/gzip",
}
MAX_FILE = 1 << 30      # a response's bytes on the wire are counted in 31 bits
MAX_SITE = 768 << 20    # the image, and all that boot puts behind it, lies in the first GiB


def fnv(path):
    h = 0x811C9DC5
    for b in path:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def content_type(name):
    ext = os.path.splitext(name)[1].lower()
    return TYPES.get(ext) or mimetypes.guess_type(name)[0] or "application/octet-stream"


def main(site, out):
    env = os.environ.get
    cache, hsts = env("CACHE", "600"), env("HSTS", "")
    common = [b"Server: k3"]
    if cache:
        common.append(b"Cache-Control: max-age=%d" % int(cache))
    if hsts:
        common.append(b"Strict-Transport-Security: max-age=%d" % int(hsts))
    common.append(b"X-Content-Type-Options: nosniff")
    common += [line.strip().encode() for line in env("HEADERS", "").replace(";;", "\n").split("\n") if line.strip()]

    def response(status, headers, body):
        head = b"\r\n".join([b"HTTP/1.1 " + status] + headers + [b"Content-Length: %d" % len(body)]) + b"\r\n\r\n"
        return head, body

    def page(status, ctype, body):
        return response(status, [b"Server: k3", b"Content-Type: " + ctype.encode()] + common[1:], body)

    responses = []      # (head, body, flags)
    index = {}          # (head, body, flags) -> its number

    def add(head, body, flags=0):
        key = (head, body, flags)
        if key not in index:
            index[key] = len(responses)
            responses.append(key)
        return index[key]

    add(b"", b"")       # number 0: nothing (what a connection has in hand before its first request)
    paths = {}          # request path -> response number
    files = []
    for root, dirs, names in os.walk(site):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") or d == ".well-known")
        for name in sorted(names):
            if not name.startswith("."):
                files.append(os.path.join(root, name))
    not_found = None
    for path in files:
        rel = os.path.relpath(path, site).replace(os.sep, "/")
        body = open(path, "rb").read()
        if len(body) >= MAX_FILE:
            sys.exit(f"pack.py: {rel} is too large (the limit is 1 GiB)")
        url = "/" + quote(rel, safe="/~!$&'()*+,;=:@-._")
        ctype = content_type(rel)
        n = add(*page(b"200 OK", ctype, body))
        paths[url.encode()] = n
        if rel == "404.html":
            not_found = (ctype, body)
        if os.path.basename(rel) == "index.html":
            folder = url[:-len("index.html")]               # "/" or "/a/b/"
            paths[folder.encode()] = n
            if folder != "/":
                head, _ = response(b"301 Moved Permanently", [b"Server: k3", b"Location: " + folder.encode()], b"")
                paths.setdefault(folder[:-1].encode(), add(head, b""))
    ctype, body = not_found or ("text/plain; charset=utf-8", b"404 Not Found\n")
    a404 = add(*response(b"404 Not Found", [b"Server: k3", b"Content-Type: " + ctype.encode()], body))
    head, _ = response(b"405 Method Not Allowed", [b"Server: k3", b"Allow: GET, HEAD", b"Connection: close"], b"")
    a405 = add(head, b"", 1)

    # port 80: one response for every request
    name = open(os.path.join(out, "name")).read().strip() if os.path.exists(os.path.join(out, "name")) else ""
    if env("P80", "page") == "redirect":
        host = f"[{name}]" if ":" in name else name
        head, body = response(b"301 Moved Permanently", [b"Server: k3", b"Location: https://" + host.encode() + b"/"], b"")
        p80 = head + body
    else:
        head, body, _ = responses[paths.get(b"/", a404)]
        p80 = head + body

    # the layout
    slots = 2
    while slots < 2 * len(paths):
        slots *= 2
    at = slots * 8
    recs_at = at + 16 * len(responses)
    recs, rec_off = b"", {}
    for path, n in sorted(paths.items()):
        if len(path) > 0xFFFF:
            sys.exit("pack.py: a path of over 64 KB")
        rec_off[path] = recs_at + len(recs)
        recs += n.to_bytes(2, "little") + len(path).to_bytes(2, "little") + path
    blobs_at = recs_at + len(recs)
    blobs, table = b"", b""
    for head, body, flags in responses:
        table += (blobs_at + len(blobs)).to_bytes(4, "little") + (len(head) + len(body)).to_bytes(4, "little") \
            + len(head).to_bytes(4, "little") + flags.to_bytes(4, "little")
        blobs += head + body
    p80_at = blobs_at + len(blobs)
    blobs += p80
    hashed = [(0, 0)] * slots
    for path, off in rec_off.items():
        h = fnv(path)
        i = h & (slots - 1)
        while hashed[i][1]:
            i = (i + 1) & (slots - 1)
        hashed[i] = (h, off)
    data = b"".join(h.to_bytes(4, "little") + off.to_bytes(4, "little") for h, off in hashed) + table + recs + blobs
    if len(responses) > 0x7FFF:
        sys.exit("pack.py: more than 32,767 different responses")
    if len(data) > MAX_SITE:
        sys.exit(f"pack.py: the site is {len(data) >> 20} MiB; the limit is {MAX_SITE >> 20} MiB")

    with open(os.path.join(out, "site.bin"), "wb") as f:
        f.write(data)
    with open(os.path.join(out, "site.inc"), "w") as f:
        f.write("; generated by tools/pack.py: what os.asm needs to know of site.bin\n"
                f"%assign SITE_LEN {len(data)}\n"
                f"PT_MASK equ {slots - 1}\nAT_OFF equ {at}\nA_404 equ {a404}\nA_405 equ {a405}\n"
                f"P80_OFF equ {p80_at}\nP80_LEN equ {len(p80)}\n")
    with open(os.path.join(out, "page80.bin"), "wb") as f:
        f.write(p80)
    want = {}
    for path, n in paths.items():
        head, body, _ = responses[n]
        want[path.decode()] = {"status": int(head.split()[1]), "head": head.decode("latin-1"),
                               "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    head, body, _ = responses[a404]
    meta = {"paths": want, "not_found": {"head": head.decode("latin-1"), "length": len(body),
                                         "sha256": hashlib.sha256(body).hexdigest()},
            "not_allowed": responses[a405][0].decode("latin-1"), "files": len(files), "bytes": len(data)}
    with open(os.path.join(out, "site.json"), "w") as f:
        json.dump(meta, f, indent=1)
    print(f"site: {len(files)} files, {len(paths)} paths, {len(data)} bytes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
