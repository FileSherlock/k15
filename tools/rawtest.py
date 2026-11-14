#!/usr/bin/env python3
"""rawtest.py [SEED]: frames that no router would pass on, put on the wire next to the guest.

What a client's TCP sends is well-formed below TCP, and a router drops what is not. A
sender on the same link is held to nothing. So: frames whose IP header says a total
length of less than itself (0 to 39 bytes, where 40 is the least there can be: with a TCP
header behind them, with bytes drawn at random, and, for the lengths where the image once
went on to sum a few bytes, with a source address that makes those sum right), frames
that end in the middle of their headers, total lengths beyond the frame, IP headers with
options, TCP headers that say they are shorter than 20 bytes or longer than what is
there, and frames of every such kind with the rest drawn at random.

What must hold: the machine is still there (a fault is its end: QEMU, which tap.sh
starts with -no-reboot, is then gone) and serves a real client as before.

    unshare -Urn ./tap.sh python3 tools/rawtest.py        (the suite's `rawframes`; seconds)

(Until 2026-11-14 a total length below 20 passed for 4 GiB: its length less 20 was
compared, not it. The first such frame was the machine's end.)
"""
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hellofuzz import alive, real, HOST  # noqa: E402

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 1
TAP = os.environ.get("TAP", "k2t")
OURS = socket.inet_aton(HOST)


def ip(total, src, ihl=0x45, proto=6, frag=0):
    return struct.pack(">BBHHHBBH4s4s", ihl, 0, total & 0xFFFF, 0, frag, 64, proto, 0, src, OURS)


def tcp(sport, flags=0x02, off=0x50, seq=1, ack=0):
    return struct.pack(">HHIIBBHHH", sport, 443, seq, ack, off, flags, 65535, 0, 0)


def sums_right(total):
    """A source address with which the bytes the image summed for such a length (the
    pseudo header's first total - 8, in words) came to nothing: the way past its check."""
    n = (total - 8 + 1) // 2
    for low in range(65536):
        src = bytes([10, 0, low >> 8, low & 255])
        head = bytes([0, 6]) + struct.pack(">H", (total - 20) & 0xFFFF) + src + OURS
        s = sum(struct.unpack("<%dH" % n, head[:2 * n]))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        if s == 0xFFFF:
            return src
    return None


def main():
    rng = random.Random(SEED)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((TAP, 0))
    eth = b"\xff" * 6 + s.getsockname()[4] + b"\x08\x00"
    src = socket.inet_aton("10.0.2.34")
    frames = []
    for total in range(40):                             # a total length that is too short
        frames.append(eth + ip(total, src) + tcp(40000 + total) + bytes(6))
        frames.append(eth + ip(total, src) + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))))
        if 13 <= total <= 19 and sums_right(total):
            for flags in (0x02, 0x10, 0x18, 0x11, 0x04):
                frames.append(eth + ip(total, sums_right(total)) + tcp(41000 + total, flags) + bytes(64))
    whole = eth + ip(60, src) + tcp(42000) + bytes(20)
    frames += [whole[:n] for n in range(14, len(whole))]  # frames that end in their headers
    for total in (41, 60, 61, 100, 1500, 2000, 4000, 65535):    # total lengths beyond the frame
        frames.append(eth + ip(total, src) + tcp(43000) + bytes(8))
    for ihl in (0x40, 0x44, 0x46, 0x4F, 0x55, 0x65):    # other headers than ours
        frames.append(eth + ip(60, src, ihl=ihl) + tcp(44000) + bytes(40))
    for off in (0x00, 0x10, 0x40, 0x60, 0xA0, 0xF0):    # TCP headers of other lengths than they have
        frames.append(eth + ip(40, src) + tcp(45000, off=off))
        frames.append(eth + ip(44, src) + tcp(45001, off=off) + bytes(4))
    for _ in range(3000):                               # and all of it with the rest at random
        f = bytearray(rng.choice(frames))
        for _ in range(rng.choice((1, 2, 4, 16))):
            if len(f) > 14:
                f[rng.randrange(14, len(f))] = rng.randrange(256)
        if rng.random() < 0.5:
            f[16:18] = rng.choice((b"\0\0", b"\0\x13", b"\0\x14", b"\0\x27", b"\0\x28", bytes([rng.randrange(256), rng.randrange(256)])))
        frames.append(bytes(f))
    print("seed %d, %d frames" % (SEED, len(frames)), flush=True)
    for i, f in enumerate(frames):
        s.send(f)
        if i % 200 == 199:
            time.sleep(0.05)
            if not alive():
                print("FAIL: the machine was gone after frame %d: %s" % (i, f[:54].hex()))
                return 1
    time.sleep(0.3)
    ok = alive() and real()
    print("ok: the machine is there and serves as before" if ok else "FAIL: the machine no longer serves (seed %d)" % SEED)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
