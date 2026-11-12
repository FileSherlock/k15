#!/usr/bin/env python3
"""mkdisk.py BOOT OS OUT: the disk image = boot sector, then the image. The boot sector is
told how many sectors the image has (the dword before its signature: src/boot.asm reads
them in pieces of 64). The disk is 8 MiB at least (sparse): SeaBIOS won't boot one of a
few KiB."""
import sys

boot, osbin = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
assert len(boot) == 512 and boot[510:] == b"\x55\xaa" and boot[506:510] == bytes(4), "boot sector"
sectors = -(-len(osbin) // 512)
pieces = -(-sectors // 64) * 64                 # (it reads whole pieces: they must be there)
with open(sys.argv[3], "wb") as f:
    f.write(boot[:506] + sectors.to_bytes(4, "little") + boot[510:] + osbin.ljust(pieces * 512, b"\0"))
    f.truncate(max(8 << 20, -(-(512 + pieces * 512) >> 20) << 20))
