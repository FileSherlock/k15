#!/usr/bin/env python3
"""mkdisk.py BOOT OS OUT: the disk image = boot sector, then the image. The boot sector is
told what the image's multiboot header says (where it is loaded: 1 MiB and a few bytes,
so that its code ends where a page does; and where it is entered) and how many sectors
it has (the three dwords before its signature: src/boot.asm reads the sectors in pieces
of 64). The disk is 8 MiB at least (sparse): SeaBIOS won't boot one of a few KiB."""
import struct
import sys

boot, osbin = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
assert len(boot) == 512 and boot[510:] == b"\x55\xaa" and boot[498:510] == bytes(12), "boot sector"
magic, flags, check, header, load, _, _, entry = struct.unpack("<8I", osbin[:32])
assert magic == 0x1BADB002 and (magic + flags + check) & 0xFFFFFFFF == 0 and flags & 0x10000, "the image's multiboot header"
assert header == load and 0x100000 <= load < 0x101000 and load <= entry < load + len(osbin), "where the image says it goes"
sectors = -(-len(osbin) // 512)
pieces = -(-sectors // 64) * 64                 # (it reads whole pieces: they must be there)
with open(sys.argv[3], "wb") as f:
    f.write(boot[:498] + struct.pack("<3I", load, entry, sectors) + boot[510:] + osbin.ljust(pieces * 512, b"\0"))
    f.truncate(max(8 << 20, -(-(512 + pieces * 512) >> 20) << 20))
