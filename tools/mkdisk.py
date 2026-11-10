#!/usr/bin/env python3
"""mkdisk.py BOOT OS OUT: the disk image = boot sector, then the image, padded to the 64
sectors the boot sector reads (src/boot.asm: SECTORS), in an 8 MiB (sparse) disk."""
import sys

boot, osbin = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
assert len(boot) == 512 and boot[510:] == b"\x55\xaa", "boot sector"
if len(osbin) > 64 * 512:
    sys.exit("os.bin is over 32 KiB: raise SECTORS in src/boot.asm and here")
with open(sys.argv[3], "wb") as f:
    f.write(boot + osbin.ljust(64 * 512, b"\0"))
    f.truncate(8 << 20)  # sparse: SeaBIOS won't boot a disk of a few KiB. Only the first 65 sectors matter.
