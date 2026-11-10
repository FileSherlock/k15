#!/usr/bin/env python3
"""ip.py A.B.C.D        -> the address as the dword it is on the wire (for nasm -DOURIP=)
ip.py A.B.C.D FILE   -> write the address to FILE unless it already says so (so that make
                        rebuilds the image only when the address changes)"""
import os
import sys

ip = sys.argv[1]
a, b, c, d = (int(x) for x in ip.split("."))
if len(sys.argv) > 2:
    if not os.path.exists(sys.argv[2]) or open(sys.argv[2]).read() != ip:
        open(sys.argv[2], "w").write(ip)
else:
    print("0x%02X%02X%02X%02X" % (d, c, b, a))
