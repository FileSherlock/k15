#!/usr/bin/env python3
"""jcc.py LISTING [ROUTINE...]: jumps that cross or end on a 32-byte boundary.

On Intel processors from Skylake to Cascade Lake (the cloud server's is one), a jump, call
or return whose bytes cross a 32-byte boundary, or whose last byte is the last of such a
block, is not kept in the decoded-instruction cache since the microcode update for the
"jump conditional code" erratum; nor is a compare or test fused with such a jump. A loop
with one of those is decoded again on every turn: several percent of a handshake when it
is in the field arithmetic. This lists them per routine from a NASM listing (nasm -l), so
that the routines that matter can be kept free of them (`align 32` in front, and a look
here after touching one). With routine names: only those, and exit 1 if they have any.
"""
import re
import sys

FUSE = re.compile(r"^(?:3[89AB]|8[0135]|8[45]|A[89]|F[67]|4[0-9A-F](?:3[89AB]|8[0135]|8[45]|F[67]|FF)|FF|0[0-3]|2[0-389AB])")


def is_jump(code):
    b = bytes.fromhex(code)
    if not b:
        return False
    if b[0] in (0xE8, 0xE9, 0xEB, 0xC3) or 0x70 <= b[0] <= 0x7F or 0xE0 <= b[0] <= 0xE3:
        return True
    if b[0] == 0x0F and len(b) > 1 and 0x80 <= b[1] <= 0x8F:
        return True
    if b[0] == 0xFF and len(b) > 1 and (b[1] >> 3) & 7 in (2, 4):
        return True
    return False


def fit(path, names):
    """For each routine named: what would lie on a boundary if it began K bytes behind a
    32-byte boundary, for every K (it is assumed to begin on one now)."""
    routine, prev, jumps = "?", None, {}
    for line in open(path, errors="replace"):
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+([0-9A-F\[\]\(\)]+)-?\s+(?:<\d+>\s*)?(.*)", line)
        lab = re.match(r"\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?(?:<\d+>\s*)?([A-Za-z_]\w*):", line)
        if lab:
            routine = lab.group(1)
            if m:
                jumps.setdefault(routine, {"at": int(m.group(1), 16), "j": []})
        if not m:
            continue
        addr, code, src = int(m.group(1), 16), re.sub(r"[^0-9A-F]", "", m.group(2)), m.group(3)
        if len(code) % 2 or not code:
            prev = None
            continue
        n = len(code) // 2
        r = jumps.setdefault(routine, {"at": addr, "j": []})
        if is_jump(code):
            start = addr
            if prev and prev[0] + prev[1] == addr and FUSE.match(prev[2]) and (0x70 <= int(code[:2], 16) <= 0x7F or code[:2] == "0F"):
                start = prev[0]
            r["j"].append((start - r["at"], addr + n - 1 - r["at"], src.split(";")[0].strip()))
        prev = (addr, n, code)
    for name in names:
        r = jumps[name]
        base = r["at"] % 32
        print(f"{name} (begins {base} behind a boundary now, {len(r['j'])} jumps):")
        for k in range(32):
            bad = [src for a, b, src in r["j"] if (a + k) // 32 != (b + k) // 32 or (b + k) % 32 == 31]
            print(f"  {k:2d}: {len(bad)}  {'; '.join(bad[:6])}")


def main(path, only):
    if only and only[0] == "fit":
        return fit(path, only[1:])
    routine, prev, bad = "?", None, {}
    for line in open(path, errors="replace"):
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+([0-9A-F\[\]\(\)]+)-?\s+(?:<\d+>\s*)?(.*)", line)
        lab = re.match(r"\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?(?:<\d+>\s*)?([A-Za-z_]\w*):", line)
        if lab:
            routine = lab.group(1)
        if not m:
            continue
        addr, code, src = int(m.group(1), 16), re.sub(r"[^0-9A-F]", "", m.group(2)), m.group(3)
        if len(code) % 2 or not code:
            prev = None
            continue
        n = len(code) // 2
        if is_jump(code):
            start = addr
            if prev and prev[0] + prev[1] == addr and FUSE.match(prev[2]) and (0x70 <= int(code[:2], 16) <= 0x7F or code[:2] == "0F"):
                start = prev[0]             # (a compare or test that fuses with the jump)
            end = addr + n - 1
            if start // 32 != end // 32 or end % 32 == 31:
                bad.setdefault(routine, []).append((addr, src.split(";")[0].strip()))
        prev = (addr, n, code)
    if only:
        hit = {r: bad[r] for r in only if r in bad}
        for r, items in hit.items():
            for addr, src in items:
                print(f"{r}: {addr:#x} {src}")
        return 1 if hit else 0
    for r, items in sorted(bad.items(), key=lambda kv: -len(kv[1])):
        print(f"{len(items):3d}  {r}: " + ", ".join(src for _, src in items[:4]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
