#!/usr/bin/env bash
# Score = connections / KiB of image. Builds, boots in QEMU (same machine as measure.sh),
# every connection verifying the certificate,
# then `tools/load.py hold` opens TLS connections and keeps them all open, fetching the page
# over every one at 64, 128, 256, ... open; "connections" is the most that worked at once.
# Usage: ./score.sh [image] [max connections]   (default: build/os.bin, until out of ports)
#
# By default the client uses every unprivileged source port: explicit binds to 1024-32767 and
# 61000-65535, then the kernel's own ephemeral range, ~64.5K connections in ~45 minutes. While
# it runs, most of 127.0.0.1's ports are taken (don't start servers then). PORTS=auto keeps to
# the ephemeral range: 28,232 connections in ~8 minutes.
set -euo pipefail
cd "$(dirname "$0")"
export PORTS=${PORTS:-1024-32767,61000-65535,auto}

PORT=${PORT:-8445}
IMG=${1:-}
export B=${B:-build}
if [[ -z "$IMG" ]]; then
  make -s all B="$B" CERT="${CERT:-cert}" >/dev/null
  IMG=$B/os.bin
fi
source tools/vm.sh
boot

OUT=$(PORT=$PORT python3 tools/load.py hold ${2:-} | tee /dev/stderr)
CONN=$(sed -n 's/^connections: \([0-9]*\).*/\1/p' <<<"$OUT")
SIZE=$(stat -c %s "$IMG")
python3 -c "print(f'SCORE {$CONN / ($SIZE / 1024):.1f}  = $CONN connections / $SIZE bytes')"
