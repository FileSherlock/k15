#!/usr/bin/env bash
# Build, boot in QEMU, fetch the page with curl (which verifies the certificate chain and the
# name: no -k), report image size.
# Usage: ./measure.sh [image]   (default: build the asm image -> build/os.bin)
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8443}
IMG=${1:-}
if [[ -z "$IMG" ]]; then
  make -s all >/dev/null
  IMG=build/os.bin
fi
EXPECT=$(cat www/index.html)
source tools/vm.sh
boot

BODY=$("${CURL[@]}" "$URL") || { echo "FAIL: curl exit $? (verified fetch of $URL)"; cat "$QEMU_LOG"; exit 1; }
if [[ "$BODY" != "$EXPECT" ]]; then
  echo "FAIL: got '${BODY}'"
  exit 1
fi
# second and third request on fresh connections, plus keep-alive reuse
for _ in 1 2; do
  B2=$("${CURL[@]}" "$URL" "${URL}x") || { echo "FAIL: repeat"; exit 1; }
  [[ "$B2" == "$EXPECT"$'\n'"$EXPECT" ]] || { echo "FAIL: keep-alive got '$B2'"; exit 1; }
done
# and nobody who doesn't trust our CA gets in (the chain is checked, not waved through)
if [[ -s build/ca.pem ]] && curl -s --max-time 10 -o /dev/null "$URL"; then
  echo "FAIL: curl accepted the certificate without our CA"; exit 1
fi

SIZE=$(stat -c %s "$IMG")
echo "PASS  image=$IMG  size=${SIZE} bytes"
LST=${IMG%.bin}.lst
if [[ -f "$LST" ]]; then
  python3 tools/tbcheck.py "$LST" || true   # warns if TCG would run the handshake ~4x slower
  echo "--- largest routines/data (bytes) ---"
  python3 tools/sizes.py "$LST" 14
fi
