#!/usr/bin/env bash
# The site test: an image with tools/mksite.py's site in it (in $B, default build-site: 80
# files, one of 1.5 MiB, so the image is over 1 MiB and everything else sits higher) must
# serve every path as tools/pack.py made it, to every kind of client tools/sitecheck.py
# plays.
#   tools/sitetest.sh [quick]                   through QEMU's own network
#   tools/sitetest.sh tap [quick]               over tap (run it as: unshare -Urn tools/sitetest.sh tap),
#                                               where LOSS=3, REORDER=25, MTU=600, SMP=n mean what they
#                                               mean to ./tap.sh
# BIG=n: the large file has n MiB (default 1.5). ISNTOP=n ISNBITS=b: an image whose initial
# sequence numbers all begin with n's top b bits (default 12): with 0x7FF00000 or
# 0xFFF00000 every connection crosses 2^31 or 2^32 within 1 MiB of what we send; with more
# bits sooner, but then not with loss (the SYN cookie checks that many bits less, and a
# connection whose first segment was lost can be begun by its second). KEYLIFE=n: an image
# whose connections may seal 2^n records (make KEYLIFE=n), and the check that they don't
# seal more. NOTSO=1: an image that sends a segment a frame also over tap, where the card
# would cut frames into segments for it (a control for the runs that do).
cd "$(dirname "$0")/.." || exit 1
export B=${B:-build-site}
mkdir -p "$B"
python3 tools/mksite.py "$B/www" ${BIG:-1.5} >/dev/null || exit 1
make -s B="$B" SITE="$B/www" CERT="${CERT:-cert}" ISNTOP="${ISNTOP:-}" ISNBITS="${ISNBITS:-}" KEYLIFE="${KEYLIFE:-}" NOTSO="${NOTSO:-}" BIGSH="${BIGSH:-}" >/dev/null || { echo "BUILD FAILED"; exit 1; }
if [[ ${1:-} == tap ]]; then
  shift
  exec ./tap.sh env HOST=10.0.2.15 PORT=443 SRC=10.0.2.32 T="${T:-40}" python3 tools/sitecheck.py "$@"
fi
PORT=${PORT:-8483}
IMG=$B/os.bin
source tools/vm.sh
boot
PORT=$PORT python3 tools/sitecheck.py "$@"
