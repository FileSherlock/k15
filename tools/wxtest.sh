#!/usr/bin/env bash
# That only code is executed and neither code nor site is written is checked by doing each
# of the things that must not be possible, once, in an image built to do just that after
# it has set everything up (make WXTEST=n: write to the code, run the stack, write to the
# site, run the site, run a packet buffer). Each must be the machine's end: a fault, and
# with no handlers a reset, which makes this QEMU quit. An image that does none of them
# (WXTEST=0) must stay up and serve.
#   tools/wxtest.sh          (SMP=n for other machines than 2 processors)
cd "$(dirname "$0")/.." || exit 1
mkdir -p build-site
python3 tools/mksite.py build-site/www >/dev/null || exit 1
WHAT=("none of it" "writing to the code" "running the stack" "writing to the site" "running the site" "running a packet buffer")
bad=0
for n in 0 1 2 3 4 5; do
  export B=build-wx
  make -s -B B=$B SITE=build-site/www WXTEST=$n >/dev/null 2>&1 || { echo "BUILD FAILED (WXTEST=$n)"; exit 1; }
  PORT=$((8500 + n))
  HPORT=$((9500 + n))
  IMG=$B/os.bin
  source tools/vm.sh
  LOG=$(mktemp)
  qemu-system-x86_64 -nodefaults -display none -no-reboot -machine q35 -smp "${SMP:-2}" "${ACCEL[@]}" -m 256 \
    -drive "file=$B/disk.img,format=raw,if=none,id=d0,snapshot=on" \
    -netdev "user,id=n0,net=${GUEST%.*}.0/24,hostfwd=tcp:127.0.0.1:${PORT}-${GUEST}:443" \
    -device pcie-root-port,id=rp1,chassis=1 -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= \
    -device pcie-root-port,id=rp2,chassis=2 -device virtio-scsi-pci,bus=rp2 -device scsi-hd,drive=d0 >"$LOG" 2>&1 &
  pid=$!
  served=no
  for _ in $(seq 1 40); do
    kill -0 $pid 2>/dev/null || break
    if "${CURL[@]}" -o /dev/null "$URL"; then served=yes; break; fi
    sleep 0.25
  done
  alive=no
  kill -0 $pid 2>/dev/null && alive=yes
  kill $pid 2>/dev/null
  wait $pid 2>/dev/null
  rm -f "$LOG"
  if [[ $n == 0 ]]; then
    [[ $served == yes ]] && echo "ok   an image that does ${WHAT[$n]} serves" || { echo "FAIL the image that does ${WHAT[$n]} does not serve"; bad=1; }
  else
    [[ $served == no && $alive == no ]] && echo "ok   ${WHAT[$n]} is the machine's end" || { echo "FAIL ${WHAT[$n]}: the machine went on (served: $served, running: $alive)"; bad=1; }
  fi
done
exit $bad
