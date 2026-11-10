# Sourced by measure.sh and browsers.sh: the test machine (shaped like the server), and how a client
# reaches the server (its certificate's name, and the CA to trust if it is our private one).
# Needs PORT and IMG; B (default build) is where the image was built. Sets NAME, URL, CURL
# and NOCA (arrays), and boot starts QEMU (QEMU_PID).

B=${B:-build}
NAME=$(cat "$B/name")
URL="https://${NAME}:${PORT}/"
GUEST=$(cat "$B/ip")                                    # the address baked into the image
CURL=(curl -s --max-time 10 --connect-to "${NAME}:${PORT}:127.0.0.1:${PORT}")
NOCA=("${CURL[@]}")                                    # the same, trusting only the system's roots
[[ -s $B/ca.pem ]] && CURL+=(--cacert "$B/ca.pem")

# Hardware virtualisation where there is /dev/kvm (KVM=0: emulate instead; ~15 s to boot,
# 27 handshakes a second instead of 120).
ACCEL=(-cpu max)
[[ ${KVM:-1} == 1 && -w /dev/kvm ]] && ACCEL=(-accel kvm -cpu host)

boot() {
  QEMU_LOG=$(mktemp)
  qemu-system-x86_64 -nodefaults -display none -no-reboot -machine q35 "${ACCEL[@]}" -m 256 \
    -drive "file=${IMG%os.bin}disk.img,format=raw,if=none,id=d0,snapshot=on" \
    -netdev "user,id=n0,net=${GUEST%.*}.0/24,hostfwd=tcp:127.0.0.1:${PORT}-${GUEST}:443" \
    -device pcie-root-port,id=rp1,chassis=1 -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= \
    -device pcie-root-port,id=rp2,chassis=2 -device virtio-scsi-pci,bus=rp2 -device scsi-hd,drive=d0 >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  trap 'kill $QEMU_PID 2>/dev/null || true; rm -rf "$QEMU_LOG" ${TMP:-}' EXIT
  for _ in $(seq 1 40); do
    "${CURL[@]}" -o /dev/null "$URL" && return 0
    sleep 0.25
  done
  return 0   # the caller's first real request reports the failure
}
