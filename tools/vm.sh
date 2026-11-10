# Sourced by measure.sh, browsers.sh and score.sh: the machine contract, and how a client
# reaches the server (its certificate's name, and the CA to trust if it is our private one).
# Needs PORT and IMG; B (default build) is where the image was built. Sets NAME, URL, CURL
# and NOCA (arrays), and boot starts QEMU (QEMU_PID).

B=${B:-build}
NAME=$(cat "$B/name")
URL="https://${NAME}:${PORT}/"
CURL=(curl -s --max-time 10)
[[ $NAME =~ ^[0-9.]+$ ]] || CURL+=(--resolve "${NAME}:${PORT}:127.0.0.1")
NOCA=("${CURL[@]}")                                    # the same, trusting only the system's roots
[[ -s $B/ca.pem ]] && CURL+=(--cacert "$B/ca.pem")

# KVM=1 uses hardware virtualisation instead of emulation. It is not the default: the curve
# math gets much faster, but every byte to or from the NE2000 is a port access, which costs a
# VM exit each, so handshakes only go from ~26 to ~34 per second and keep-alive requests
# drop from ~8,500 to ~800 per second (Ryzen 7 3800X).
ACCEL=(-cpu max)
[[ ${KVM:-} == 1 ]] && ACCEL=(-accel kvm -cpu host)

boot() {
  QEMU_LOG=$(mktemp)
  qemu-system-x86_64 -nodefaults -display none -no-reboot "${ACCEL[@]}" -m 160 \
    -kernel "$IMG" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:443 \
    -device ne2k_isa,netdev=n0 >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  trap 'kill $QEMU_PID 2>/dev/null || true; rm -rf "$QEMU_LOG" ${TMP:-}' EXIT
  for _ in $(seq 1 40); do
    "${CURL[@]}" -o /dev/null "$URL" && return 0
    sleep 0.25
  done
  return 0   # the caller's first real request reports the failure
}
