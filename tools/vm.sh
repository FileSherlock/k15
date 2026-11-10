# Sourced by measure.sh, browsers.sh and score.sh: the machine contract, and how a client
# reaches the server (its certificate's name, and the CA to trust if it is our private one).
# Needs PORT and IMG; sets NAME, URL, CURL (an array), and boot starts QEMU (QEMU_PID).

NAME=$(cat build/name)
URL="https://${NAME}:${PORT}/"
CURL=(curl -s --max-time 10)
[[ $NAME =~ ^[0-9.]+$ ]] || CURL+=(--resolve "${NAME}:${PORT}:127.0.0.1")
[[ -s build/ca.pem ]] && CURL+=(--cacert build/ca.pem)   # else: the system's roots

boot() {
  QEMU_LOG=$(mktemp)
  qemu-system-x86_64 -nodefaults -display none -no-reboot -cpu max -m 16 \
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
