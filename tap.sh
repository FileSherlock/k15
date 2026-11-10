#!/usr/bin/env bash
# Boot the image on a tap interface instead of slirp and run a command against it: a real
# Ethernet segment (ARP, the host's own traffic, random initial sequence numbers), and no
# slirp walking every open socket. No root needed inside a throwaway namespace:
# Usage: [B=build] [KVM=1] unshare -Urn ./tap.sh COMMAND [ARGS...]   e.g. ... ./taprunc.sh 2000 1024 4
# The host is 10.0.2.2 plus 10.0.2.32-47; the guest is 10.0.2.15.
set -euo pipefail
cd "$(dirname "$0")"
export B=${B:-build}
IMG=${IMG:-$B/os.bin}
NAME=$(cat "$B/name")
TAP=k2t

ip link del "$TAP" 2>/dev/null || true
ip tuntap add dev "$TAP" mode tap
sysctl -q "net.ipv6.conf.$TAP.disable_ipv6=1" 2>/dev/null || true
ip link set "$TAP" multicast off
ip addr add 10.0.2.2/24 dev "$TAP"
for i in $(seq 32 47); do ip addr add "10.0.2.$i/24" dev "$TAP"; done
ip link set "$TAP" up
ACCEL=(-cpu max)
[[ ${KVM:-1} == 1 && -w /dev/kvm ]] && ACCEL=(-accel kvm -cpu host)
LOG=$(mktemp)
qemu-system-x86_64 -nodefaults -display none -no-reboot -machine q35 "${ACCEL[@]}" -m "${MEM:-160}" -drive "file=${IMG%os.bin}disk.img,format=raw,if=none,id=d0,snapshot=on" \
  -netdev "tap,id=n0,ifname=$TAP,script=no,downscript=no" -device pcie-root-port,id=rp1,chassis=1 -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= -device pcie-root-port,id=rp2,chassis=2 -device virtio-scsi-pci,bus=rp2 -device scsi-hd,drive=d0 >"$LOG" 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true; wait $QEMU_PID 2>/dev/null || true; ip link del '"$TAP"' 2>/dev/null || true; rm -f "$LOG"' EXIT

CURL=(curl -s --max-time 3 -o /dev/null --interface 10.0.2.32 --connect-to "$NAME:443:10.0.2.15:443")
[[ -s $B/ca.pem ]] && CURL+=(--cacert "$B/ca.pem")
up=
for _ in $(seq 1 40); do
  if "${CURL[@]}" "https://$NAME/"; then up=1; break; fi
  sleep 0.25
done
[[ -n "$up" ]] || { echo "FAIL: guest not answering over tap (verified fetch)"; cat "$LOG"; exit 1; }
"$@"
