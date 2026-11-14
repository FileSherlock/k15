#!/usr/bin/env bash
# Boot the image on a tap interface instead of slirp and run a command against it: a real
# Ethernet segment (ARP, the host's own traffic, random initial sequence numbers), and no
# slirp walking every open socket. No root needed inside a throwaway namespace:
# Usage: [B=build] [KVM=1] [SMP=1] [MEM=n] [LOSS=1] [REORDER=25] [DELAY=20] [MTU=n] unshare -Urn ./tap.sh COMMAND [ARGS...]   e.g. ... ./taprunc.sh 2000 1024 4
# (The VM has 2 processors and 256 MiB unless SMP and MEM say otherwise.)
# The host is 10.0.2.2 plus 10.0.2.32-63; the guest is 10.0.2.15.
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
for i in $(seq 32 63); do ip addr add "10.0.2.$i/24" dev "$TAP"; done
ip link set "$TAP" up
# LOSS=n: drop n% of the packets in each direction (host -> guest by netem, guest -> host by
# an ingress filter), and MTU=n sets the tap's MTU (a small one splits the client's segments)
if [[ -n ${LOSS:-} ]]; then
  tc qdisc add dev "$TAP" root netem loss "$LOSS%"
  tc qdisc add dev "$TAP" handle ffff: ingress
  tc filter add dev "$TAP" parent ffff: protocol ip u32 match u32 0 0 action gact pass random netrand drop $((100 / LOSS))
fi
# REORDER=n: n% of the packets to the guest overtake the others, which are held 5 ms (not with LOSS)
[[ -n ${REORDER:-} ]] && tc qdisc add dev "$TAP" root netem delay 5ms reorder "$REORDER%"
# DELAY=n: what goes to the guest takes n ms (a round trip of that length; not with LOSS or REORDER)
[[ -n ${DELAY:-} ]] && tc qdisc add dev "$TAP" root netem delay "${DELAY}ms" limit 100000
[[ -n ${MTU:-} ]] && ip link set "$TAP" mtu "$MTU"
ACCEL=(-cpu max)
[[ ${KVM:-1} == 1 && -w /dev/kvm ]] && ACCEL=(-accel kvm -cpu host)
LOG=$(mktemp)
# MON=path: QEMU's monitor on that unix socket (to ask a guest that hangs where it is)
qemu-system-x86_64 -nodefaults -display none ${MON:+-monitor unix:$MON,server,nowait} -no-reboot -machine q35 -smp "${SMP:-2}" "${ACCEL[@]}" -m "${MEM:-256}" -drive "file=${IMG%os.bin}disk.img,format=raw,if=none,id=d0,snapshot=on" \
  -netdev "tap,id=n0,ifname=$TAP,script=no,downscript=no" -device pcie-root-port,id=rp1,chassis=1 -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= -device pcie-root-port,id=rp2,chassis=2 -device virtio-scsi-pci,bus=rp2 -device scsi-hd,drive=d0 >"$LOG" 2>&1 &
export QEMU_PID=$!
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
