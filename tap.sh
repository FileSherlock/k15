#!/usr/bin/env bash
# Boot the image on a tap interface instead of slirp and run a command against it (needs root
# and /dev/net/tun; from k1). Not the machine contract: a faster way to hold many connections,
# since slirp walks every open socket on each turn of QEMU's main loop (at 20,000 connections
# that already takes most of a core and slows the guest).
# Usage: sudo [B=build] [KVM=1] ./tap.sh COMMAND [ARGS...]     e.g. sudo ./tap.sh ./taprunc.sh
# The host is 10.0.2.2 plus 10.0.2.32-47; the guest is 10.0.2.15. The image is the unmodified
# one, so the host does what a tap needs: the guest answers no ARP and sends frames back with
# the Ethernet header it received, so its permanent neighbour entry is the tap's own MAC; and
# it takes every IPv4 frame for TCP, so everything else is dropped before it gets there.
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
MAC=$(ip -o link show "$TAP" | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
ip neigh replace 10.0.2.15 lladdr "$MAC" dev "$TAP" nud permanent
tc qdisc add dev "$TAP" clsact
tc filter add dev "$TAP" egress protocol ip prio 1 flower ip_proto tcp action pass
tc filter add dev "$TAP" egress protocol ip prio 2 matchall action drop

ACCEL=(-cpu max)
[[ ${KVM:-} == 1 ]] && ACCEL=(-accel kvm -cpu host)
LOG=$(mktemp)
qemu-system-x86_64 -nodefaults -display none -no-reboot "${ACCEL[@]}" -m "${MEM:-160}" -kernel "$IMG" \
  -netdev "tap,id=n0,ifname=$TAP,script=no,downscript=no" -device ne2k_isa,netdev=n0 >"$LOG" 2>&1 &
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
