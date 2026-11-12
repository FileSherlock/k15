#!/usr/bin/env bash
# Start the image on a test server that runs Linux with GRUB (BIOS boot), without touching
# its installation: the image goes to /boot/k3.bin, GRUB gets a "k3" entry that loads it as
# a multiboot kernel, and the server reboots into it ONCE (grub-reboot). Any later reset
# boots Linux again: the provider's reset button, or tools/knock.sh if the image was built
# with KNOCK=a,b (the ports are in $B/knock).
# Usage: B=build-hz tools/deploy.sh root@a.b.c.d
set -euo pipefail
cd "$(dirname "$0")/.."
B=${B:-build-hz}
HOST=$1
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

# (the image holds the key: on the server it is for root's eyes only, from its first byte)
"${SSH[@]}" 'umask 077 && rm -f /boot/k3.bin.new && cat > /boot/k3.bin.new && chmod 600 /boot/k3.bin.new && mv /boot/k3.bin.new /boot/k3.bin' < "$B/os.bin"
"${SSH[@]}" 'set -e
if ! grep -q "menuentry \"k3\"" /etc/grub.d/40_custom; then
  UUID=$(findmnt -no UUID /boot 2>/dev/null || findmnt -no UUID /)
  cat >> /etc/grub.d/40_custom <<EOF
menuentry "k3" --id k3 {
    insmod part_gpt
    insmod ext2
    insmod multiboot
    search --no-floppy --fs-uuid --set=root $UUID
    multiboot /boot/k3.bin
}
EOF
  update-grub 2>&1 | tail -1
fi
grub-reboot k3
sync
echo "rebooting into k3 once"
nohup sh -c "sleep 1; reboot" >/dev/null 2>&1 &'
