#!/usr/bin/env bash
# End-to-end RAM-only ceremony for the 15kb.org $200 Bitcoin bounty:
#   tools/bounty_ceremony.sh --dry-run      test keygen, proof & raw disk build in /dev/shm
#   tools/bounty_ceremony.sh [--staging]    live deploy to Hetzner k3 (/dev/sda, wipes Ubuntu)
#   tools/bounty_ceremony.sh --redeploy     the same key and certificate again, from the 24 words:
#                                           for a change of the site or the system before the deadline
#   tools/bounty_ceremony.sh --revoke       revoke cert via saved ACME account key (no server.key)
#
# A rehearsal on another server: SERVER=NAME HOST=ADDRESS DOMAIN=NAME (and SAN=NAME) before any of
# these. Then the page is changed in a copy, the proof and the certificate go to cert-DOMAIN/, and
# 15kb.org's renewal timer is left alone.
#
# All secret material (server.key, regs.inc, os.bin, disk.img) lives exclusively in /dev/shm
# (tmpfs in RAM) and is shredded on exit. Write down the 24 BIP-39 words when prompted.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

SERVER=${SERVER:-k3}
HOST=${HOST:-2.28.113.14}
DOMAIN=${DOMAIN:-15kb.org}
if [[ $DOMAIN == 15kb.org ]]; then
  LIVE=1
  SAN=${SAN-www.15kb.org}
  PROOF=bounty.proof
  ACME_TAR="$HOME/.config/k15-acme-account.tar.gz"
else
  LIVE=0
  SAN=${SAN-}
  PROOF="cert-$DOMAIN/bounty.proof"
  ACME_TAR="$HOME/.config/k15-acme-account-$DOMAIN.tar.gz"
fi
PUB_PEM="cert-$DOMAIN/bounty-server.pem"
SANOPT=()
[[ -n $SAN ]] && SANOPT=(--san "$SAN")

die() { echo "bounty_ceremony: $*" >&2; exit 1; }

[[ $(df -T /dev/shm | awk 'NR==2 {print $2}') == tmpfs ]] || die "/dev/shm is not tmpfs"
WORK=$(mktemp -d /dev/shm/k15-bounty.XXXXXX)
cleanup() {
  if [[ -d ${WORK:-} ]]; then
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

isip() { [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || $1 == *:* ]]; }
[[ $LIVE == 1 || $SERVER != k3 ]] || die "$DOMAIN is not 15kb.org, but SERVER is k3: say SERVER= and HOST= too"
[[ $LIVE == 0 || $HOST == 2.28.113.14 ]] || die "15kb.org is not on $HOST: say DOMAIN= too"

# The page gets the address and the day the certificate ends, and the image is packed in RAM.
# (For 15kb.org the page and the README of this folder are changed; for a rehearsal, a copy.)
pack_image() {
  local site=site files=(site/index.html README.md)
  if [[ $LIVE == 0 ]]; then
    cp -r site "$WORK/site"
    site=$WORK/site files=("$WORK/site/index.html")
  fi
  ADDR="$ADDR" DEADLINE="$DEADLINE" python3 - "${files[@]}" <<'PY'
import os, re, sys
addr, dl = os.environ["ADDR"], os.environ["DEADLINE"]
for path in sys.argv[1:]:
    s = open(path, encoding="utf-8").read()
    s = re.sub(r"bc1q[a-z0-9]{38}", addr, s)
    s = re.sub(r"until 20[0-9]{2}-[0-9]{2}-[0-9]{2}", f"until {dl}", s)
    open(path, "w", encoding="utf-8").write(s)
PY
  ./k15 pack "$site" -n "$DOMAIN" "${SANOPT[@]}" -i "$HOST" -c "$WORK/cert" -o "$WORK/build" --hsts 31536000
}

SSHR=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts")
rescue() {
  local key i
  key=$(hcloud ssh-key list -o noheader -o columns=id | head -n1)
  [[ -n $key ]] || die "no SSH key in hcloud (hcloud ssh-key list)"
  hcloud server enable-rescue --type linux64 --ssh-key "$key" "$SERVER" >/dev/null
  hcloud server reset "$SERVER" >/dev/null
  echo "Waiting for Hetzner Rescue SSH on $HOST..."
  for i in $(seq 1 60); do
    sleep 3
    if ssh "${SSHR[@]}" "root@$HOST" 'uname -a' >/dev/null 2>&1; then
      return 0
    fi
  done
  die "Rescue did not answer SSH on $HOST within 3 minutes"
}

write_disk() {
  gzip -c "$WORK/build/disk.img" | ssh "${SSHR[@]}" "root@$HOST" '
    set -euo pipefail
    blkdiscard -f /dev/sda 2>/dev/null || dd if=/dev/zero of=/dev/sda bs=1M count=128 conv=fsync status=none
    gunzip | dd of=/dev/sda bs=1M conv=fsync status=none
    sync
    nohup sh -c "sleep 1; reboot" >/dev/null 2>&1 &
  '
}

# Is it up, and is what it shows the certificate whose key the proof is about? A certificate the
# world trusts is asked for by name, as anyone would; one it does not (staging, a rehearsal with
# our own) is compared with the one we hold, and the proof is checked against that.
check_live() {
  local i ca=() sni=(-servername "$DOMAIN")
  openssl verify -untrusted "$PUB_PEM" "$PUB_PEM" >/dev/null 2>&1 || ca=(--insecure)
  isip "$DOMAIN" && sni=(-noservername)
  for i in $(seq 1 30); do
    sleep 2
    if curl -s --max-time 4 "${ca[@]}" --connect-to "$DOMAIN:443:$HOST:443" -o /dev/null "https://$DOMAIN/"; then
      break
    fi
    [[ $i == 30 ]] && die "https://$DOMAIN/ did not come up within 60 s"
  done
  if [[ ${#ca[@]} == 0 ]]; then
    python3 tools/bounty.py --verify "$DOMAIN" "$PROOF"
  else
    [[ $(openssl s_client -connect "$HOST:443" "${sni[@]}" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256) == \
       $(openssl x509 -noout -fingerprint -sha256 -in "$PUB_PEM") ]] || die "$HOST does not show the certificate in $PUB_PEM"
    python3 tools/bounty.py --verify "$PUB_PEM" "$PROOF"
  fi
}
same_key() {   # CERT KEY: is the certificate for this key?
  [[ $(openssl x509 -pubkey -noout -in "$1" 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) == \
     $(openssl pkey -in "$2" -pubout -outform DER | sha256sum) ]]
}

if [[ ${1:-} == "--revoke" ]]; then
  [[ -f $ACME_TAR ]] || die "no saved ACME account at $ACME_TAR"
  [[ -f $PUB_PEM ]] || die "no saved public certificate at $PUB_PEM"
  mkdir -p "$WORK/le"
  tar -xzf "$ACME_TAR" -C "$WORK/le"
  certbot revoke --non-interactive --config-dir "$WORK/le/etc/letsencrypt" \
    --work-dir "$WORK/work" --logs-dir "$WORK/logs" \
    --cert-path "$PUB_PEM" --reason keycompromise
  echo "Certificate revoked (keycompromise)."
  exit 0
fi

DRY=0
REDEPLOY=0
STAGING=""
for arg in "$@"; do
  case $arg in
    --dry-run) DRY=1 ;;
    --staging) STAGING="--staging" ;;
    --redeploy) REDEPLOY=1 ;;
    *) die "unknown flag '$arg' (expected --dry-run, --staging, --redeploy, or --revoke)" ;;
  esac
done

if [[ $REDEPLOY == 1 ]]; then
  [[ -f $PUB_PEM && -f $PROOF ]] || die "no $PUB_PEM or no $PROOF: nothing to deploy again"
  openssl x509 -checkend 0 -noout -in "$PUB_PEM" >/dev/null || die "the certificate in $PUB_PEM has ended: this bounty is over"
  echo "=== Step 1: The key again, from your 24 words (in RAM) ==="
  mkdir -p "$WORK/cert"
  ADDR=$(python3 tools/bounty.py --restore --out "$WORK/cert/server.key")
  [[ $ADDR =~ ^bc1q[a-z0-9]{38}$ ]] || die "unexpected BTC address '$ADDR'"
  same_key "$PUB_PEM" "$WORK/cert/server.key" || die "these words are not the key of the certificate in $PUB_PEM"
  python3 tools/bounty.py --verify "$PUB_PEM" "$PROOF" | grep -qx "BTC address: $ADDR" || die "$PROOF is not about $ADDR"
  cp "$PUB_PEM" "$WORK/cert/server.pem"
  DEADLINE=$(date -u -d "$(openssl x509 -enddate -noout -in "$PUB_PEM" | cut -d= -f2)" +%Y-%m-%d)
  echo "=== Step 2: Packing disk.img for $ADDR (until $DEADLINE) ==="
  pack_image
  echo "=== Step 3: Booting $SERVER ($HOST) into Hetzner Rescue & writing raw disk.img ==="
  rescue
  write_disk
  echo "=== Step 4: Waiting for k15 & checking certificate and proof ==="
  check_live
  echo ""
  echo "=== LIVE AGAIN WITH THE SAME KEY ($ADDR) & RAM SECRETS SHREDDED ==="
  exit 0
fi

echo "=== Step 1: Generating 24-word BIP-39 wallet + P-256 CSR + Cross-Curve ZK proof in RAM ==="
GEN_OUT=$(python3 tools/bounty.py --gen "$WORK/cert" -n "$DOMAIN" "${SANOPT[@]}")
printf '%s\n\n' "$GEN_OUT"
ADDR=$(awk '/^Bitcoin address/ {print $NF}' <<<"$GEN_OUT")
[[ $ADDR =~ ^bc1q[a-z0-9]{38}$ ]] || die "unexpected BTC address '$ADDR'"

if [[ $DRY == 1 ]]; then
  openssl req -x509 -key "$WORK/cert/server.key" -out "$WORK/cert/server.pem" -days 90 \
    -subj "/CN=$DOMAIN" -addext "subjectAltName=$(isip "$DOMAIN" && echo IP || echo DNS):$DOMAIN${SAN:+,DNS:$SAN}" 2>/dev/null
  ./k15 pack site -n "$DOMAIN" "${SANOPT[@]}" -i "$HOST" -c "$WORK/cert" -o "$WORK/build" --hsts 31536000
  python3 tools/bounty.py --verify "$WORK/cert/server.pem" "$WORK/cert/bounty.proof"
  echo ""
  echo "Dry-run complete: $WORK/build/disk.img built and verified in RAM; shredding $WORK now."
  exit 0
fi

echo "=== Step 2: Confirm your handwritten 24-word backup before proceeding ==="
while true; do
  if CHECK_ADDR=$(python3 tools/bounty.py --restore) && [[ $CHECK_ADDR == "$ADDR" ]]; then
    echo "Verified: your handwritten words restore $ADDR."
    break
  fi
  echo "Mismatch (got '${CHECK_ADDR:-error}', expected '$ADDR'). Check your paper and try again." >&2
done

echo "=== Step 3: Booting $SERVER ($HOST) into Hetzner Rescue ==="
if [[ $LIVE == 1 ]]; then
  echo "(and disabling the local auto-renewal timer: it would make a new key)"
  systemctl --user disable --now 15kb-renew.timer 2>/dev/null || true
fi
rescue

echo "=== Step 4: Obtaining 90-day Let's Encrypt certificate inside Rescue (server.key stays in local RAM) ==="
ssh "${SSHR[@]}" "root@$HOST" 'cat > /run/k15.csr' < "$WORK/cert/csr.pem"
ssh "${SSHR[@]}" "root@$HOST" "STAGING='$STAGING' bash -s" <<'EOF' > "$WORK/cert/server.pem"
set -euo pipefail
mkdir -p /mnt/old
for part in /dev/sda1 /dev/sda2 /dev/sda; do
  if [ -b "$part" ] && mount -o ro "$part" /mnt/old 2>/dev/null; then
    if [ -d /mnt/old/etc/letsencrypt ]; then
      mkdir -p /etc
      cp -a /mnt/old/etc/letsencrypt /etc/letsencrypt
      umount /mnt/old
      break
    fi
    umount /mnt/old
  fi
done
command -v certbot >/dev/null || { apt-get update -qq >&2 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >&2; }
rm -f /run/k15.cert.pem /run/k15.chain.pem /run/k15.full.pem
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email $STAGING \
  --csr /run/k15.csr --cert-path /run/k15.cert.pem --chain-path /run/k15.chain.pem \
  --fullchain-path /run/k15.full.pem >&2
cat /run/k15.full.pem
EOF

same_key "$WORK/cert/server.pem" "$WORK/cert/server.key" || die "certificate public key mismatch"

# Back up ACME account key (contains NO cert private key) so --revoke works after server.key is shredded
mkdir -p "$(dirname "$ACME_TAR")" "cert-$DOMAIN"
ssh "${SSHR[@]}" "root@$HOST" 'tar -czf - -C / etc/letsencrypt' > "$ACME_TAR"
chmod 600 "$ACME_TAR"
cp "$WORK/cert/server.pem" "$PUB_PEM"
cp "$WORK/cert/bounty.proof" "$PROOF"
chmod 644 "$PROOF" "$PUB_PEM"

END_RAW=$(openssl x509 -enddate -noout -in "$WORK/cert/server.pem" | cut -d= -f2)
DEADLINE=$(date -u -d "$END_RAW" +%Y-%m-%d)

echo "=== Step 5: Putting $ADDR (until $DEADLINE) into the page & packing disk.img ==="
pack_image

echo "=== Step 6: Wiping /dev/sda (removing Ubuntu completely) & writing raw disk.img ==="
write_disk

echo "=== Step 7: Waiting for raw-disk k15 boot & verifying live TLS + ZK proof ==="
check_live

echo ""
echo "=== LIVE & RAM SECRETS SHREDDED ==="
if [[ $LIVE == 0 ]]; then
  echo "  A rehearsal: $ADDR is the address, $PROOF the proof, $PUB_PEM the certificate."
  echo "  The same key again: SERVER=$SERVER HOST=$HOST DOMAIN=$DOMAIN tools/bounty_ceremony.sh --redeploy"
  exit 0
fi
echo "  1. Fund $ADDR with \$200 BTC (double-check it matches https://$DOMAIN/)."
echo "  2. Commit and push: git add site/index.html site/style.css README.md bounty.proof && git commit -m 'Start \$200 bounty' && git push"
echo "  3. Remove the hcloud token from this laptop (rm -f ~/.config/hcloud/cli.toml + revoke in Hetzner Console, keep Console 2FA on)."
echo "  4. Monitor defacement & wallet: python3 tools/monitor_bounty.py --watch 60 --notify --expect-funded"
echo "  5. A change before the deadline, with the same key: tools/bounty_ceremony.sh --redeploy"
