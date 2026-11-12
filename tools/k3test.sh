#!/usr/bin/env bash
# The tool itself, as far as it goes without a server. ./k3 pack a folder for a name, with
# a certificate from elsewhere (here: one that signs itself, good for 60 days), HSTS and a
# header of its own; ./k3 run it; what comes back is the site, verified, with those
# headers, and port 80 sends everybody to the name. What it made is for its owner's eyes
# only. ./k3 renew does nothing while the certificate has 30 days left, and when it has
# not (or with --force) makes a new key and a request here and would then go to the
# server (--dry-run stops it there): the old key is still in its place.
# (./k3 deploy, and renew's part on the server, need a server: CLAUDE.md, "Running it on
# the server".)
cd "$(dirname "$0")/.." || exit 1
PORT=${PORT:-8513}
OUT=build-k3test CERT=cert-k3test
mkdir -p $OUT $CERT
python3 tools/mksite.py $OUT/www 0.1 >/dev/null || exit 1
# (a certificate with between 40 and 61 days left, and nothing else in its folder)
if [[ -e $CERT/ca.pem ]] || ! openssl x509 -checkend $((40 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1 ||
   openssl x509 -checkend $((61 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1; then
  rm -f $CERT/ca.pem
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $CERT/server.key -out $CERT/server.pem \
    -days 60 -subj /CN=k3cli.test -addext subjectAltName=DNS:k3cli.test 2>/dev/null || { echo "FAIL openssl"; exit 1; }
fi
./k3 pack $OUT/www -n k3cli.test -c $CERT -o $OUT --hsts 300 --header 'X-Test: yes' > $OUT/pack.out || { echo "FAIL k3 pack"; exit 1; }
grep -q "of system" $OUT/pack.out || { echo "FAIL k3 pack said: $(cat $OUT/pack.out)"; exit 1; }
./k3 run $OUT -p $PORT > $OUT/run.out 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
CURL=(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "k3cli.test:$PORT:127.0.0.1:$PORT")
for _ in $(seq 1 40); do
  "${CURL[@]}" -o /dev/null "https://k3cli.test:$PORT/" && break
  sleep 0.25
done
bad=0
check() { if [[ $2 == ok ]]; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }
H=$("${CURL[@]}" -D - -o $OUT/big.got "https://k3cli.test:$PORT/big.bin" | tr -d '\r')
check "the large file comes back as it is" "$(cmp -s $OUT/big.got $OUT/www/big.bin && echo ok)"
check "with the headers asked for" "$([[ $H == *"Strict-Transport-Security: max-age=300"* && $H == *"X-Test: yes"* ]] && echo ok)"
check "a folder's page at its name" "$("${CURL[@]}" "https://k3cli.test:$PORT/docs/" | cmp -s - $OUT/www/docs/index.html && echo ok)"
R=$(curl -s --max-time 5 -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:$((PORT + 1000))/docs/")
check "port 80 sends everybody to the name ($R)" "$([[ $R == "301 https://k3cli.test/" ]] && echo ok)"
P="$(stat -c %a $OUT/os.bin) $(stat -c %a $OUT/disk.img) $(stat -c %a $OUT/regs.inc) $(stat -c %a $CERT/server.key) $(stat -c %a $OUT)"
check "image, disk, key and their folder are their owner's alone ($P)" "$([[ $P == "600 600 600 600 700" ]] && echo ok)"
check "how it was packed is kept for renew" "$(grep -q 'X-Test' $OUT/pack.conf && grep -q '^hsts=300$' $OUT/pack.conf && grep -q '^p80=redirect$' $OUT/pack.conf && echo ok)"
# renew: 192.0.2.1 is nobody's address; none of this may so much as try to reach it
K0=$(sha256sum < $CERT/server.key)
T0=$(date +%s)
R=$(./k3 renew 192.0.2.1 $OUT 2>&1)
check "renew does nothing while the certificate has 30 days left" "$([[ $? == 0 && $R == *"nothing to do"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT --days 90 --dry-run 2>&1)
check "with less left than it is told to keep, it would ask for one (${R:0:60}...)" "$([[ $R == *"would ask Let's Encrypt for a certificate for DNS:k3cli.test"*"CN=k3cli.test"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT --force --dry-run 2>&1)
check "and with --force" "$([[ $R == *"would ask Let's Encrypt"* ]] && echo ok)"
check "none of that took time, touched the key or left anything behind" \
  "$([[ $(( $(date +%s) - T0 )) -le 3 && $(sha256sum < $CERT/server.key) == "$K0" && -z $(ls -A $CERT | grep -v -E '^server\.(key|pem)$') ]] && echo ok)"
exit $bad
