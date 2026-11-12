#!/usr/bin/env bash
# The tool itself, as far as it goes without a server. ./k3 pack a folder for a name, with
# a certificate from elsewhere (here: one that signs itself, good for 60 days), HSTS and a
# header of its own; ./k3 run it; what comes back is the site, verified, with those
# headers, and port 80 sends everybody to the name. What it made is for its owner's eyes
# only. ./k3 renew does nothing while the certificate has 30 days left, and when it has
# not (or with --force) makes a new key and a request here and would then go to the
# server (--dry-run stops it there): the old key is still in its place. A second name
# (--san) is served if the certificate is for it, is asked for by renew, and is in the
# certificate that is made when there is none.
# (./k3 deploy, and renew's part on the server, need a server: CLAUDE.md, "Running it on
# the server".)
cd "$(dirname "$0")/.." || exit 1
PORT=${PORT:-8513}
OUT=build-k3test CERT=cert-k3test
mkdir -p $OUT $CERT
python3 tools/mksite.py $OUT/www 0.1 >/dev/null || exit 1
# (a certificate for two names, the second one first, with between 40 and 61 days left,
# and nothing else in its folder)
if [[ -e $CERT/ca.pem ]] || ! openssl x509 -checkend $((40 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1 ||
   openssl x509 -checkend $((61 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1 ||
   ! openssl x509 -checkhost also.k3cli.test -noout -in $CERT/server.pem 2>/dev/null | grep -q "does match"; then
  rm -f $CERT/ca.pem
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $CERT/server.key -out $CERT/server.pem \
    -days 60 -subj /CN=k3cli.test -addext subjectAltName=DNS:also.k3cli.test,DNS:k3cli.test 2>/dev/null || { echo "FAIL openssl"; exit 1; }
fi
./k3 pack $OUT/www -n k3cli.test --san also.k3cli.test -c $CERT -o $OUT --hsts 300 --header 'X-Test: yes' > $OUT/pack.out 2>&1 || { echo "FAIL k3 pack"; exit 1; }
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
H=$("${CURL[@]}" -D - -o /dev/null "https://k3cli.test:$PORT/nothing/here" | tr -d '\r')
check "an unknown path too, but for the one about caching" "$([[ $H == "HTTP/1.1 404 "*"Strict-Transport-Security: max-age=300"* && $H == *"X-Test: yes"* &&
  $H == *"X-Content-Type-Options: nosniff"* && $H != *"Cache-Control"* ]] && echo ok)"
H=$("${CURL[@]}" -D - -o /dev/null "https://k3cli.test:$PORT/docs" | tr -d '\r')$("${CURL[@]}" -X POST -D - -o /dev/null "https://k3cli.test:$PORT/" | tr -d '\r')
check "a folder's redirect and the no to POST say HTTPS only as well" "$([[ $H == "HTTP/1.1 301 "*"Strict-Transport-Security: max-age=300"*"HTTP/1.1 405 "*"Strict-Transport-Security: max-age=300"* ]] && echo ok)"
H=$(curl -s --max-time 5 -D - -o /dev/null "http://127.0.0.1:$((PORT + 1000))/" | tr -d '\r')
check "port 80 does not" "$([[ $H == "HTTP/1.1 301 "* && $H != *"Strict-Transport-Security"* ]] && echo ok)"
check "a folder's page at its name" "$("${CURL[@]}" "https://k3cli.test:$PORT/docs/" | cmp -s - $OUT/www/docs/index.html && echo ok)"
check "the same under its second name" "$(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "also.k3cli.test:$PORT:127.0.0.1:$PORT" \
  "https://also.k3cli.test:$PORT/docs/" | cmp -s - $OUT/www/docs/index.html && echo ok)"
check "and not under one the certificate is not for" "$(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "other.k3cli.test:$PORT:127.0.0.1:$PORT" \
  -o /dev/null "https://other.k3cli.test:$PORT/docs/"; [[ $? == 60 ]] && echo ok)"
R=$(curl -s --max-time 5 -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:$((PORT + 1000))/docs/")
check "port 80 sends everybody to the name ($R)" "$([[ $R == "301 https://k3cli.test/" ]] && echo ok)"
P="$(stat -c %a $OUT/os.bin) $(stat -c %a $OUT/disk.img) $(stat -c %a $OUT/regs.inc) $(stat -c %a $CERT/server.key) $(stat -c %a $OUT)"
check "image, disk, key and their folder are their owner's alone ($P)" "$([[ $P == "600 600 600 600 700" ]] && echo ok)"
check "how it was packed is kept for renew" "$(grep -q 'X-Test' $OUT/pack.conf && grep -q '^hsts=300$' $OUT/pack.conf && grep -q '^p80=redirect$' $OUT/pack.conf &&
  grep -q '^sans=also.k3cli.test$' $OUT/pack.conf && echo ok)"
check "pack says nothing about names when the certificate has them all" "$(grep -q "is not for" $OUT/pack.out || echo ok)"
# renew: 192.0.2.1 is nobody's address; none of this may so much as try to reach it
K0=$(sha256sum < $CERT/server.key)
T0=$(date +%s)
R=$(./k3 renew 192.0.2.1 $OUT 2>&1)
check "renew does nothing while the certificate has 30 days left" "$([[ $? == 0 && $R == *"nothing to do"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT --days 90 --dry-run 2>&1)
check "with less left than it is told to keep, it would ask for one, for both names (${R:0:60}...)" \
  "$([[ $R == *"would ask Let's Encrypt for a certificate for DNS:k3cli.test,DNS:also.k3cli.test "*"CN=k3cli.test"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT --force --dry-run 2>&1)
check "and with --force" "$([[ $R == *"would ask Let's Encrypt"* ]] && echo ok)"
check "none of that took time, touched the key or left anything behind" \
  "$([[ $(( $(date +%s) - T0 )) -le 3 && $(sha256sum < $CERT/server.key) == "$K0" && -z $(ls -A $CERT | grep -v -E '^server\.(key|pem)$') ]] && echo ok)"
# A name the certificate lacks: pack says so, renew says so and does nothing (cron may
# run it), and --force would ask for it.
R=$(./k3 pack $OUT/www -n k3cli.test --san also.k3cli.test --san third.k3cli.test -c $CERT -o $OUT --hsts 300 --header 'X-Test: yes' 2>&1)
check "pack says which name the certificate is not for" "$([[ $R == *"is not for: third.k3cli.test"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT 2>&1)
check "renew says so too, and does nothing" "$([[ $? == 0 && $R == *"nothing to do"*"not for: third.k3cli.test"* ]] && echo ok)"
R=$(./k3 renew 192.0.2.1 $OUT --force --dry-run 2>&1)
check "with --force it would ask for all three" "$([[ $R == *"for DNS:k3cli.test,DNS:also.k3cli.test,DNS:third.k3cli.test "* ]] && echo ok)"
# No certificate at all: one is made under a private CA, for every name, the first one first.
OUT2=build-k3test2 CERT2=cert-k3test2
rm -rf $CERT2
./k3 pack $OUT/www -n k3priv.test --san also.k3priv.test --san 192.0.2.7 -c $CERT2 -o $OUT2 > $OUT2.out 2>&1
check "a certificate made here is for all its names ($(cat $OUT2/name 2>/dev/null))" "$([[ $(cat $OUT2/name) == k3priv.test ]] && ! grep -q "is not for" $OUT2.out &&
  openssl verify -CAfile $OUT2/ca.pem -verify_hostname also.k3priv.test $CERT2/server.pem >/dev/null 2>&1 &&
  openssl verify -CAfile $OUT2/ca.pem -verify_ip 192.0.2.7 $CERT2/server.pem >/dev/null 2>&1 &&
  ! openssl verify -CAfile $OUT2/ca.pem -verify_hostname other.k3priv.test $CERT2/server.pem >/dev/null 2>&1 && echo ok)"
rm -f $OUT2.out
exit $bad
