#!/usr/bin/env bash
# The regression runs, a few at a time, one line each: what CLAUDE.md's Workflow asks for
# after a change to TLS, TCP, the tables, the driver or the polling loops.
#
#   tools/suite.sh [JOBS] [name...]      (default: 4 at a time, all of them)
#   SMP=1 tools/suite.sh                 (the VMs have 2 processors unless SMP says otherwise)
#
# A run is "ok" only if every connection in it worked. The logs stay in $LOGS (default: a
# directory in /tmp that the last line names). Runs that overflow rings on purpose
# (raw1m_20k) can time out a few connections in a million when the host is this busy: run
# such a one alone (`tools/suite.sh 1 raw1m_20k`) before believing it. Rare failures
# (1 in thousands of lossy handshakes) need many runs: `tools/suite.sh 4 real_loss3
# real_loss3 real_loss3 ...` does not repeat a name; loop over it instead.
cd "$(dirname "$0")/.." || exit 1
JOBS=${1:-4}
shift
WANT=" $* "
LOGS=${LOGS:-$(mktemp -d /tmp/k3-suite.XXXXXX)}
mkdir -p "$LOGS"

AES=SUITES=TLS_AES_128_GCM_SHA256
TLS='unshare -Urn ./tap.sh ./taprunc.sh 500 1024 4'
declare -A T
T[measure]='./measure.sh'
T[measure_tcg]='KVM=0 PORT=8453 ./measure.sh'
T[browsers]='./browsers.sh'
T[tls]="$TLS"
T[tls_loss3]="LOSS=3 $TLS"
T[tls_mtu300_loss3]="MTU=300 LOSS=3 $TLS"
T[tls_reorder]="REORDER=25 $TLS"
T[aes]="$AES $TLS"
T[aes_loss3]="$AES LOSS=3 $TLS"
T[aes_mtu300_loss3]="$AES MTU=300 LOSS=3 $TLS"
T[aes_reorder]="$AES REORDER=25 $TLS"
T[plain]='PLAIN=1 INFLIGHT=64 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[plain_loss3]='PLAIN=1 INFLIGHT=64 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[plain_mtu300_loss3]='PLAIN=1 INFLIGHT=64 MTU=300 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4'
T[plain_reorder]='PLAIN=1 INFLIGHT=64 REORDER=25 unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4'
# the same clients twice (same addresses, ports, sequence numbers), not having closed
T[twice]='unshare -Urn ./tap.sh sh -c "build/rawc 200000 && build/rawc 200000"'
T[twice_reorder]='REORDER=25 unshare -Urn ./tap.sh sh -c "build/rawc 50000 && build/rawc 50000"'
T[raw1m]='unshare -Urn ./tap.sh build/rawc 1000000'
T[raw1m_20k]='unshare -Urn ./tap.sh build/rawc 1000000 20000'
T[raw_4g]='MEM=4096 unshare -Urn ./tap.sh build/rawc 2000000'
T[tls_4g]="MEM=4096 $TLS"
T[churn]='B=build-small FLOOD=20000 unshare -Urn ./tap.sh python3 tools/churn.py'
T[churn_idle]='B=build-small-idle unshare -Urn ./tap.sh python3 tools/churn.py 64 3000'
T[real_measure]='B=build-real CERT=cert-real PORT=8463 ./measure.sh'
T[real_loss3]="B=build-real LOSS=3 $TLS"
T[real_mtu300_loss3]="B=build-real MTU=300 LOSS=3 $TLS"
T[real_reorder]="B=build-real REORDER=25 $TLS"
ORDER="measure measure_tcg browsers tls tls_loss3 tls_mtu300_loss3 tls_reorder aes aes_loss3
  aes_mtu300_loss3 aes_reorder twice twice_reorder plain plain_loss3 plain_mtu300_loss3
  plain_reorder raw1m raw1m_20k raw_4g tls_4g churn churn_idle real_measure real_loss3
  real_mtu300_loss3 real_reorder"

# the images and clients first (not in parallel)
[[ -f cert-real/server.pem ]] || python3 tools/mkchain.py cert-real >/dev/null || exit 1
make -s all >/dev/null || { echo "BUILD FAILED"; exit 1; }
make -s B=build-small CAP=1024 >/dev/null || { echo "BUILD FAILED (small)"; exit 1; }
make -s B=build-small-idle CAP=1024 IDLE=0 >/dev/null || { echo "BUILD FAILED (small-idle)"; exit 1; }
make -s B=build-real CERT=cert-real >/dev/null || { echo "BUILD FAILED (real)"; exit 1; }
[[ -x build/rawc && build/rawc -nt tools/rawc.c ]] || gcc -O2 -o build/rawc tools/rawc.c || exit 1
for b in build build-real build-small build-small-idle; do
  [[ -x $b/tapc && $b/tapc -nt tools/tapc.c ]] || gcc -O2 -o $b/tapc tools/tapc.c -lssl -lcrypto || exit 1
done

verdict() {  # name, exit code -> one line
  local n=$1 rc=$2 f=$LOGS/$1.log v=FAIL note=
  case $n in
    measure*|real_measure) grep -q '^PASS' "$f" && v=ok; note=$(grep -m1 -E '^(PASS|FAIL)' "$f");;
    browsers) [[ $rc == 0 ]] && grep -q 'refused OK' "$f" && v=ok; note=$(tr '\n' ';' <"$f" | tail -c 120);;
    raw*|twice*) [[ $rc == 0 ]] && ! grep -q -E ' [1-9][0-9]* (reset|timed out)' "$f" && v=ok
       note=$(grep '^RAW total' "$f" | tail -1 | cut -c1-80)
       note="$note; $(grep -o '[0-9]* reset, [0-9]* timed out' "$f" | tr '\n' ';')";;
    churn*) [[ $rc == 0 ]] && v=ok; note=$(tail -1 "$f");;
    *) note=$(grep '^SCORE' "$f"); [[ $note == SCORE* && $note != "SCORE 0.0"* ]] && ! grep -q FAILED "$f" && v=ok
       note="${note#*= }; $(grep -c FAILED "$f") failed; $(grep -m1 -o 'open_s [0-9.]*' "$f")";;
  esac
  printf '%-20s %-4s %s\n' "$n" "$v" "$note"
}

running=0
for n in $ORDER; do
  [[ $WANT == "  " || $WANT == *" $n "* ]] || continue
  ( t0=$(date +%s); bash -c "${T[$n]}" >"$LOGS/$n.log" 2>&1; rc=$?; echo "$(verdict "$n" $rc)  [$(( $(date +%s) - t0 )) s]" ) &
  running=$((running + 1))
  if (( running >= JOBS )); then wait -n; running=$((running - 1)); fi
done
wait
echo "logs: $LOGS"
