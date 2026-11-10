#!/usr/bin/env bash
# Reset a server running an image built with KNOCK=a,b: one TCP connection attempt to port a,
# then one to port b (the image answers neither). The ports are in $B/knock.
# Usage: B=build-hz tools/knock.sh a.b.c.d
cd "$(dirname "$0")/.."
B=${B:-build-hz}
read -r A KB < "$B/knock"
for p in "$A" "$KB"; do
  timeout 1 bash -c "exec 3<>/dev/tcp/$1/$p" 2>/dev/null
done
true
