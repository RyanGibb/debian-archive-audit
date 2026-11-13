#!/bin/sh
# Wait for snapshot.debian.org with exponential backoff (cap 30 min, total ~4h)
d=60; t=0
while [ $t -lt 14400 ]; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 'https://snapshot.debian.org/archive/debian/?year=2012&month=1')
  echo "$(date -Is) $c"
  [ "$c" = 200 ] && exit 0
  sleep $d; t=$((t+d)); d=$((d*2)); [ $d -gt 1800 ] && d=1800
done
exit 1
