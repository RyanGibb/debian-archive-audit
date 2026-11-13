#!/bin/sh
# Detached pipeline on iphito: probe -> sample Index files -> two trial runs -> full scan.
B=/mnt/disk3/ryan/snapshot-scan; S=$B/scripts; D=$B/data; R=$B/results
cd $B || exit 1
log() { echo "$(date -Is) $*" >> $R/go.log; }
d=60; t=0; DEADLINE=${DEADLINE:-21600}
while :; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 'https://snapshot.debian.org/archive/debian/?year=2012&month=1')
  log "probe $c"
  [ "$c" = 200 ] && break
  if [ $t -ge $DEADLINE ]; then log "GIVE-UP snapshot.debian.org still down"; touch $R/GAVE_UP; exit 1; fi
  sleep $d; t=$((t+d)); d=$((d*2)); [ $d -gt 1800 ] && d=1800
done
mkdir -p $D/samples
for dt in 20120101T000000Z 20140101T000000Z 20160101T000000Z 20180101T000000Z 20200101T000000Z 20210101T000000Z 20220101T000000Z 20240101T000000Z 20261101T000000Z; do
  curl -s -L --max-time 120 -o $D/samples/Index-$dt "https://snapshot.debian.org/archive/debian/$dt/dists/sid/main/binary-amd64/Packages.diff/Index" \
    -w "%{http_code} %{url_effective}\n" >> $R/go.log
  sleep 1
done
log "samples fetched"
mkdir -p $R/trial1 $R/trial2 $R/full
python3 -I $S/run.py $S $D $R/trial1 --limit 12 >> $R/go.log 2>&1; log "trial1 exit $?"
python3 -I $S/run.py $S $D $R/trial2 --from 20240101T000000Z --limit 12 >> $R/go.log 2>&1; log "trial2 exit $?"
touch $R/TRIALS_DONE
python3 -I $S/run.py $S $D $R/full >> $R/go.log 2>&1; rc=$?
log "full exit $rc"
mkdir -p $R/full
python3 -I $S/report.py $S $R/full > $R/full/report.out 2>&1
touch $R/FULL_DONE
