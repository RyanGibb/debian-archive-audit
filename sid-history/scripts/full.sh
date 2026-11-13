#!/bin/sh
# Full scan with automatic resume (each run.py gives up after ~4h of continuous server failure).
B=/mnt/disk3/ryan/snapshot-scan; S=$B/scripts; D=$B/data; R=$B/results; F=$R/full
mkdir -p $F; cd $B || exit 1
log() { echo "$(date -Is) $*" >> $R/go.log; }
n=0
while [ $n -lt 4 ]; do
  extra=""; [ -f $F/checkpoint.pkl ] && extra="--resume"
  log "full attempt $n $extra"
  python3 -I $S/run.py $S $D $F $extra >> $F/stderr.log 2>&1; rc=$?
  log "full attempt $n exit $rc"
  [ $rc = 0 ] && break
  n=$((n+1)); sleep 1800
done
python3 -I $S/report.py $S $F > $F/report.out 2>&1
[ $rc = 0 ] && touch $R/FULL_DONE || touch $R/GAVE_UP
