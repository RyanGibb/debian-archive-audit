#!/bin/sh
# Offline replay in yearly segments, with intermediate dinstall states.
B=/mnt/disk3/ryan/snapshot-scan; S=$B/scripts; D=$B/data; R=$B/results/replay
export SNAPSCAN_LOCK=$B/fetch.lock
mkdir -p $R; cd $B || exit 1
python3 -I -c '
import json, sys
ts = json.load(open(sys.argv[1]))
prev = None
for y in range(2012, 2027):
    yr = [t for t in ts if t.startswith(str(y))]
    if not yr: continue
    start = prev or yr[0]
    print(y, start, yr[-1], "warm" if prev else "cold")
    prev = yr[-1]
' $D/timestamps.json > $R/segments.txt
while read y start end mode; do
  mkdir -p $R/$y
  extra=""; [ $mode = warm ] && extra="--warm-first"
  (python3 -I $S/run.py $S $D $R/$y --offline --intermediate --from $start --to $end $extra > $R/$y/stderr.log 2>&1; echo "$y exit $?" >> $R/segs.done) &
  sleep 120
done < $R/segments.txt
wait
python3 -I $S/merge.py $R/merged $(awk '{print "'$R'/"$1}' $R/segments.txt) > $R/merge.out 2>&1
python3 -I $S/report.py $S $R/merged > $R/merged/report.out 2>&1
touch $B/results/REPLAY_DONE
