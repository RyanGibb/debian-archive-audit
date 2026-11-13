"""Independent line-level cross-check over every cached download.

Every line that was ever present in a reconstructed state entered either via a
seed (full Packages file) or as added text in a pdiff, all cached under DATA.
Grep them for the line-local features of C1, C4, C5 and C7 (case, '|').

Usage: python3 -I indep.py DATA OUT
"""
import bz2
import gzip
import lzma
import os
import re
import sys
from collections import defaultdict
from multiprocessing import Pool

DATA, OUT = sys.argv[1], sys.argv[2]
REL = ["Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
       "Conflicts", "Breaks", "Provides", "Replaces"]
CANON = ["Package", "Version", "Architecture", "Multi-Arch"] + REL
CL = {c.lower(): c for c in CANON}
FIELD = re.compile(rb"^([^ \t:][^:]*):(.*)$")
QUAL = re.compile(rb"[A-Za-z0-9+.\-]:([A-Za-z0-9\-]+)")


def files():
    for root, _, fs in os.walk(DATA):
        for f in fs:
            if f.endswith((".404", ".tmp")) or "samples" in root:
                continue
            p = os.path.join(root, f)
            if "/Packages.diff/" in p and f != "Index":
                yield p
            elif f in ("Packages.xz", "Packages.bz2", "Packages.gz"):
                yield p


def scan(p):
    raw = open(p, "rb").read()
    try:
        if p.endswith(".xz"):
            d = lzma.decompress(raw)
        elif p.endswith(".bz2"):
            d = bz2.decompress(raw)
        else:
            d = gzip.decompress(raw)
    except Exception as e:
        return p, [("decompress-error", repr(e))]
    hits = []
    for line in d.split(b"\n"):
        m = FIELD.match(line)
        if not m:
            continue
        k = m.group(1).decode("latin-1")
        kl = k.lower()
        if kl in CL and k != CL[kl]:
            hits.append(("noncanonical-case", line[:300].decode("utf-8", "replace")))
        if kl not in CL or CL[kl] not in REL:
            continue
        v = m.group(2)
        f = CL[kl]
        if f in ("Conflicts", "Breaks", "Provides") and b"|" in v:
            hits.append(("alt-in-" + f, line[:300].decode("utf-8", "replace")))
        for q in QUAL.findall(re.sub(rb"\([^)]*\)", b"", v)):
            q = q.decode()
            if f == "Provides":
                hits.append(("provides-qual:" + q, line[:300].decode("utf-8", "replace")))
            if q in ("all", "native"):
                hits.append((f"qual-{q}", line[:300].decode("utf-8", "replace")))
    return p, hits


def main():
    fl = sorted(files())
    agg = defaultdict(lambda: defaultdict(list))
    with Pool(64) as pool:
        for p, hits in pool.imap_unordered(scan, fl, chunksize=8):
            for kind, line in hits:
                agg[kind][line].append(os.path.relpath(p, DATA))
    with open(OUT, "w") as o:
        o.write(f"files scanned: {len(fl)}\n")
        for kind in sorted(agg):
            o.write(f"== {kind}: {len(agg[kind])} distinct lines\n")
            for line, ps in sorted(agg[kind].items()):
                ps.sort()
                o.write(f"  {line}\n      in {len(ps)} files, first {ps[0]}, last {ps[-1]}\n")
    print(open(OUT).read()[:5000])


if __name__ == "__main__":
    main()
