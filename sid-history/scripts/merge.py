"""Merge per-segment results into one directory for report.py.

Usage: python3 -I merge.py OUT_DIR SEG_DIR...
Labels: snapshot 'YYYYMMDDTHHMMSSZ', intermediate dinstall 'YYYYMMDDTHHMMSSD'.
"""
import os
import pickle
import sys

out, segs = sys.argv[1], sys.argv[2:]
os.makedirs(out, exist_ok=True)


def k(label):
    return label[:15]


occ, any_atoms, qa, qp = {}, set(), set(), set()
meta = {}
scanned = 0
pos = ""
with open(os.path.join(out, "coverage.tsv"), "w") as cov, \
        open(os.path.join(out, "intermediate.tsv"), "w") as icov:
    for sd in segs:
        d = pickle.load(open(os.path.join(sd, "checkpoint.pkl"), "rb"))
        for key, (f, l, n, extra, _) in d["occ"].items():
            r = occ.get(key)
            if r is None:
                occ[key] = [f, l, n, set(extra), None]
            else:
                r[0] = min(r[0], f, key=k)
                r[1] = max(r[1], l, key=k)
                r[2] += n
                r[3] |= extra
        any_atoms |= d["any_atoms"]
        qa |= d["qual_all"]
        qp |= d["qual_prov"]
        scanned += d["scanned"]
        pos = max(pos, d["pos"])
        for kk, v in d["meta"].items():
            if isinstance(v, dict):
                m = meta.setdefault(kk, {})
                for a, b in v.items():
                    m[a] = m.get(a, 0) + b
            elif isinstance(v, int):
                meta[kk] = meta.get(kk, 0) + v
        cov.write(open(os.path.join(sd, "coverage.tsv")).read())
        p = os.path.join(sd, "intermediate.tsv")
        if os.path.exists(p):
            icov.write(open(p).read())
pickle.dump({"occ": occ, "any_atoms": any_atoms, "qual_all": qa, "qual_prov": qp,
             "pos": pos, "meta": meta, "scanned": scanned},
            open(os.path.join(out, "checkpoint.pkl"), "wb"))
print("merged", len(segs), "segments;", len(occ), "occurrences")
