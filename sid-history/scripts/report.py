"""Summarise checkpoint.pkl + coverage.tsv into results/.

Usage: python3 -I report.py SCRIPTS_DIR RESULTS_DIR
"""
import json
import os
import pickle
import sys
from collections import Counter, defaultdict

RES = sys.argv[2]
d = pickle.load(open(os.path.join(RES, "checkpoint.pkl"), "rb"))
occ = d["occ"]

by_check = defaultdict(list)
for (chk, comp, idx, pkg, ver, arch, detail), (f, l, n, extra, _) in occ.items():
    by_check[chk].append({"first": f, "last": l, "states": n, "component": comp,
                          "index_arch": idx, "Package": pkg, "Version": ver,
                          "Architecture": arch, "field": detail,
                          "matches": sorted(extra)[:20]})
for v in by_check.values():
    v.sort(key=lambda r: (r["Package"], r["Version"], r["component"], r["index_arch"], r["first"]))
json.dump(by_check, open(os.path.join(RES, "occurrences.json"), "w"), indent=1)

with open(os.path.join(RES, "occurrences.txt"), "w") as out:
    for chk in sorted(by_check):
        rows = by_check[chk]
        out.write(f"== {chk}: {len(rows)} distinct occurrences\n")
        for r in rows:
            out.write(f"  {r['first']}..{r['last']} ({r['states']} states) {r['component']}/{r['index_arch']} "
                      f"{r['Package']} {r['Version']} [{r['Architecture']}] {r['field']}\n")
            for m in r["matches"][:3]:
                out.write(f"      match: {m}\n")

anyc = Counter(f for (f, *_rest) in d["any_atoms"])
anyc_pv = Counter((f) for f in {(f, p, v, raw) for (f, c, i, p, v, a, raw) in d["any_atoms"]})
anyc_pv = Counter(k[0] for k in {(f, p, v, raw) for (f, c, i, p, v, a, raw) in d["any_atoms"]})
q_all = Counter(k[0] for k in d["qual_all"])
q_prov = Counter(k[0] for k in d["qual_prov"])
summary = {
    "last_position": d["pos"], "meta": d["meta"], "stanzas_scanned": d["scanned"],
    "counts": {k: len(v) for k, v in sorted(by_check.items())},
    "any_atoms_CBR_by_field_stanza_level": dict(anyc),
    "any_atoms_CBR_by_field_distinct_pkg_ver_atom": dict(anyc_pv),
    "explicit_qual_neg_atoms_by_field": dict(q_all),
    "explicit_qual_neg_atoms_with_provider_by_field": dict(q_prov),
}
json.dump(summary, open(os.path.join(RES, "summary.json"), "w"), indent=1)
with open(os.path.join(RES, "any_atoms.tsv"), "w") as out:
    for r in sorted(d["any_atoms"]):
        out.write("\t".join(map(str, r)) + "\n")
with open(os.path.join(RES, "explicit_qual_neg_atoms.tsv"), "w") as out:
    for r in sorted(d["qual_all"]):
        out.write("\t".join(map(str, r)) + ("\tHAS-PROVIDER" if r in d["qual_prov"] else "") + "\n")

# coverage: per stream, first/last ts present, counts per method, gaps
cov = [l.rstrip("\n").split("\t") for l in open(os.path.join(RES, "coverage.tsv"))]
COMPS = ["main", "contrib", "non-free", "non-free-firmware"]
ARCHS = ["amd64", "i386", "arm64"]
keys = [(c, a) for c in COMPS for a in ARCHS]
per = {k: Counter() for k in keys}
span = {}
gaps = []
noref = []
for row in cov:
    if len(row) == 2:
        noref.append(row)
        continue
    ts = row[0]
    for k, code in zip(keys, row[1:]):
        if code == "-":
            continue
        span.setdefault(k, [ts, ts])[1] = ts
        tag = code.split(":")[0]
        per[k][tag[0] if tag[0] in "PS=" else tag] += 1
        if "MI" in code or code == "GAP":
            gaps.append((ts, k, code))
with open(os.path.join(RES, "coverage_summary.txt"), "w") as out:
    out.write(f"states (timestamps processed): {len([r for r in cov if len(r) > 2])}\n")
    out.write(f"timestamps without sid Release: {len(noref)} {noref[:20]}\n")
    for k in keys:
        if k in span:
            out.write(f"{k[0]}/{k[1]}: {span[k][0]}..{span[k][1]} {dict(per[k])}\n")
    out.write(f"gap/mismatch events: {len(gaps)}\n")
    for g in gaps:
        out.write(f"  {g}\n")
print(json.dumps(summary, indent=1))
