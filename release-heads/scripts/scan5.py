"""Fifth pass: what a single-architecture reading that drops qualifiers
(debian.tex, Single-Architecture) changes, per release and architecture
(that arch's index, arch:all included):
- ':any' atoms in Pre-Depends/Depends/Recommends with a satisfier, real or
  provider, that is not Multi-Arch: allowed (version formula checked), split
  by whether an allowed satisfier also exists
- atoms qualified with an architecture other than the index's own, split by
  whether the bare name has a satisfier in this index

Usage: python3 -I scan5.py ANY_DIR PROV_DIR [SUITE ...]
"""
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_lib import stanzas, releases, parse_field, sat  # noqa: E402

POS = ["Pre-Depends", "Depends", "Recommends"]


def main():
    any_dir, prov_dir = sys.argv[1:3]
    only = sys.argv[3:] or None
    for r, files in releases(any_dir, prov_dir).items():
        if only and r not in only:
            continue
        for arch in sorted({a for _, a, _ in files}):
            sts = [dict(st) for comp, a, f in files if a == arch for st in stanzas(f)]
            sats = defaultdict(list)  # name -> [(holder, version or None, ma)]
            for d in sts:
                ma = d.get("Multi-Arch", "no")
                sats[d["Package"]].append((d["Package"], d["Version"], ma, True))
                for cl in parse_field(d.get("Provides", "")):
                    for raw, g in cl or []:
                        if g:
                            sats[g["name"]].append(
                                (d["Package"], g["ver"] if g["op"] == "=" else None, ma, False))
            C = Counter()
            ex = defaultdict(list)

            def note(k, s):
                C[k] += 1
                if len(ex[k]) < 3:
                    ex[k].append(s)

            for d in sts:
                for fld in POS:
                    for cl in parse_field(d.get(fld, "")):
                        for raw, g in cl or []:
                            if not g or not g["qual"]:
                                continue
                            q = g["qual"]
                            hits = []
                            for holder, v, ma, isreal in sats.get(g["name"], ()):
                                if g["op"] is None:
                                    ok = True
                                elif v is None:
                                    ok = False
                                else:
                                    ok = sat(v, g["op"], g["ver"])
                                if ok:
                                    hits.append((holder, ma))
                            s = f"{d['Package']} {fld}: {raw.strip()} sats={sorted(set(hits))[:3]} alts={len(cl)}"
                            if q == "any":
                                bad = [h for h in hits if h[1] != "allowed"]
                                good = [h for h in hits if h[1] == "allowed"]
                                if bad:
                                    note("any_nonallowed_sat" + ("_also_allowed" if good else "_only"), s)
                            elif q not in ("native", arch):
                                note("otherarch_" + ("sat_if_dropped" if hits else "unsat_anyway"), s)
            print(f"== {r} {arch}: {dict(C)}", flush=True)
            for k, v in ex.items():
                print("   ", k, v)


main()
