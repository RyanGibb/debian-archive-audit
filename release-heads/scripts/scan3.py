"""Third pass, per release and per single architecture index set:
- :any atoms in positive fields whose name has no Multi-Arch: allowed satisfier
  (real allowed version or a Provides by an allowed package)
- explicit-arch atoms naming an architecture other than the index's own

Usage: python3 -I scan3.py ANY_DIR PROV_DIR
"""
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_lib import stanzas, releases, parse_field  # noqa: E402

POS = ["Pre-Depends", "Depends", "Recommends"]


def main():
    any_dir, prov_dir = sys.argv[1:3]
    for r, files in releases(any_dir, prov_dir).items():
        if r not in ("sid", "bookworm", "bullseye"):
            continue
        for arch in sorted({a for _, a, _ in files}):
            sts = [dict(st) for comp, a, f in files if a == arch for st in stanzas(f)]
            allowed = set()
            real = set()
            for d in sts:
                real.add(d["Package"])
                if d.get("Multi-Arch") == "allowed":
                    allowed.add(d["Package"])
                    for cl in parse_field(d.get("Provides", "")):
                        for raw, g in cl or []:
                            if g:
                                allowed.add(g["name"])
            C = Counter()
            ex = defaultdict(list)
            for d in sts:
                for field in POS:
                    for cl in parse_field(d.get(field, "")) if field in d else []:
                        for raw, g in cl or []:
                            if not g or not g["qual"]:
                                continue
                            q = g["qual"]
                            if q == "any":
                                C["any_atoms"] += 1
                                if g["name"] not in allowed:
                                    k = "any_no_allowed_" + ("real" if g["name"] in real else "absent")
                                    C[k] += 1
                                    if len(ex[k]) < 3:
                                        ex[k].append(f"{d['Package']}: {raw.strip()} (single-alt={len(cl)==1})")
                                    if len(cl) == 1:
                                        C[k + "_sole_alt"] += 1
                            elif q not in ("native", arch) and not (q == "all"):
                                C["foreign_explicit"] += 1
                                if len(ex["foreign_explicit"]) < 3:
                                    ex["foreign_explicit"].append(f"{d['Package']}: {raw.strip()}")
            print(f"== {r} {arch}: {dict(C)}")
            for k, v in ex.items():
                print("   ", k, v)


main()
