"""Second pass: version-identity questions across architectures.

Usage: python3 -I scan2.py ANY_DIR PROV_DIR
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_lib import stanzas, releases, vcmp  # noqa: E402


def main():
    any_dir, prov_dir = sys.argv[1:3]
    for r, files in releases(any_dir, prov_dir).items():
        by_name = defaultdict(set)   # pkg -> {(arch, ver, ma)}
        for comp, arch, f in files:
            for st in stanzas(f):
                d = dict(st)
                by_name[d.get("Package")].add((d.get("Architecture"), d.get("Version"), d.get("Multi-Arch", "no")))
        all_any_same_ver = []
        same_eq_distinct = []
        all_and_any = []
        for p, s in by_name.items():
            archs = {a for a, v, m in s}
            if "all" in archs and len(archs) > 1:
                all_and_any.append(p)
                vs_all = {v for a, v, m in s if a == "all"}
                vs_any = {v for a, v, m in s if a != "all"}
                if vs_all & vs_any:
                    all_any_same_ver.append((p, sorted(vs_all & vs_any)))
            same = [(a, v) for a, v, m in s if m == "same"]
            for i in range(len(same)):
                for j in range(i + 1, len(same)):
                    (a1, v1), (a2, v2) = same[i], same[j]
                    if a1 != a2 and v1 != v2 and vcmp(v1, v2) == 0:
                        same_eq_distinct.append((p, a1, v1, a2, v2))
        print(f"== {r}: names with arch:all and arch-specific stanzas: {len(all_and_any)}; "
              f"same version both ways: {len(all_any_same_ver)} {all_any_same_ver[:5]}; "
              f"M-A same equal-but-distinct version strings across archs: {len(same_eq_distinct)} {same_eq_distinct[:3]}",
              flush=True)


main()
